package postgres

// Integración CU-SES-04 T-08: Lookup/RotateCAS(CAS)/ReuseGlobal contra
// PG+Redis reales. Skip sin compose. Cubre: lookup current/parent/miss,
// rotate feliz (counter+denylist+outbox+espejo), CAS perdido → Concurrent,
// familia revoked, reuse → corte SES-02 real + evidencia P1, flaps/idem Redis.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func rotTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://auth:auth@localhost:5432/auth_db?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Skipf("sin postgres: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		t.Skipf("sin postgres: %v", err)
	}
	return pool
}

func rotTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	return rdb
}

func rotHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func seedRotUser(t *testing.T, pool *pgxpool.Pool, tag string) (string, string) {
	t.Helper()
	uid := uuid.NewString()
	email := "rot-" + tag + "-" + uid + "@test.local"
	_, err := pool.Exec(context.Background(), `INSERT INTO users (id, email_normalized, email_original,
		password_hash, status, terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, '$argon2id$v=19$m=65536$test$hash',
		'ACTIVE','v2026.10','v2026.10', now())
		ON CONFLICT (email_normalized) DO NOTHING`, uid, email)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	return uid, email
}

type rotChain struct {
	family, sid, cur, par string
	curJTI                string
}

// seedRotChain crea family counter=3 (current R3 + parent R2) + sesión viva.
func seedRotChain(t *testing.T, pool *pgxpool.Pool, uid, tag string, rotatedAgo time.Duration) rotChain {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	fam, sid, jti := uuid.NewString(), uuid.NewString(), uuid.NewString()
	cur, par := rotHash("R3-"+tag), rotHash("R2-"+tag)
	if _, err := pool.Exec(ctx, `INSERT INTO refresh_families
		(family, user_id, current_hash, parent_hash, counter, absolute_exp, revoked,
		last_rotated_at, device_hash)
		VALUES ($1::uuid,$2::uuid,$3,$4,3,$5,FALSE,$6,'dev-seed')`,
		fam, uid, cur, par, now.Add(80*24*time.Hour), now.Add(-rotatedAgo)); err != nil {
		t.Fatalf("family: %v", err)
	}
	for _, hh := range []struct {
		hash string
		n    int
		exp  time.Time
	}{{cur, 3, now.Add(20 * 24 * time.Hour)}, {par, 2, now.Add(19 * 24 * time.Hour)}} {
		if _, err := pool.Exec(ctx, `INSERT INTO refresh_hashes (hash, family, counter, expires_at)
			VALUES ($1,$2::uuid,$3,$4)`, hh.hash, fam, hh.n, hh.exp); err != nil {
			t.Fatalf("hash: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sessions
		(sid, user_id, family, jti_actual, device_hash, ip_hash, created_at, last_seen, expires_at,
		device_label, ip_masked, auth_time, amr, roles, roles_ver)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'dev-seed','ip',$5,$5,$6,'L','1.2.3.xxx',$7,'{pwd}','{user}',0)`,
		sid, uid, fam, jti, now, now.Add(90*24*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatalf("session: %v", err)
	}
	return rotChain{family: fam, sid: sid, cur: cur, par: par, curJTI: jti}
}

func cleanupRotUser(ctx context.Context, pool *pgxpool.Pool, uid, email string) {
	_, _ = pool.Exec(ctx, `DELETE FROM outbox WHERE aggregate_id=$1::uuid`, uid)
	_, _ = pool.Exec(ctx, `DELETE FROM email_queue WHERE to_email=$1`, email)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
}

func countRot(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func newTestRotationStore(pool *pgxpool.Pool, rdb *redis.Client) *CombinedRotationStore {
	return NewCombinedRotationStore(pool, redisadapter.NewRotationCache(rdb),
		NewGlobalRevoker(pool, redisadapter.NewGlobalSweep(rdb), nil), nil)
}

func TestRotationStore_Integration(t *testing.T) {
	pool := rotTestPool(t)
	defer pool.Close()
	rdb := rotTestRedis(t)
	defer rdb.Close()
	ctx := context.Background()

	uid, email := seedRotUser(t, pool, "a")
	defer cleanupRotUser(ctx, pool, uid, email)
	chain := seedRotChain(t, pool, uid, "a", time.Hour)
	store := newTestRotationStore(pool, rdb)

	// 1. Lookup current + parent + miss.
	lkp, err := store.Lookup(ctx, chain.cur)
	if err != nil || !lkp.IsCurrent || lkp.IsParent {
		t.Fatalf("lookup cur: %v %+v", err, lkp)
	}
	if lkp.State.SID != chain.sid || lkp.State.Counter != 3 || len(lkp.State.AMR) == 0 {
		t.Fatalf("state: %+v", lkp.State)
	}
	par, err := store.Lookup(ctx, chain.par)
	if err != nil || !par.IsParent || par.IsCurrent {
		t.Fatalf("lookup par: %v %+v", err, par)
	}
	if _, err := store.Lookup(ctx, rotHash("no-existe-en-ninguna-family-xyz")); err == nil {
		t.Fatal("miss→NotFound")
	}
	if _, err := store.Lookup(ctx, "corto"); err == nil {
		t.Fatal("malforma→NotFound")
	}

	// 2. RotateCAS feliz.
	newPlain := "R4-nuevo-plano-de-43-caracteres-rotacion-1"
	newHash := rotHash(newPlain)
	newJTI := uuid.NewString()
	slidingTo := time.Now().UTC().Add(30 * 24 * time.Hour)
	absExp := time.Now().UTC().Add(80 * 24 * time.Hour)
	if slidingTo.After(absExp) {
		slidingTo = absExp
	}
	pair, err := store.RotateCAS(ctx, auth.RotateCASInput{
		State: lkp.State, OldHash: chain.cur,
		NewPair: auth.RotatedPair{AccessJWT: "jwt-new", Refresh: newPlain,
			ExpiresAt: slidingTo, SID: chain.sid, Family: chain.family, JTI: newJTI, Counter: 4},
		NewHash: newHash, SlidingTo: slidingTo, PresentedFP: "dev-seed",
	})
	if err != nil || pair.Counter != 4 {
		t.Fatalf("rotate: %v %+v", err, pair)
	}
	var curDB string
	var counterDB int
	_ = pool.QueryRow(ctx, `SELECT current_hash, counter FROM refresh_families WHERE family=$1::uuid`,
		chain.family).Scan(&curDB, &counterDB)
	if curDB != newHash || counterDB != 4 {
		t.Fatalf("chain: %q %d", curDB, counterDB)
	}
	var jtiDB string
	_ = pool.QueryRow(ctx, `SELECT jti_actual::text FROM sessions WHERE sid=$1::uuid`, chain.sid).Scan(&jtiDB)
	if jtiDB != newJTI {
		t.Fatal("jti rotado en sesión")
	}
	if n := countRot(t, pool, `SELECT COUNT(*) FROM revoked_jtis WHERE jti=$1::uuid`, chain.curJTI); n != 1 {
		t.Fatal("denylist viejo")
	}
	if n := countRot(t, pool, `SELECT COUNT(*) FROM outbox WHERE event_type='session.rotated'
		AND aggregate_id=$1::uuid`, uid); n != 1 {
		t.Fatal("outbox rotated")
	}
	if v := rdb.Get(ctx, "fam:"+chain.family).Val(); v != newHash {
		t.Fatalf("redis fam: %q", v)
	}
	if v := rdb.Get(ctx, "jti:"+chain.curJTI).Val(); v != "revoked" {
		t.Fatalf("redis denylist: %q", v)
	}

	// 3. CAS perdido con el viejo → Concurrent (el nuevo sí es current).
	lkp2, err := store.Lookup(ctx, newHash)
	if err != nil || !lkp2.IsCurrent {
		t.Fatalf("nuevo current: %v", err)
	}
	if _, err := store.RotateCAS(ctx, auth.RotateCASInput{
		State: lkp2.State, OldHash: chain.cur,
		NewPair: auth.RotatedPair{AccessJWT: "x", Refresh: "y", ExpiresAt: slidingTo,
			SID: chain.sid, Family: chain.family, JTI: uuid.NewString(), Counter: 9},
		NewHash: rotHash("otro"), SlidingTo: slidingTo, PresentedFP: "dev-seed",
	}); !errors.Is(err, auth.ErrRefreshConcurrent) {
		t.Fatalf("CAS perdido→Concurrent: %v", err)
	}

	// 4. Flaps + idem Redis.
	if n, err := store.IncrFlaps(ctx, chain.cur); err != nil || n < 1 {
		t.Fatalf("flaps: %v %d", err, n)
	}
}

func TestRotationStore_ReuseGlobal(t *testing.T) {
	pool := rotTestPool(t)
	defer pool.Close()
	rdb := rotTestRedis(t)
	defer rdb.Close()
	ctx := context.Background()

	uid, email := seedRotUser(t, pool, "reuse")
	defer cleanupRotUser(ctx, pool, uid, email)
	chain := seedRotChain(t, pool, uid, "reuse", time.Hour)
	store := newTestRotationStore(pool, rdb)

	lkp, err := store.Lookup(ctx, chain.par)
	if err != nil {
		t.Fatalf("lookup parent: %v", err)
	}
	res, err := store.ReuseGlobal(ctx, auth.ReuseGlobalInput{
		State: lkp.State, PresentedHash: chain.par, PresentedDevice: "fp-atacante",
		PresentedAt: time.Now().UTC(), IP: "9.9.9.9",
		CounterPresented: lkp.CounterPresented,
	})
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	if res.Sessions != 1 {
		t.Fatalf("corte total: %+v", res)
	}
	if n := countRot(t, pool, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid); n != 0 {
		t.Fatal("0 vivas")
	}
	if n := countRot(t, pool, `SELECT COUNT(*) FROM outbox WHERE event_type='session.reuse_detected'
		AND aggregate_id=$1::uuid`, uid); n != 1 {
		t.Fatal("P1 reuse_detected")
	}
	if n := countRot(t, pool, `SELECT COUNT(*) FROM outbox WHERE event_type='audit.session.reuse'
		AND aggregate_id=$1::uuid`, uid); n != 1 {
		t.Fatal("audit reuse")
	}
	var subject string
	if err := pool.QueryRow(ctx, `SELECT subject FROM email_queue WHERE to_email=$1
		ORDER BY created_at DESC LIMIT 1`, email).Scan(&subject); err != nil {
		t.Fatalf("email crítico: %v", err)
	}
	if subject == "" {
		t.Fatal("email con asunto")
	}
}

func TestRotationStore_RevokedFamily(t *testing.T) {
	pool := rotTestPool(t)
	defer pool.Close()
	rdb := rotTestRedis(t)
	defer rdb.Close()
	ctx := context.Background()

	uid, email := seedRotUser(t, pool, "rev")
	defer cleanupRotUser(ctx, pool, uid, email)
	chain := seedRotChain(t, pool, uid, "rev", time.Hour)
	store := newTestRotationStore(pool, rdb)

	if _, err := pool.Exec(ctx, `UPDATE refresh_families SET revoked=TRUE WHERE family=$1::uuid`, chain.family); err != nil {
		t.Fatal(err)
	}
	lkp, err := store.Lookup(ctx, chain.cur)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !lkp.State.Revoked {
		t.Fatal("revoked visible")
	}
	if _, err := store.RotateCAS(ctx, auth.RotateCASInput{
		State: lkp.State, OldHash: chain.cur,
		NewPair: auth.RotatedPair{AccessJWT: "x", Refresh: "y", ExpiresAt: time.Now().UTC().Add(time.Hour),
			SID: chain.sid, Family: chain.family, JTI: uuid.NewString(), Counter: 4},
		NewHash: rotHash("nuevo"), SlidingTo: time.Now().UTC().Add(time.Hour), PresentedFP: "x",
	}); !errors.Is(err, auth.ErrRefreshRevoked) {
		t.Fatalf("revoked→401 base: %v", err)
	}
}
