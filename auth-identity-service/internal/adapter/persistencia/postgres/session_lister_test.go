package postgres

// Integración CU-SES-03 T-08: List/RevokeOne/Touch contra PG+Redis reales.
// Skip sin compose. Cubre: orden+masked PG, fast-path Redis all-or-nothing,
// miss→PG, RevokeOne triple-capa+outbox+audit+email, miss→NotFound,
// Touch debounce (1 UPDATE/5min) + espejo, Redis-down vía PG.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func listerTestPool(t *testing.T) *pgxpool.Pool {
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

func listerTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	return rdb
}

func seedListUser(t *testing.T, pool *pgxpool.Pool, tag string) (string, string) {
	t.Helper()
	uid := uuid.NewString()
	email := "seslist-" + tag + "-" + uid + "@test.local"
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

// cleanupListUser borra huellas sin FK (outbox/email) + el usuario (cascada
// limpia sessions/families/hashes/revoked_jtis).
func cleanupListUser(ctx context.Context, pool *pgxpool.Pool, uid, email string) {
	_, _ = pool.Exec(ctx, `DELETE FROM outbox WHERE aggregate_id=$1::uuid`, uid)
	_, _ = pool.Exec(ctx, `DELETE FROM email_queue WHERE to_email=$1`, email)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
}

type listSeed struct{ sid, family, jti string }

// seedListSessions crea n sesiones con labels y last_seen escalonados.
func seedListSessions(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, uid string, n int) []listSeed {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	cache := redisadapter.NewSessionCache(rdb)
	out := make([]listSeed, 0, n)
	for i := 0; i < n; i++ {
		sid, fam, jti := uuid.NewString(), uuid.NewString(), uuid.NewString()
		sum := sha256.Sum256([]byte("l" + sid))
		h := hex.EncodeToString(sum[:])
		seen := now.Add(-time.Duration(i) * time.Hour)
		label := "Chrome · Windows"
		masked := "203.0.113.xxx"
		if _, err := pool.Exec(ctx, `INSERT INTO refresh_families
			(family, user_id, current_hash, counter, absolute_exp, revoked)
			VALUES ($1::uuid,$2::uuid,$3,0,$4,FALSE)`, fam, uid, h, now.Add(90*24*time.Hour)); err != nil {
			t.Fatalf("family: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO refresh_hashes (hash, family, counter, expires_at)
			VALUES ($1,$2::uuid,0,$3)`, h, fam, now.Add(30*24*time.Hour)); err != nil {
			t.Fatalf("hash: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO sessions
			(sid, user_id, family, jti_actual, device_hash, ip_hash, created_at, last_seen, expires_at,
			device_label, ip_masked, location)
			VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip',$5,$6,$7,$8,$9,$10)`,
			sid, uid, fam, jti, now, seen, now.Add(90*24*time.Hour), label, masked, "Lima, PE"); err != nil {
			t.Fatalf("session: %v", err)
		}
		_ = cache.Save(ctx, auth.Session{SID: sid, UserID: uid, Family: fam, JTI: jti,
			DeviceHash: "d", IPHash: "ip", DeviceLabel: label, IPMasked: masked, Location: "Lima, PE",
			CreatedAt: now, LastSeen: seen},
			auth.RefreshFamily{Family: fam, UserID: uid, CurrentHash: h}, jti)
		out = append(out, listSeed{sid: sid, family: fam, jti: jti})
	}
	return out
}

func TestSessionLister_Integration(t *testing.T) {
	pool := listerTestPool(t)
	defer pool.Close()
	rdb := listerTestRedis(t)
	defer rdb.Close()
	ctx := context.Background()

	uid, uemail := seedListUser(t, pool, "a")
	defer cleanupListUser(ctx, pool, uid, uemail)
	seeds := seedListSessions(t, pool, rdb, uid, 3)

	lister := NewSessionLister(pool, redisadapter.NewSessionListCache(rdb), nil)

	// 1. Lista PG: orden last_seen DESC + masked, sin sensibles.
	views, err := lister.List(ctx, uid)
	if err != nil || len(views) != 3 {
		t.Fatalf("list: %v (%d)", err, len(views))
	}
	if views[0].SID != seeds[0].sid {
		t.Fatalf("orden DESC: %q", views[0].SID)
	}
	for _, v := range views {
		if v.DeviceLabel == "" || v.IPMasked == "" || v.Location != "Lima, PE" {
			t.Fatalf("masked: %+v", v)
		}
	}

	// 2. Fast-path Redis: mismo contenido (all-or-nothing).
	cached, err := redisadapter.NewSessionListCache(rdb).List(ctx, uid)
	if err != nil || len(cached) != 3 || cached[0].SID != seeds[0].sid {
		t.Fatalf("cache: %v (%d)", err, len(cached))
	}

	// 3. RevokeOne remota: triple-capa + outbox + audit + email.
	out, err := lister.RevokeOne(ctx, uid, seeds[0].sid, seeds[2].sid)
	if err != nil || out.SID != seeds[2].sid {
		t.Fatalf("revoke: %v %+v", err, out)
	}
	if out.DeviceLabel != "Chrome · Windows" || out.IPMasked != "203.0.113.xxx" {
		t.Fatalf("labels para email: %+v", out)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE sid=$1::uuid`, seeds[2].sid).Scan(&n)
	if n != 0 {
		t.Fatal("target borrada")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid).Scan(&n)
	if n != 2 {
		t.Fatal("resto vive")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM refresh_families WHERE family=$1::uuid AND revoked`, seeds[2].family).Scan(&n)
	if n != 1 {
		t.Fatal("family revocada")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE event_type='session.revoked_one'
		AND payload::json->'payload'->>'sid'=$1`, seeds[2].sid).Scan(&n)
	if n != 1 {
		t.Fatal("outbox revoked_one")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE event_type='audit.session.revoke_one'
		AND aggregate_id=$1::uuid`, uid).Scan(&n)
	if n != 1 {
		t.Fatal("audit revoke_one")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_queue WHERE to_email=$1`, uemail).Scan(&n)
	if n != 1 {
		t.Fatal("email aviso")
	}
	if rdb.Exists(ctx, "sess:"+seeds[2].sid).Val() != 0 {
		t.Fatal("sess DEL")
	}
	if v := rdb.Get(ctx, "jti:"+seeds[2].jti).Val(); v != "revoked" {
		t.Fatalf("denylist jti: %q", v)
	}

	// 4. Miss → NotFound (ajena/muerta, idéntico).
	if _, err := lister.RevokeOne(ctx, uid, seeds[0].sid, seeds[2].sid); err == nil {
		t.Fatal("muerta→NotFound")
	}
	if _, err := lister.RevokeOne(ctx, uid, seeds[0].sid, uuid.NewString()); err == nil {
		t.Fatal("inexistente→NotFound")
	}
	other, otherEmail := seedListUser(t, pool, "b")
	defer cleanupListUser(ctx, pool, other, otherEmail)
	otherSeeds := seedListSessions(t, pool, rdb, other, 1)
	if _, err := lister.RevokeOne(ctx, uid, seeds[0].sid, otherSeeds[0].sid); err == nil {
		t.Fatal("ajena→NotFound")
	}
	// La ajena sigue viva (0 cambios).
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE sid=$1::uuid`, otherSeeds[0].sid).Scan(&n)
	if n != 1 {
		t.Fatal("ajena intacta")
	}

	// 5. Touch debounce: 1º actualiza, 2º inmediato no.
	var before time.Time
	_ = pool.QueryRow(ctx, `SELECT last_seen FROM sessions WHERE sid=$1::uuid`, seeds[0].sid).Scan(&before)
	touchAt := before.Add(30 * time.Minute)
	if err := lister.Touch(ctx, uid, seeds[0].sid, touchAt); err != nil {
		t.Fatalf("touch: %v", err)
	}
	var afterFirst time.Time
	_ = pool.QueryRow(ctx, `SELECT last_seen FROM sessions WHERE sid=$1::uuid`, seeds[0].sid).Scan(&afterFirst)
	if !afterFirst.Equal(touchAt.UTC()) && afterFirst.Sub(touchAt.UTC()) > time.Second {
		t.Fatalf("touch actualiza: %v vs %v", afterFirst, touchAt)
	}
	if err := lister.Touch(ctx, uid, seeds[0].sid, touchAt.Add(time.Minute)); err != nil {
		t.Fatalf("touch2: %v", err)
	}
	var afterSecond time.Time
	_ = pool.QueryRow(ctx, `SELECT last_seen FROM sessions WHERE sid=$1::uuid`, seeds[0].sid).Scan(&afterSecond)
	if !afterSecond.Equal(afterFirst) {
		t.Fatalf("debounce 5min: %v vs %v", afterFirst, afterSecond)
	}
	if ttl := rdb.TTL(ctx, "touch:"+seeds[0].sid).Val(); ttl <= 0 {
		t.Fatalf("touch key TTL: %v", ttl)
	}
}

func TestSessionLister_PGDown500(t *testing.T) {
	// Sin pool → ErrSessionInfra (el servicio responde 500, jamás 200 []).
	lister := NewSessionLister(nil, nil, nil)
	if _, err := lister.List(context.Background(), uuid.NewString()); err == nil {
		t.Fatal("list sin PG → error")
	}
	if _, err := lister.RevokeOne(context.Background(), uuid.NewString(), uuid.NewString(), uuid.NewString()); err == nil {
		t.Fatal("revoke sin PG → error")
	}
}
