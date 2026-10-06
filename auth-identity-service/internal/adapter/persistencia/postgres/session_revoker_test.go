package postgres

// Integración CU-SES-01 T-08: RevokeSID/ByRefresh contra PG+Redis reales.
// Requiere compose up (postgres+redis); si no hay, skip (patrón
// session_store_test.go). Cubre: ok triple-capa, Already idempotente sin
// doble-outbox, ByRefresh, hash desconocido→Already, filas de auditoría.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func revokerTestPool(t *testing.T) *pgxpool.Pool {
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

func revokerTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	return rdb
}

func ensureRevokeSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS revoked_jtis (
		  jti UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		  expires_at TIMESTAMPTZ NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_revoked_exp ON revoked_jtis(expires_at)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
}

func seedRevokeUser(t *testing.T, pool *pgxpool.Pool) (uid string) {
	t.Helper()
	ctx := context.Background()
	uid = uuid.NewString()
	email := "revoke-" + uid + "@test.local"
	_, err := pool.Exec(ctx, `INSERT INTO users (id, email_normalized, email_original,
		password_hash, status, terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, '$argon2id$v=19$m=65536$test$hash',
		'ACTIVE','v2026.10','v2026.10', now())
		ON CONFLICT (email_normalized) DO NOTHING`, uid, email)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	return uid
}

// seedRevokeSession crea family+sesión+hash vivos y los refleja en Redis
// (como haría IssueService.Save).
func seedRevokeSession(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, uid string) (sid, family, jti, refreshHash string) {
	t.Helper()
	ctx := context.Background()
	sid, family, jti = uuid.NewString(), uuid.NewString(), uuid.NewString()
	plain := uuid.NewString() + uuid.NewString()
	sum := sha256.Sum256([]byte(plain))
	refreshHash = hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	_, err := pool.Exec(ctx, `INSERT INTO refresh_families
		(family, user_id, current_hash, counter, absolute_exp, revoked)
		VALUES ($1::uuid,$2::uuid,$3,0,$4,FALSE)`, family, uid, refreshHash, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("family: %v", err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO refresh_hashes (hash, family, counter, expires_at)
		VALUES ($1,$2::uuid,0,$3)`, refreshHash, family, now.Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO sessions
		(sid, user_id, family, jti_actual, device_hash, ip_hash, created_at, last_seen, expires_at)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip',now(),now(),$5)`,
		sid, uid, family, jti, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	cache := redisadapter.NewSessionCache(rdb)
	_ = cache.Save(ctx, auth.Session{SID: sid, UserID: uid, Family: family, JTI: jti, DeviceHash: "d", IPHash: "ip"},
		auth.RefreshFamily{Family: family, UserID: uid, CurrentHash: refreshHash}, jti)
	_ = plain
	return sid, family, jti, refreshHash
}

func countWhere(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func TestSessionRevoker_Integration(t *testing.T) {
	pool := revokerTestPool(t)
	defer pool.Close()
	rdb := revokerTestRedis(t)
	defer rdb.Close()
	ensureRevokeSchema(t, pool)
	ctx := context.Background()

	uid := seedRevokeUser(t, pool)
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
	sid, family, jti, _ := seedRevokeSession(t, pool, rdb, uid)

	rev := NewSessionRevoker(pool, redisadapter.NewLogoutCache(rdb), nil)
	exp := time.Now().UTC().Add(10 * time.Minute)

	// 1. RevokeSID ok triple-capa.
	out, err := rev.RevokeSID(ctx, auth.LogoutIdentity{
		UserID: uid, SID: sid, JTI: jti, ExpiresAt: exp,
	})
	if err != nil || out.Result != auth.LogoutLoggedOut {
		t.Fatalf("ok: %v %+v", err, out)
	}
	if out.Identity.Family != family {
		t.Fatalf("family resuelta: %q", out.Identity.Family)
	}
	if n := countWhere(t, pool, `SELECT COUNT(*) FROM sessions WHERE sid=$1::uuid`, sid); n != 0 {
		t.Fatal("sesión borrada")
	}
	if n := countWhere(t, pool, `SELECT COUNT(*) FROM refresh_families WHERE family=$1::uuid AND revoked`, family); n != 1 {
		t.Fatal("family revocada")
	}
	if n := countWhere(t, pool, `SELECT COUNT(*) FROM revoked_jtis WHERE jti=$1::uuid`, jti); n != 1 {
		t.Fatal("denylist PG")
	}
	if n := countWhere(t, pool, `SELECT COUNT(*) FROM outbox WHERE event_type='session.logged_out'
		AND payload::json->'payload'->>'sid'=$1`, sid); n != 1 {
		t.Fatal("1 outbox logged_out")
	}
	// Auditoría en la misma Tx (topic auth.audit.v1, sin tokens).
	var auditSID, auditFam, auditJTI, auditResult string
	if err := pool.QueryRow(ctx, `SELECT payload->>'sid', payload->>'family',
		payload->>'jti', payload->>'result' FROM outbox
		WHERE event_type='audit.session.logout' AND aggregate_id=$1::uuid`, uid).Scan(
		&auditSID, &auditFam, &auditJTI, &auditResult); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if auditSID != sid || auditFam != family || auditJTI != jti || auditResult != "ok" {
		t.Fatalf("audit: %q %q %q %q", auditSID, auditFam, auditJTI, auditResult)
	}
	var auditPayload string
	_ = pool.QueryRow(ctx, `SELECT payload::text FROM outbox
		WHERE event_type='audit.session.logout' AND aggregate_id=$1::uuid`, uid).Scan(&auditPayload)
	for _, secret := range []string{"access_token", "refresh_token", "password"} {
		if strings.Contains(strings.ToLower(auditPayload), secret) {
			t.Fatalf("audit expone %q", secret)
		}
	}
	if v := rdb.Get(ctx, "jti:"+jti).Val(); v != "revoked" {
		t.Fatalf("denylist Redis: %q", v)
	}
	if rdb.Exists(ctx, "sess:"+sid).Val() != 0 {
		t.Fatal("sess DEL")
	}

	// 2. Replay → Already, sin doble-outbox.
	out2, err := rev.RevokeSID(ctx, auth.LogoutIdentity{
		UserID: uid, SID: sid, JTI: jti, ExpiresAt: exp,
	})
	if err != nil || out2.Result != auth.LogoutAlreadyLoggedOut {
		t.Fatalf("already: %v %+v", err, out2)
	}
	if n := countWhere(t, pool, `SELECT COUNT(*) FROM outbox WHERE event_type='session.logged_out'
		AND payload::json->'payload'->>'sid'=$1`, sid); n != 1 {
		t.Fatal("sin doble-outbox")
	}
	// El replay deja rastro de auditoría (already) sin nuevo logged_out.
	if n := countWhere(t, pool, `SELECT COUNT(*) FROM outbox WHERE event_type='audit.session.logout'
		AND aggregate_id=$1::uuid AND payload->>'result'='already'`, uid); n < 1 {
		t.Fatal("audit del replay")
	}

	// 3. ByRefresh sobre sesión viva nueva.
	sid2, fam2, _, hash2 := seedRevokeSession(t, pool, rdb, uid)
	out3, err := rev.RevokeByRefreshHash(ctx, hash2)
	if err != nil || out3.Result != auth.LogoutLoggedOut {
		t.Fatalf("by-refresh: %v %+v", err, out3)
	}
	if out3.Identity.SID != sid2 || out3.Identity.Family != fam2 {
		t.Fatalf("identidad resuelta: %+v", out3.Identity)
	}

	// 4. Hash desconocido → Already (sin oráculo).
	out4, err := rev.RevokeByRefreshHash(ctx, hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil || out4.Result != auth.LogoutAlreadyLoggedOut {
		t.Fatalf("unknown hash: %v %+v", err, out4)
	}
}
