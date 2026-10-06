package postgres

// Integración CU-SES-02 T-08: RevokeAll contra PG+Redis reales.
// Skip sin compose (patrón session_store_test.go). Cubre: corte 3/3 +
// pub/sub, repeat 0/0 con re-bump, bulk 20/20, usuario borrado→401 base,
// email encolado, barrido Redis (sess/fam/jti/by_user).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func globalTestPool(t *testing.T) *pgxpool.Pool {
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

func globalTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	return rdb
}

func seedGlobalUser(t *testing.T, pool *pgxpool.Pool, tag string) (string, string) {
	t.Helper()
	uid := uuid.NewString()
	email := "grevoke-" + tag + "-" + uid + "@test.local"
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

// cleanupGlobalUser borra huellas sin FK (outbox/email) + usuario (cascada).
func cleanupGlobalUser(ctx context.Context, pool *pgxpool.Pool, uid, email string) {
	_, _ = pool.Exec(ctx, `DELETE FROM outbox WHERE aggregate_id=$1::uuid`, uid)
	_, _ = pool.Exec(ctx, `DELETE FROM email_queue WHERE to_email=$1`, email)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
}

// seedGlobalSessions crea n sesiones vivas (families 1:1) + espejo Redis.
func seedGlobalSessions(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, uid string, n int) (sids []string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	cache := redisadapter.NewSessionCache(rdb)
	for i := 0; i < n; i++ {
		sid, fam, jti := uuid.NewString(), uuid.NewString(), uuid.NewString()
		sum := sha256.Sum256([]byte("g" + sid))
		h := hex.EncodeToString(sum[:])
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
			(sid, user_id, family, jti_actual, device_hash, ip_hash, created_at, last_seen, expires_at)
			VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip',now(),now(),$5)`,
			sid, uid, fam, jti, now.Add(90*24*time.Hour)); err != nil {
			t.Fatalf("session: %v", err)
		}
		_ = cache.Save(ctx, auth.Session{SID: sid, UserID: uid, Family: fam, JTI: jti},
			auth.RefreshFamily{Family: fam, UserID: uid, CurrentHash: h}, jti)
		sids = append(sids, sid)
	}
	return sids
}

func countGlobal(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func TestGlobalRevoker_Integration(t *testing.T) {
	pool := globalTestPool(t)
	defer pool.Close()
	rdb := globalTestRedis(t)
	defer rdb.Close()
	ctx := context.Background()

	uid, uemail := seedGlobalUser(t, pool, "a")
	defer cleanupGlobalUser(ctx, pool, uid, uemail)
	sids := seedGlobalSessions(t, pool, rdb, uid, 3)

	// Suscripción pub/sub ANTES del corte (gateways ~1s).
	sub := rdb.Subscribe(ctx, redisadapter.RevokedAllChannel())
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	msgCh := sub.Channel()

	rev := NewGlobalRevoker(pool, redisadapter.NewGlobalSweep(rdb), nil)
	before := time.Now().UTC()
	out, err := rev.RevokeAll(ctx, uid, "10.9.9.9")
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if out.Sessions != 3 || out.Families != 3 {
		t.Fatalf("counts 3/3: %+v", out)
	}
	if out.ValidAfter.Before(before.Add(-time.Minute)) || out.ValidAfter.After(after.Add(time.Minute)) {
		t.Fatalf("valid_after≈now: %v", out.ValidAfter)
	}

	// PG: 0 vivas, families revocadas, outbox+audit+email.
	if n := countGlobal(t, pool, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid); n != 0 {
		t.Fatal("0 sesiones")
	}
	if n := countGlobal(t, pool, `SELECT COUNT(*) FROM refresh_families WHERE user_id=$1::uuid AND revoked`, uid); n != 3 {
		t.Fatal("3 families revoked")
	}
	var payload string
	if err := pool.QueryRow(ctx, `SELECT payload::text FROM outbox
		WHERE event_type='session.revoked_all' AND aggregate_id=$1::uuid`, uid).Scan(&payload); err != nil {
		t.Fatalf("revoked_all: %v", err)
	}
	var env struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		t.Fatalf("json: %v", err)
	}
	if int(env.Payload["sessions"].(float64)) != 3 || env.Payload["reason"] != "user_request" {
		t.Fatalf("payload: %v", env.Payload)
	}
	if n := countGlobal(t, pool, `SELECT COUNT(*) FROM outbox WHERE event_type='audit.session.logout_global'
		AND aggregate_id=$1::uuid AND payload->>'result'='ok'`, uid); n != 1 {
		t.Fatal("audit ok")
	}
	var mailTo, mailSubject, mailStatus string
	if err := pool.QueryRow(ctx, `SELECT to_email, subject, status FROM email_queue
		WHERE to_email LIKE 'grevoke-a-%' ORDER BY created_at DESC LIMIT 1`).Scan(&mailTo, &mailSubject, &mailStatus); err != nil {
		t.Fatalf("email: %v", err)
	}
	if mailStatus != "pending" || mailSubject == "" || mailTo == "" {
		t.Fatalf("email pendiente: %q %q %q", mailTo, mailSubject, mailStatus)
	}

	// Redis: sess/fam/jti barridos + índice borrado.
	for _, sid := range sids {
		if rdb.Exists(ctx, "sess:"+sid).Val() != 0 {
			t.Fatalf("sess barrido: %s", sid)
		}
	}
	if rdb.Exists(ctx, redisadapter.SessByUserKey(uid)).Val() != 0 {
		t.Fatal("by_user borrado")
	}

	// PUBLISH recibido (~1s gateway).
	select {
	case m := <-msgCh:
		var pm struct {
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal([]byte(m.Payload), &pm); err != nil {
			t.Fatalf("pub json: %v", err)
		}
		if pm.Payload["user_id"] != uid {
			t.Fatalf("pub user: %v", pm.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sin PUBLISH (ventana ~1s)")
	}

	// Repeat con 0 vivas → 200 shape 0/0 + re-bump (2º revoked_all).
	out2, err := rev.RevokeAll(ctx, uid, "10.9.9.9")
	if err != nil || out2.Sessions != 0 || out2.Families != 0 {
		t.Fatalf("repeat 0/0: %v %+v", err, out2)
	}
	if !out2.ValidAfter.After(out.ValidAfter.Add(-time.Second)) {
		t.Fatal("re-bump monótono")
	}
	if n := countGlobal(t, pool, `SELECT COUNT(*) FROM outbox WHERE event_type='session.revoked_all'
		AND aggregate_id=$1::uuid`, uid); n != 2 {
		t.Fatalf("re-bump emite de nuevo: %d", n)
	}
}

func TestGlobalRevoker_Bulk20(t *testing.T) {
	pool := globalTestPool(t)
	defer pool.Close()
	rdb := globalTestRedis(t)
	defer rdb.Close()
	ctx := context.Background()

	uid, uemail := seedGlobalUser(t, pool, "bulk")
	defer cleanupGlobalUser(ctx, pool, uid, uemail)
	seedGlobalSessions(t, pool, rdb, uid, 20)

	rev := NewGlobalRevoker(pool, redisadapter.NewGlobalSweep(rdb), nil)
	out, err := rev.RevokeAll(ctx, uid, "10.9.9.20")
	if err != nil || out.Sessions != 20 || out.Families != 20 {
		t.Fatalf("bulk 20/20: %v %+v", err, out)
	}
	if n := countGlobal(t, pool, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid); n != 0 {
		t.Fatal("0 vivas post-corte")
	}
}

func TestGlobalRevoker_UserMissing(t *testing.T) {
	pool := globalTestPool(t)
	defer pool.Close()
	rdb := globalTestRedis(t)
	defer rdb.Close()

	rev := NewGlobalRevoker(pool, redisadapter.NewGlobalSweep(rdb), nil)
	if _, err := rev.RevokeAll(context.Background(), uuid.NewString(), "1.1.1.1"); !errors.Is(err, auth.ErrGlobalUserNotFound) {
		t.Fatalf("borrado→401 base: %v", err)
	}
}
