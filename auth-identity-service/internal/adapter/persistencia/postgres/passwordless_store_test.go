package postgres

// Integración CU-AUTH-05 T-08/T-12: dual-write + supersede + quotas +
// ConsumeTx (low/high-risk) + burn + cascade.
// Requiere PG/Redis locales (docker compose up); si no hay, skip.

import (
	"context"
	"os"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func plessTestPool(t *testing.T) *pgxpool.Pool {
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

func plessSetup(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS passwordless_tokens (
	  token_hash TEXT PRIMARY KEY, otp_hash TEXT NOT NULL UNIQUE,
	  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  expires_at TIMESTAMPTZ NOT NULL, attempts INT NOT NULL DEFAULT 0,
	  consumed BOOLEAN NOT NULL DEFAULT FALSE, superseded BOOLEAN NOT NULL DEFAULT FALSE,
	  ctx_ip_hash TEXT NOT NULL, ctx_ua_hash TEXT NOT NULL,
	  created_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	_, _ = pool.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ`)
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS email_queue (
	  id UUID PRIMARY KEY, to_email TEXT NOT NULL, subject TEXT NOT NULL, body_text TEXT NOT NULL,
	  status TEXT NOT NULL DEFAULT 'pending', attempts INT NOT NULL DEFAULT 0,
	  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), sent_at TIMESTAMPTZ)`)
}

func plessEnsureUser(t *testing.T, pool *pgxpool.Pool, uid, email, status string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `INSERT INTO users
		(id, email_normalized, email_original, status, terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, $3,'v2026.10','v2026.10', now())
		ON CONFLICT (email_normalized) DO NOTHING`, uid, email, status)
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
}

func plessStore(t *testing.T, pool *pgxpool.Pool) *CombinedPasswordlessStore {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return NewCombinedPasswordlessStore(pool, redisadapter.NewPasswordlessCache(rdb),
		"http://localhost:3000", nil)
}

func plessRec(uid, th, oh string, ctx auth.PlessContext) *auth.PasswordlessRecord {
	return &auth.PasswordlessRecord{
		UserID: uid, TokenHash: th, OTPHash: oh,
		ExpiresAt: time.Now().UTC().Add(auth.PlessTTL),
		Ctx: ctx, TokenPlain: "plain-" + th[:8], OTPPlain: "12345678",
	}
}

func TestPlessStore_IssueConsume(t *testing.T) {
	pool := plessTestPool(t)
	defer pool.Close()
	plessSetup(t, pool)
	ctx := context.Background()
	uid := uuid.NewString()
	email := "pless-" + uid + "@load.test"
	plessEnsureUser(t, pool, uid, email, string(user.StatusActive))
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
	store := plessStore(t, pool)

	// Eligible ACTIVE (+mfa=false).
	gotUID, mfa, eligible, err := store.Eligible(ctx, email)
	if err != nil || !eligible || gotUID != uid || mfa {
		t.Fatalf("eligible: %v %v %v %v", gotUID, mfa, eligible, err)
	}
	// PENDING → no elegible (pero resuelve uid).
	uid2 := uuid.NewString()
	email2 := "pless-p-" + uid2 + "@load.test"
	plessEnsureUser(t, pool, uid2, email2, string(user.StatusPendingVerification))
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid2)
	if _, _, eligible, _ := store.Eligible(ctx, email2); eligible {
		t.Fatal("pending no elegible")
	}
	if _, _, eligible, _ := store.Eligible(ctx, "nadie@load.test"); eligible {
		t.Fatal("inexistente no elegible")
	}

	// Quota fresca permite; tras NoteSent interno (Issue) throttled por cooldown.
	plessEnsureUser(t, pool, uid, email, string(user.StatusActive))
	emitCtx := auth.NewPlessContext("1.2.3.4", "Mozilla/5.0")
	rec1 := plessRec(uid, "ptest-th-1-"+uid[:8], "ptest-oh-1-"+uid[:8], emitCtx)
	if err := store.Issue(ctx, rec1); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Email encolado con link + OTP.
	var body string
	if err := pool.QueryRow(ctx, `SELECT body_text FROM email_queue WHERE to_email=$1 ORDER BY created_at DESC LIMIT 1`, email).Scan(&body); err != nil {
		t.Fatalf("email_queue: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("cuerpo vacío")
	}
	// Outbox requested.
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE aggregate_id=$1::uuid AND event_type='passwordless.requested'`, uid).Scan(&n)
	if n == 0 {
		t.Fatal("falta outbox requested")
	}

	// Segundo Issue supersede al primero (solo 1 activo).
	plessEnsureUser(t, pool, uid, email, string(user.StatusActive))
	rec2 := plessRec(uid, "ptest-th-2-"+uid[:8], "ptest-oh-2-"+uid[:8], emitCtx)
	if err := store.Issue(ctx, rec2); err != nil {
		t.Fatalf("issue2: %v", err)
	}
	var sup bool
	_ = pool.QueryRow(ctx, `SELECT superseded FROM passwordless_tokens WHERE token_hash=$1`, rec1.TokenHash).Scan(&sup)
	if !sup {
		t.Fatal("supersede anterior")
	}

	// FindAlive por link y por OTP.
	if _, err := store.FindAlive(ctx, rec2.TokenHash); err != nil {
		t.Fatalf("find link: %v", err)
	}
	got, err := store.FindAlive(ctx, rec2.OTPHash)
	if err != nil || got.UserID != uid {
		t.Fatalf("find otp: %v %+v", err, got)
	}

	// Quota throttled tras envío (cooldown 60s).
	if allowed, _, _ := store.QuotaCheck(ctx, uid); allowed {
		t.Fatal("cooldown debe throttlear")
	}

	// ConsumeTx low-risk → MFA false, last_login, outbox consumed.
	consumeCtx := auth.NewPlessContext("1.2.3.99", "Mozilla/5.0 Chrome/1")
	res, err := store.ConsumeTx(ctx, uid, rec2.TokenHash, "link", auth.RiskOf(emitCtx, consumeCtx),
		consumeCtx.IPHash24, consumeCtx.UAHash)
	if err != nil || res.UserID != uid || res.MFAEnabled {
		t.Fatalf("consume: %v %+v", err, res)
	}
	var ll bool
	_ = pool.QueryRow(ctx, `SELECT last_login IS NOT NULL FROM users WHERE id=$1::uuid`, uid).Scan(&ll)
	if !ll {
		t.Fatal("last_login")
	}
	// Reuso → inválido.
	if _, err := store.ConsumeTx(ctx, uid, rec2.TokenHash, "link", "low", "x", "y"); err == nil {
		t.Fatal("reuso debe fallar")
	}
	// FK cascade.
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid); err != nil {
		t.Fatal(err)
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM passwordless_tokens WHERE user_id=$1::uuid`, uid).Scan(&n)
	if n != 0 {
		t.Fatal("cascade")
	}
}

func TestPlessStore_HighRiskMismatch(t *testing.T) {
	pool := plessTestPool(t)
	defer pool.Close()
	plessSetup(t, pool)
	ctx := context.Background()
	uid := uuid.NewString()
	email := "pless-hr-" + uid + "@load.test"
	plessEnsureUser(t, pool, uid, email, string(user.StatusActive))
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
	store := plessStore(t, pool)

	emitCtx := auth.NewPlessContext("192.168.1.10", "Mozilla/5.0 Chrome/120")
	rec := plessRec(uid, "phr-th-"+uid[:8], "phr-oh-"+uid[:8], emitCtx)
	if err := store.Issue(ctx, rec); err != nil {
		t.Fatalf("issue: %v", err)
	}
	consumeCtx := auth.NewPlessContext("10.20.30.40", "okhttp/4.12")
	risk := auth.RiskOf(emitCtx, consumeCtx)
	if risk != "high" {
		t.Fatalf("risk: %q", risk)
	}
	if _, err := store.ConsumeTx(ctx, uid, rec.TokenHash, "link", risk, consumeCtx.IPHash24, consumeCtx.UAHash); err != nil {
		t.Fatalf("consume high: %v", err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE aggregate_id=$1::uuid AND event_type='security.context_mismatch'`, uid).Scan(&n)
	if n == 0 {
		t.Fatal("falta outbox mismatch")
	}
	var subj string
	if err := pool.QueryRow(ctx, `SELECT subject FROM email_queue WHERE to_email=$1 ORDER BY created_at DESC LIMIT 1`, email).Scan(&subj); err != nil || subj == "" {
		t.Fatalf("alerta email: %v %q", err, subj)
	}
}

func TestPlessStore_QuemaTresIntentos(t *testing.T) {
	pool := plessTestPool(t)
	defer pool.Close()
	plessSetup(t, pool)
	ctx := context.Background()
	uid := uuid.NewString()
	email := "pless-bu-" + uid + "@load.test"
	plessEnsureUser(t, pool, uid, email, string(user.StatusActive))
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
	// Sin caché (PG puro): quema al 3º.
	bare := NewCombinedPasswordlessStore(pool, nil, "http://localhost:3000", nil)
	rec := plessRec(uid, "pbu-th-"+uid[:8], "pbu-oh-"+uid[:8], auth.NewPlessContext("1.1.1.1", "UA"))
	if err := bare.Issue(ctx, rec); err != nil {
		t.Fatalf("issue: %v", err)
	}
	for i := 0; i < 2; i++ {
		if burned, _ := bare.IncrementAttempts(ctx, rec.TokenHash); burned {
			t.Fatalf("quema prematura en %d", i)
		}
	}
	if burned, _ := bare.IncrementAttempts(ctx, rec.TokenHash); !burned {
		t.Fatal("3º debe quemar")
	}
	if _, err := bare.FindAlive(ctx, rec.TokenHash); err == nil {
		t.Fatal("quemado no reutilizable")
	}
}
