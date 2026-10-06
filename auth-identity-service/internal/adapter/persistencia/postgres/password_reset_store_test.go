package postgres

// Integración CU-CRED-01 T-08/T-12: eligible/hint + supersede + quotas +
// ConsumeTx con corte global (valid_after + revoke + emails) + burn + cascade.
// Requiere PG/Redis locales (docker compose up); si no hay, skip.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/adapter/security"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func pwdResetTestPool(t *testing.T) *pgxpool.Pool {
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

// isDeadlock detecta abortos por contención (40P01) para reintentar una vez.
func isDeadlock(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "deadlock") || strings.Contains(msg, "40P01")
}

func pwdResetSetup(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS password_reset_tokens (
	  token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  expires_at TIMESTAMPTZ NOT NULL, attempts INT NOT NULL DEFAULT 0,
	  consumed BOOLEAN NOT NULL DEFAULT FALSE, superseded BOOLEAN NOT NULL DEFAULT FALSE,
	  ctx_ip_hash TEXT NOT NULL, ctx_ua_hash TEXT NOT NULL,
	  created_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sessions (
	  sid UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  family UUID NOT NULL, jti_actual UUID NOT NULL, device_hash TEXT NOT NULL, ip_hash TEXT NOT NULL,
	  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
	  expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '90 days')`)
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS refresh_families (
	  family UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  current_hash TEXT NOT NULL UNIQUE, parent_hash TEXT NOT NULL DEFAULT '',
	  counter INT NOT NULL DEFAULT 0, absolute_exp TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)`)
	_, _ = pool.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z'`)
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS email_queue (
	  id UUID PRIMARY KEY, to_email TEXT NOT NULL, subject TEXT NOT NULL, body_text TEXT NOT NULL,
	  status TEXT NOT NULL DEFAULT 'pending', attempts INT NOT NULL DEFAULT 0,
	  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), sent_at TIMESTAMPTZ)`)
}

func pwdResetStore(t *testing.T, pool *pgxpool.Pool) *CombinedPasswordResetStore {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return NewCombinedPasswordResetStore(pool,
		redisadapter.NewPasswordResetCache(rdb), redisadapter.NewSessionCache(rdb),
		"http://localhost:3000", nil)
}

func pwdResetUser(t *testing.T, pool *pgxpool.Pool, email, status, password string) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.NewString()
	var pwHash any
	if password != "" {
		pwHash = password
	}
	_, err := pool.Exec(ctx, `INSERT INTO users
		(id, email_normalized, email_original, password_hash, password_algo, status,
		 terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, $3, 'argon2id', $4,'v2026.10','v2026.10', now())
		ON CONFLICT (email_normalized) DO NOTHING`,
		uid, email, pwHash, status)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	// Resuelve el id real (por si existía de otra corrida).
	var id string
	_ = pool.QueryRow(ctx, `SELECT id::text FROM users WHERE email_normalized=$1::citext`, email).Scan(&id)
	if id == "" {
		t.Fatal("sin usuario")
	}
	return id
}

func TestPwdResetStore_EligibleIssueConsume(t *testing.T) {
	pool := pwdResetTestPool(t)
	defer pool.Close()
	pwdResetSetup(t, pool)
	ctx := context.Background()

	hasher := security.NewArgon2Hasher(nil)
	oldHash, err := hasher.Hash(ctx, "Str0ng!Passw0rd-2026")
	if err != nil {
		t.Fatal(err)
	}
	email := "pr-" + uuid.NewString() + "@load.test"
	uid := pwdResetUser(t, pool, email, string(user.StatusActive), oldHash)
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
	store := pwdResetStore(t, pool)

	// Elegible + 2 sesiones vivas (para el corte).
	if _, eligible, hint, err := store.EligibleForReset(ctx, email); err != nil || !eligible || hint {
		t.Fatalf("eligible: %v %v %v", eligible, hint, err)
	}
	sid1, fam1, jti1 := uuid.NewString(), uuid.NewString(), uuid.NewString()
	sid2 := uuid.NewString()
	_, _ = pool.Exec(ctx, `INSERT INTO sessions (sid, user_id, family, jti_actual, device_hash, ip_hash)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip')`, sid1, uid, fam1, jti1)
	_, _ = pool.Exec(ctx, `INSERT INTO sessions (sid, user_id, family, jti_actual, device_hash, ip_hash)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip')`, sid2, uid, uuid.NewString(), uuid.NewString())
	_, _ = pool.Exec(ctx, `INSERT INTO refresh_families (family, user_id, current_hash, absolute_exp)
		VALUES ($1::uuid,$2::uuid,'h1',now()+INTERVAL '90 days')`, fam1, uid)

	emitCtx := auth.NewPlessContext("1.2.3.4", "Mozilla/5.0")
	rec := &auth.PasswordResetRecord{UserID: uid, TokenHash: "pr-th-1",
		ExpiresAt: time.Now().UTC().Add(auth.PwdResetTTL), Ctx: emitCtx, TokenPlain: "plain-token-43ch-00000000000000000000"}
	if err := store.Issue(ctx, rec); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Email con link + outbox requested.
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_queue WHERE to_email=$1 AND subject='Restablece tu contraseña'`, email).Scan(&n)
	if n == 0 {
		t.Fatal("falta email con link")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE aggregate_id=$1::uuid AND event_type='password.reset_requested'`, uid).Scan(&n)
	if n == 0 {
		t.Fatal("falta outbox requested")
	}
	// Segundo Issue supersede al primero.
	rec2 := &auth.PasswordResetRecord{UserID: uid, TokenHash: "pr-th-2",
		ExpiresAt: time.Now().UTC().Add(auth.PwdResetTTL), Ctx: emitCtx, TokenPlain: "plain-2"}
	if err := store.Issue(ctx, rec2); err != nil {
		// Deadlock por contención paralela (Tx abortada, estado intacto):
		// reintenta la misma operación una vez.
		if isDeadlock(err) {
			if err := store.Issue(ctx, rec2); err != nil {
				t.Fatalf("issue2: %v", err)
			}
		} else {
			t.Fatalf("issue2: %v", err)
		}
	}
	var sup bool
	_ = pool.QueryRow(ctx, `SELECT superseded FROM password_reset_tokens WHERE token_hash='pr-th-1'`).Scan(&sup)
	if !sup {
		t.Fatal("supersede anterior")
	}
	// Quota throttled tras envío.
	if allowed, _, _ := store.QuotaCheck(ctx, uid); allowed {
		t.Fatal("cooldown debe throttlear")
	}

	// Re-asegura estado ante wipes concurrentes de E2E (serial -p 1 no los hay).
	uid = pwdResetUser(t, pool, email, string(user.StatusActive), oldHash)
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid).Scan(&n)
	if n == 0 {
		_, _ = pool.Exec(ctx, `INSERT INTO sessions (sid, user_id, family, jti_actual, device_hash, ip_hash)
			VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip')`, sid1, uid, fam1, jti1)
		_, _ = pool.Exec(ctx, `INSERT INTO refresh_families (family, user_id, current_hash, absolute_exp)
			VALUES ($1::uuid,$2::uuid,'h1',now()+INTERVAL '90 days')
			ON CONFLICT (family) DO NOTHING`, fam1, uid)
	}
	var tokExists bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM password_reset_tokens WHERE token_hash='pr-th-2')`).Scan(&tokExists)
	if !tokExists {
		if err := store.Issue(ctx, rec2); err != nil {
			t.Fatalf("re-issue: %v", err)
		}
	}

	// ConsumeTx low-risk: cambio + corte + emails + outbox.
	newHash, _ := hasher.Hash(ctx, "Nu3va!Valida-2026")
	consumeCtx := auth.NewPlessContext("1.2.3.9", "Mozilla/5.0 Chrome/1")
	if err := store.ConsumeTx(ctx, uid, "pr-th-2", newHash,
		auth.RiskOf(emitCtx, consumeCtx), consumeCtx.IPHash24, consumeCtx.UAHash, "req-test-1"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	var gotHash, va string
	_ = pool.QueryRow(ctx, `SELECT password_hash, tokens_valid_after::text FROM users WHERE id=$1::uuid`, uid).Scan(&gotHash, &va)
	if gotHash != newHash || va == "" {
		t.Fatal("hash rotado + valid_after")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid).Scan(&n)
	if n != 0 {
		t.Fatal("0 sesiones tras corte")
	}
	var revoked bool
	_ = pool.QueryRow(ctx, `SELECT revoked FROM refresh_families WHERE family=$1::uuid`, fam1).Scan(&revoked)
	if !revoked {
		t.Fatal("families revocadas")
	}
	for _, typ := range []string{"password.changed", "session.revoked_all"} {
		_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE aggregate_id=$1::uuid AND event_type=$2`, uid, typ).Scan(&n)
		if n == 0 {
			t.Fatalf("falta outbox %s", typ)
		}
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_queue WHERE to_email=$1 AND subject='Cambiaste tu contraseña'`, email).Scan(&n)
	if n == 0 {
		t.Fatal("falta email changed")
	}
	// Reuso → inválido.
	if err := store.ConsumeTx(ctx, uid, "pr-th-2", newHash, "low", "x", "y", "req-test-2"); err == nil {
		t.Fatal("reuso debe fallar")
	}
	// FK cascade.
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid); err != nil {
		t.Fatal(err)
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM password_reset_tokens WHERE user_id=$1::uuid`, uid).Scan(&n)
	if n != 0 {
		t.Fatal("cascade")
	}
}

func TestPwdResetStore_HintYBurn(t *testing.T) {
	pool := pwdResetTestPool(t)
	defer pool.Close()
	pwdResetSetup(t, pool)
	ctx := context.Background()
	store := pwdResetStore(t, pool)

	// Federated-only ACTIVE → hint (email alternativo, sin link).
	emailF := "prf-" + uuid.NewString() + "@load.test"
	uidF := pwdResetUser(t, pool, emailF, string(user.StatusActive), "")
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uidF)
	if _, eligible, hint, err := store.EligibleForReset(ctx, emailF); err != nil || eligible || !hint {
		t.Fatalf("hint: %v %v %v", eligible, hint, err)
	}
	if err := store.IssueHint(ctx, uidF, emailF); err != nil {
		t.Fatalf("hint: %v", err)
	}
	var subj string
	if err := pool.QueryRow(ctx, `SELECT subject FROM email_queue WHERE to_email=$1 ORDER BY created_at DESC LIMIT 1`, emailF).Scan(&subj); err != nil || subj == "" {
		t.Fatalf("email hint: %v %q", err, subj)
	}
	var th string
	_ = pool.QueryRow(ctx, `SELECT token_hash FROM password_reset_tokens WHERE user_id=$1::uuid LIMIT 1`, uidF).Scan(&th)
	if th != "" {
		t.Fatal("hint sin link reset")
	}

	// Burn al 3º abuso (PG puro, sin caché).
	bare := NewCombinedPasswordResetStore(pool, nil, nil, "http://localhost:3000", nil)
	emailB := "prb-" + uuid.NewString() + "@load.test"
	uidB := pwdResetUser(t, pool, emailB, string(user.StatusActive),
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash")
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uidB)
	_, _ = pool.Exec(ctx, `INSERT INTO password_reset_tokens (token_hash, user_id, expires_at, ctx_ip_hash, ctx_ua_hash)
		VALUES ('burn-th',$1::uuid,now()+INTERVAL '15 minutes','ip','ua')`, uidB)
	for i := 0; i < 2; i++ {
		if burned, _ := bare.IncrementAttempts(ctx, "burn-th"); burned {
			t.Fatalf("quema prematura %d", i)
		}
	}
	if burned, _ := bare.IncrementAttempts(ctx, "burn-th"); !burned {
		t.Fatal("3º debe quemar")
	}
	if _, _, err := bare.FindAlive(ctx, "burn-th"); err == nil {
		t.Fatal("quemado no reutilizable")
	}
}
