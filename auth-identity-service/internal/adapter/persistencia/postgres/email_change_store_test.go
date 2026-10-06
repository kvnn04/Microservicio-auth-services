package postgres

// Integración CU-CRED-03 T-08/T-12: request (doble-mail + outbox) + confirm
// con corte global (valid_after + 0 sesiones) + race de unicidad 1×200/1×409.
// Requiere PG/Redis locales (docker compose up); si no hay, skip.

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"auth-identity-service/internal/domain/user"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func emailChangeTestPool(t *testing.T) *pgxpool.Pool {
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

func emailChangeSetup(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS email_change_tokens (
	  token_hash TEXT PRIMARY KEY,
	  requester UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  new_normalized CITEXT NOT NULL, new_original TEXT NOT NULL,
	  expires_at TIMESTAMPTZ NOT NULL, attempts INT NOT NULL DEFAULT 0,
	  consumed BOOLEAN NOT NULL DEFAULT FALSE, superseded BOOLEAN NOT NULL DEFAULT FALSE,
	  created_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	_, _ = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_emailchange_req_active
	  ON email_change_tokens(requester) WHERE consumed = FALSE`)
	_, _ = pool.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z'`)
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sessions (
	  sid UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  family UUID NOT NULL, jti_actual UUID NOT NULL, device_hash TEXT NOT NULL, ip_hash TEXT NOT NULL,
	  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
	  expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '90 days')`)
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS refresh_families (
	  family UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  current_hash TEXT NOT NULL UNIQUE, parent_hash TEXT NOT NULL DEFAULT '',
	  counter INT NOT NULL DEFAULT 0, absolute_exp TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)`)
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS email_queue (
	  id UUID PRIMARY KEY, to_email TEXT NOT NULL, subject TEXT NOT NULL, body_text TEXT NOT NULL,
	  status TEXT NOT NULL DEFAULT 'pending', attempts INT NOT NULL DEFAULT 0,
	  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), sent_at TIMESTAMPTZ)`)
}

func emailChangeStore(t *testing.T, pool *pgxpool.Pool) *CombinedEmailChangeStore {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return NewCombinedEmailChangeStore(pool,
		redisadapter.NewEmailChangeCache(rdb), redisadapter.NewSessionCache(rdb),
		"http://localhost:3000", nil)
}

func emailChangeUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.NewString()
	_, err := pool.Exec(ctx, `INSERT INTO users
		(id, email_normalized, email_original, status,
		 terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, 'ACTIVE','v2026.10','v2026.10', now())
		ON CONFLICT (email_normalized) DO NOTHING`, uid, email)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	var id string
	_ = pool.QueryRow(ctx, `SELECT id::text FROM users WHERE email_normalized=$1::citext`, email).Scan(&id)
	return id
}

func emailChangeEnsure(t *testing.T, pool *pgxpool.Pool, uid, email string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `INSERT INTO users
		(id, email_normalized, email_original, status,
		 terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, 'ACTIVE','v2026.10','v2026.10', now())
		ON CONFLICT (email_normalized) DO NOTHING`, uid, email)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
}

func TestEmailChangeStore_RequestConfirmCorte(t *testing.T) {
	pool := emailChangeTestPool(t)
	defer pool.Close()
	emailChangeSetup(t, pool)
	ctx := context.Background()
	oldEmail := "ec-old-" + uuid.NewString() + "@load.test"
	uid := emailChangeUser(t, pool, oldEmail)
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
	store := emailChangeStore(t, pool)

	// 2 sesiones vivas (A actual, B par).
	sidA, famA := uuid.NewString(), uuid.NewString()
	for _, s := range [][2]string{{sidA, famA}, {uuid.NewString(), uuid.NewString()}} {
		_, _ = pool.Exec(ctx, `INSERT INTO sessions (sid, user_id, family, jti_actual, device_hash, ip_hash)
			VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip')`,
			s[0], uid, s[1], uuid.NewString())
		_, _ = pool.Exec(ctx, `INSERT INTO refresh_families (family, user_id, current_hash, absolute_exp)
			VALUES ($1::uuid,$2::uuid,$3,now()+INTERVAL '90 days')
			ON CONFLICT (family) DO NOTHING`, s[1], uid, "h-"+s[1])
	}

	// Libre → request + doble-mail + outbox.
	newNorm := "ec-new-" + uuid.NewString() + "@load.test"
	rec := &user.EmailChangeRecord{
		RequesterID: uid, TokenHash: "ec-th-1", NewNormalized: newNorm, NewOriginal: newNorm,
		ExpiresAt: time.Now().UTC().Add(user.EmailChangeTTL), TokenPlain: "plain-43ch-token",
	}
	if taken, err := store.Taken(ctx, newNorm, uid); err != nil || taken {
		t.Fatalf("taken: %v %v", taken, err)
	}
	if err := store.Issue(ctx, rec); err != nil {
		t.Fatalf("issue: %v", err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_queue WHERE to_email=$1`, newNorm).Scan(&n)
	if n == 0 {
		t.Fatal("falta mail al nuevo (link)")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_queue WHERE to_email=$1 AND subject LIKE 'Aviso:%'`, oldEmail).Scan(&n)
	if n == 0 {
		t.Fatal("falta aviso al viejo (sin token)")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE aggregate_id=$1::uuid AND event_type='email.change_requested'`, uid).Scan(&n)
	if n == 0 {
		t.Fatal("falta outbox requested")
	}

	// Confirm sin Bearer → 200 + corte global + relogin.
	// Re-asegura estado ante wipes E2E (usuario + token + sesiones).
	emailChangeEnsure(t, pool, uid, oldEmail)
	var tokExists bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM email_change_tokens WHERE token_hash='ec-th-1')`).Scan(&tokExists)
	if !tokExists {
		if err := store.Issue(ctx, rec); err != nil {
			t.Fatalf("re-issue: %v", err)
		}
	}
	var sessN int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid).Scan(&sessN)
	if sessN == 0 {
		for _, s := range [][2]string{{uuid.NewString(), uuid.NewString()}, {uuid.NewString(), uuid.NewString()}} {
			_, _ = pool.Exec(ctx, `INSERT INTO sessions (sid, user_id, family, jti_actual, device_hash, ip_hash)
				VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip')`,
				s[0], uid, s[1], uuid.NewString())
			_, _ = pool.Exec(ctx, `INSERT INTO refresh_families (family, user_id, current_hash, absolute_exp)
				VALUES ($1::uuid,$2::uuid,$3,now()+INTERVAL '90 days')
				ON CONFLICT (family) DO NOTHING`, s[1], uid, "h-"+s[1])
		}
	}
	reqID, gotNorm, err := store.ConfirmTx(ctx, "ec-th-1")
	if err != nil || reqID != uid || gotNorm != newNorm {
		t.Fatalf("confirm: %v %q %q", err, reqID, gotNorm)
	}
	var cur, va string
	_ = pool.QueryRow(ctx, `SELECT email_normalized, tokens_valid_after::text FROM users WHERE id=$1::uuid`, uid).Scan(&cur, &va)
	if cur != newNorm || va == "" || va == "1970-01-01T00:00:00Z" {
		t.Fatalf("email+valid_after: %q %q", cur, va)
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid).Scan(&n)
	if n != 0 {
		t.Fatalf("0 sesiones (incluida actual): %d", n)
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM refresh_families WHERE user_id=$1::uuid AND NOT revoked`, uid).Scan(&n)
	if n != 0 {
		t.Fatal("families revocadas")
	}
	for _, typ := range []string{"email.changed", "session.revoked_all"} {
		_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE aggregate_id=$1::uuid AND event_type=$2`, uid, typ).Scan(&n)
		if n == 0 {
			t.Fatalf("falta outbox %s", typ)
		}
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_queue WHERE to_email=$1 AND subject='Tu correo cambió'`, newNorm).Scan(&n)
	if n == 0 {
		t.Fatal("falta mail changed al nuevo")
	}
	// Reuso → inválido.
	if _, _, err := store.ConfirmTx(ctx, "ec-th-1"); err == nil {
		t.Fatal("reuso debe fallar")
	}
}

func TestEmailChangeStore_RaceTakenQuema(t *testing.T) {
	pool := emailChangeTestPool(t)
	defer pool.Close()
	emailChangeSetup(t, pool)
	ctx := context.Background()
	emailA := "ec-a-" + uuid.NewString() + "@load.test"
	uidA := emailChangeUser(t, pool, emailA)
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uidA)
	store := emailChangeStore(t, pool)

	// A pide cambio a nuevo@ (libre); B lo registra antes de confirmar A.
	target := "ec-target-" + uuid.NewString() + "@load.test"
	rec := &user.EmailChangeRecord{
		RequesterID: uidA, TokenHash: "ec-race-th", NewNormalized: target, NewOriginal: target,
		ExpiresAt: time.Now().UTC().Add(user.EmailChangeTTL),
	}
	if err := store.Issue(ctx, rec); err != nil {
		// Wipe E2E entre user e Issue: re-asegura MISMO uid y reintenta.
		emailChangeEnsure(t, pool, uidA, emailA)
		if err := store.Issue(ctx, rec); err != nil {
			t.Fatalf("issue: %v", err)
		}
	}
	otherUID := uuid.NewString()
	_, _ = pool.Exec(ctx, `INSERT INTO users (id, email_normalized, email_original, status,
		terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, 'ACTIVE','v2026.10','v2026.10', now())
		ON CONFLICT DO NOTHING`, otherUID, target)
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, otherUID)

	// Race: dos confirms concurrentes del mismo token → 1×taken + 1×invalid.
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = store.ConfirmTx(ctx, "ec-race-th")
		}(i)
	}
	wg.Wait()
	taken, invalid := 0, 0
	for _, err := range errs {
		if err == nil {
			t.Fatal("race no debe confirmar dos veces")
		} else if err == user.ErrEmailAlreadyInUse {
			taken++
		} else {
			invalid++
		}
	}
	if taken != 1 || invalid != 1 {
		t.Fatalf("1×taken + 1×invalid: taken=%d invalid=%d errs=%v", taken, invalid, errs)
	}
	// Token quemado: tercer intento → inválido (no taken).
	if _, _, err := store.ConfirmTx(ctx, "ec-race-th"); err == nil {
		t.Fatal("quemado debe fallar")
	}
}
