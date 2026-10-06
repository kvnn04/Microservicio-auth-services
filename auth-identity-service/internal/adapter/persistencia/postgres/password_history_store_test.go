package postgres

// Integración CU-CRED-02 T-08/T-12: Current/LastN + RotateTx (history+ver,
// revoke pares, outbox, email) + TOCTOU concurrente 1×200/1×REUSED.
// Requiere PG/Redis locales (docker compose up); si no hay, skip.

import (
	"context"
	"os"
	"sync"
	"testing"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/adapter/security"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func pwdHistTestPool(t *testing.T) *pgxpool.Pool {
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

func pwdHistSetup(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS password_history (
	  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	  hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	_, _ = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_pwdhist_user_created
	  ON password_history(user_id, created_at DESC)`)
	_, _ = pool.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_ver INT NOT NULL DEFAULT 1`)
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

func pwdHistStore(t *testing.T, pool *pgxpool.Pool) *CombinedPasswordHistoryStore {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return NewCombinedPasswordHistoryStore(pool, redisadapter.NewSessionCache(rdb), "http://localhost:3000", nil)
}

func pwdHistUser(t *testing.T, pool *pgxpool.Pool, email, hash string) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.NewString()
	var pwHash any
	if hash != "" {
		pwHash = hash
	}
	_, err := pool.Exec(ctx, `INSERT INTO users
		(id, email_normalized, email_original, password_hash, password_algo, status,
		 terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, $3, 'argon2id', 'ACTIVE','v2026.10','v2026.10', now())
		ON CONFLICT (email_normalized) DO NOTHING`, uid, email, pwHash)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	var id string
	_ = pool.QueryRow(ctx, `SELECT id::text FROM users WHERE email_normalized=$1::citext`, email).Scan(&id)
	return id
}

// pwdHistEnsure re-crea el MISMO uid tras wipes E2E en paralelo.
func pwdHistEnsure(pool *pgxpool.Pool, uid, email, hash string) {
	var pwHash any
	if hash != "" {
		pwHash = hash
	}
	_, _ = pool.Exec(context.Background(), `INSERT INTO users
		(id, email_normalized, email_original, password_hash, password_algo, status,
		 terms_version, privacy_version, terms_accepted_at)
		VALUES ($1::uuid, $2::citext, $2::text, $3, 'argon2id', 'ACTIVE','v2026.10','v2026.10', now())
		ON CONFLICT (email_normalized) DO NOTHING`, uid, email, pwHash)
}

func pwdHistSession(t *testing.T, pool *pgxpool.Pool, uid, email, oldHash string) (sid, fam string) {
	t.Helper()
	ctx := context.Background()
	sid, fam = uuid.NewString(), uuid.NewString()
	_, err := pool.Exec(ctx, `INSERT INTO sessions
		(sid, user_id, family, jti_actual, device_hash, ip_hash)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip')`,
		sid, uid, fam, uuid.NewString())
	if err != nil && isFKViolation(err) {
		// Wipe E2E entre user y sessions: re-asegura MISMO uid y reintenta.
		pwdHistEnsure(pool, uid, email, oldHash)
		_, err = pool.Exec(ctx, `INSERT INTO sessions
			(sid, user_id, family, jti_actual, device_hash, ip_hash)
			VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'d','ip')`,
			sid, uid, fam, uuid.NewString())
	}
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	_, _ = pool.Exec(context.Background(), `INSERT INTO refresh_families
		(family, user_id, current_hash, absolute_exp)
		VALUES ($1::uuid,$2::uuid,$3,now()+INTERVAL '90 days')
		ON CONFLICT (family) DO NOTHING`, fam, uid, "h-"+fam)
	return sid, fam
}

func TestPwdHistStore_RotateRevocaPares(t *testing.T) {
	pool := pwdHistTestPool(t)
	defer pool.Close()
	pwdHistSetup(t, pool)
	ctx := context.Background()
	hasher := security.NewArgon2Hasher(nil)
	oldHash, _ := hasher.Hash(ctx, "Str0ng!Passw0rd-2026")
	email := "ph-" + uuid.NewString() + "@load.test"
	uid := pwdHistUser(t, pool, email, oldHash)
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
	store := pwdHistStore(t, pool)

	acct, err := store.Current(ctx, uid)
	if err != nil || acct.Hash == "" || acct.Ver != 1 || acct.Status != user.StatusActive {
		t.Fatalf("current: %+v %v", acct, err)
	}
	// 3 sesiones (A actual, B, C) + historial con 2 previas.
	sidA, _ := pwdHistSession(t, pool, uid, email, oldHash)
	pwdHistSession(t, pool, uid, email, oldHash)
	pwdHistSession(t, pool, uid, email, oldHash)
	for _, h := range []string{"h-previa-1", "h-previa-2"} {
		_, _ = pool.Exec(ctx, `INSERT INTO password_history (user_id, hash) VALUES ($1::uuid,$2)`, uid, h)
	}
	hist, err := store.LastN(ctx, uid, auth.PasswordHistoryN)
	if err != nil || len(hist) != 2 {
		t.Fatalf("lastN: %v %v", hist, err)
	}

	newHash, _ := hasher.Hash(ctx, "Nu3va!Valida-2026")
	newVer, peers, err := store.RotateTx(ctx, uid, oldHash, newHash, acct.Ver, sidA, "req-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newVer != 2 || peers != 2 {
		t.Fatalf("ver=%d peers=%d", newVer, peers)
	}
	var gotHash string
	var gotVer int
	_ = pool.QueryRow(ctx, `SELECT password_hash, COALESCE(password_ver,1) FROM users WHERE id=$1::uuid`, uid).Scan(&gotHash, &gotVer)
	if gotHash != newHash || gotVer != 2 {
		t.Fatal("hash rotado + ver+1")
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM password_history WHERE user_id=$1::uuid`, uid).Scan(&n)
	if n != 3 {
		t.Fatalf("history+1: %d", n)
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1::uuid`, uid).Scan(&n)
	if n != 1 {
		t.Fatalf("solo actual vive: %d", n)
	}
	_ = pool.QueryRow(ctx, `SELECT sid::text FROM sessions WHERE user_id=$1::uuid`, uid).Scan(&gotHash)
	if gotHash != sidA {
		t.Fatal("sobrevive la actual")
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM refresh_families WHERE user_id=$1::uuid AND revoked`, uid).Scan(&n)
	if n != 2 {
		t.Fatalf("pares revocadas: %d", n)
	}
	var va string
	_ = pool.QueryRow(ctx, `SELECT tokens_valid_after::text FROM users WHERE id=$1::uuid`, uid).Scan(&va)
	if va == "1970-01-01T00:00:00Z" || va == "" {
		t.Fatal("valid_after intacto (sin corte global aquí)")
	}
	for _, typ := range []string{"password.changed", "session.revoked_peers"} {
		_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM outbox WHERE aggregate_id=$1::uuid AND event_type=$2`, uid, typ).Scan(&n)
		if n == 0 {
			t.Fatalf("falta outbox %s", typ)
		}
	}
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_queue WHERE to_email=$1 AND subject='Cambiaste tu contraseña'`, email).Scan(&n)
	if n == 0 {
		t.Fatal("falta email changed")
	}
	// Reuso misma base → REUSED (base movida).
	if _, _, err := store.RotateTx(ctx, uid, oldHash, newHash, 1, sidA, "req-2"); err == nil {
		t.Fatal("base vieja debe fallar")
	}
	// Sin Redis (down equivalente): PG verdad, 200 con corte en PG.
	bareNoRedis := NewCombinedPasswordHistoryStore(pool, nil, "http://localhost:3000", nil)
	emailNR := "ph-nr-" + uuid.NewString() + "@load.test"
	uidNR := pwdHistUser(t, pool, emailNR, oldHash)
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uidNR)
	sidNR, _ := pwdHistSession(t, pool, uidNR, emailNR, oldHash)
	newHashNR, _ := hasher.Hash(ctx, "0tra!Valida-2026")
	newVerNR, peersNR, err := bareNoRedis.RotateTx(ctx, uidNR, oldHash, newHashNR, 1, sidNR, "req-nr")
	if err != nil || newVerNR != 2 || peersNR != 0 {
		t.Fatalf("sin redis: %v ver=%d peers=%d", err, newVerNR, peersNR)
	}
}

func TestPwdHistStore_ToctouConcurrente(t *testing.T) {
	pool := pwdHistTestPool(t)
	defer pool.Close()
	pwdHistSetup(t, pool)
	ctx := context.Background()
	hasher := security.NewArgon2Hasher(nil)
	oldHash, _ := hasher.Hash(ctx, "Str0ng!Passw0rd-2026")
	email := "pht-" + uuid.NewString() + "@load.test"
	uid := pwdHistUser(t, pool, email, oldHash)
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
	store := pwdHistStore(t, pool)
	sidA, _ := pwdHistSession(t, pool, uid, email, oldHash)

	// Re-asegura justo antes de la carrera (wipes E2E en paralelo).
	uid = pwdHistUser(t, pool, email, oldHash)
	sidA, _ = pwdHistSession(t, pool, uid, email, oldHash)

	// Dos rotaciones concurrentes sobre la misma base/ver → 1×200 + 1×REUSED.
	newA, _ := hasher.Hash(ctx, "Nu3va!Valida-2026A")
	newB, _ := hasher.Hash(ctx, "Nu3va!Valida-2026B")
	type res struct{ ver, peers int }
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, nh := range []string{newA, newB} {
		wg.Add(1)
		go func(i int, nh string) {
			defer wg.Done()
			_, _, errs[i] = store.RotateTx(ctx, uid, oldHash, nh, 1, sidA, "req-tct")
		}(i, nh)
	}
	wg.Wait()
	ok, reused := 0, 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else if err == auth.ErrPasswordReused {
			reused++
		} else {
			t.Fatalf("error inesperado: %v", err)
		}
	}
	if ok != 1 || reused != 1 {
		t.Fatalf("1×200 + 1×REUSED: ok=%d reused=%d errs=%v", ok, reused, errs)
	}
}
