package postgres

// Concurrencia CU-AUTH-03 §7: 2 consumes simultáneos mismo código → 1×200/1×401.
// Requiere PG local (docker compose up); si no hay, skip.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"testing"

	"auth-identity-service/internal/domain/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBackupConsumeRace(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://auth:auth@localhost:5432/auth_db?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("sin postgres: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("sin postgres: %v", err)
	}
	var uid string
	sum := sha256.Sum256([]byte("RACERACER1"))
	h := hex.EncodeToString(sum[:])
	ensureRaceState := func() {
		_ = pool.QueryRow(ctx, `INSERT INTO users (id, email_normalized, email_original, status,
			terms_version, privacy_version, terms_accepted_at)
			VALUES (gen_random_uuid(), 'race-backup@load.test', 'race-backup@load.test', 'ACTIVE',
			'v2026.10', 'v2026.10', now())
			ON CONFLICT (email_normalized) DO UPDATE SET email_normalized=EXCLUDED.email_normalized
			RETURNING id::text`).Scan(&uid)
		if uid == "" {
			_ = pool.QueryRow(ctx, `SELECT id::text FROM users WHERE email_normalized='race-backup@load.test'`).Scan(&uid)
		}
		_, _ = pool.Exec(ctx, `DELETE FROM mfa_backup_codes WHERE code_hash=$1`, h)
		_, _ = pool.Exec(ctx, `INSERT INTO mfa_backup_codes (code_hash, user_id) VALUES ($1,$2::uuid)`, h, uid)
	}
	ensureRaceState()

	store := NewBackupCodeStore(pool)
	var wg sync.WaitGroup
	results := make([]error, 2)
	remain := make([]int, 2)
	// Re-asegura justo antes de la carrera (wipes E2E en paralelo barren users).
	ensureRaceState()
	runRace := func() {
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				remain[i], results[i] = store.ConsumeTx(ctx, uid, h, "00000000-0000-0000-0000-000000000001")
			}(i)
		}
		wg.Wait()
	}
	runRace()
	ok, fail := 0, 0
	for _, e := range results {
		if e == nil {
			ok++
		} else if e == auth.ErrBackupUsed || e == auth.ErrBackupNotFound {
			fail++
		} else {
			t.Fatalf("error inesperado: %v", e)
		}
	}
	if ok == 0 && fail == 2 {
		// Barrido total mid-race (usuario/código borrados por setup E2E):
		// re-asegura y corre una vez más.
		ensureRaceState()
		runRace()
		ok, fail = 0, 0
		for _, e := range results {
			if e == nil {
				ok++
			} else if e == auth.ErrBackupUsed || e == auth.ErrBackupNotFound {
				fail++
			} else {
				t.Fatalf("error inesperado: %v", e)
			}
		}
	}
	if ok != 1 || fail != 1 {
		t.Fatalf("carrera debe ser 1×200/1×401: ok=%d fail=%d errs=%v", ok, fail, results)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email_normalized='race-backup@load.test'`)
}
