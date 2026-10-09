package postgres

// Integración fix email inicial (F-17 CU-REG-01): CreateWithOutbox encola
// email_queue link+OTP en la MISMA Tx (fail-closed) + guarda otp_hash.
// Skip sin PG local (patrón de los integration tests del paquete).

import (
	"context"
	"os"
	"testing"
	"time"

	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func mailTestPool(t *testing.T) *pgxpool.Pool {
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

func mailTestUser(tag string) (*user.User, string) {
	uid := uuid.NewString()
	email := "mailfix-" + tag + "-" + uid + "@test.local"
	u := &user.User{
		ID: uid, EmailNormalized: email, EmailOriginal: email,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash",
		PasswordAlgo: "argon2id", Status: user.StatusPendingVerification,
		TermsVersion: "v2026.10", PrivacyVersion: "v2026.10",
		TermsAcceptedAt: time.Now().UTC(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	return u, email
}

func TestCreateWithOutbox_EnqueuesInitialEmail(t *testing.T) {
	pool := mailTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := NewUserRepository(pool, "http://localhost:3000")

	u, email := mailTestUser("a")
	defer cleanupMailUser(ctx, pool, u.ID, email)
	mail := &user.VerificationMail{
		TokenPlain: "tokplain-43ch-base64url-aaaaaaaaaaaaaa",
		TokenHash:  "tokhash-aaa", OTPPlain: "12345678", OTPHash: "otphash-aaa",
	}
	events := []user.OutboxPayload{{
		EventID: uuid.NewString(), EventType: "user.registered",
		AggregateID: u.ID, Topic: "auth.user.registered.v1", PayloadJSON: []byte(`{}`),
	}}
	if err := repo.CreateWithOutbox(ctx, u, events, "tokhash-aaa", uuid.NewString(), mail); err != nil {
		t.Fatalf("create: %v", err)
	}
	var otpHash, body, subject, status string
	if err := pool.QueryRow(ctx, `SELECT otp_hash FROM verification_tokens WHERE user_id=$1::uuid`,
		u.ID).Scan(&otpHash); err != nil || otpHash != "otphash-aaa" {
		t.Fatalf("otp_hash persistido: %q %v", otpHash, err)
	}
	if err := pool.QueryRow(ctx, `SELECT subject, body_text, status FROM email_queue WHERE to_email=$1
		ORDER BY created_at DESC LIMIT 1`, email).Scan(&subject, &body, &status); err != nil {
		t.Fatalf("email encolado: %v", err)
	}
	if subject != "Verifica tu cuenta" || status != "pending" {
		t.Fatalf("email: %q %q", subject, status)
	}
	for _, want := range []string{"tokplain-43ch-base64url-aaaaaaaaaaaaaa", "12345678", "/verify?token="} {
		if !containsStr(body, want) {
			t.Fatalf("body sin %q: %s", want, body)
		}
	}
}

func TestCreateWithOutbox_NilMailNoEmail(t *testing.T) {
	pool := mailTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := NewUserRepository(pool, "http://localhost:3000")

	u, email := mailTestUser("b")
	defer cleanupMailUser(ctx, pool, u.ID, email)
	events := []user.OutboxPayload{{
		EventID: uuid.NewString(), EventType: "user.registered",
		AggregateID: u.ID, Topic: "auth.user.registered.v1", PayloadJSON: []byte(`{}`),
	}}
	if err := repo.CreateWithOutbox(ctx, u, events, "tokhash-bbb", uuid.NewString(), nil); err != nil {
		t.Fatalf("create sin mail: %v", err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_queue WHERE to_email=$1`, email).Scan(&n)
	if n != 0 {
		t.Fatal("nil mail no encola")
	}
}

func cleanupMailUser(ctx context.Context, pool *pgxpool.Pool, uid, email string) {
	_, _ = pool.Exec(ctx, `DELETE FROM outbox WHERE aggregate_id=$1::uuid`, uid)
	_, _ = pool.Exec(ctx, `DELETE FROM email_queue WHERE to_email=$1`, email)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, uid)
}

func containsStr(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
