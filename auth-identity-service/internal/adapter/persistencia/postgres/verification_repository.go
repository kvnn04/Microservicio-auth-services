package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CombinedVerificationStore implementa auth.VerificationStore con
// Redis-como-verdad + Postgres-backup (failover automático).
// Consumo: Postgres-Tx-primero + Redis-DEL-después (write-through con
// reconciliación; si el DEL falla se registra fallback, NO se revierte la Tx).
type CombinedVerificationStore struct {
	pool       *pgxpool.Pool
	cache      *redisadapter.VerificationCache
	frontURL   string
	onFallback func(reason string)
}

func NewCombinedVerificationStore(pool *pgxpool.Pool, cache *redisadapter.VerificationCache, frontURL string, onFallback func(string)) *CombinedVerificationStore {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &CombinedVerificationStore{pool: pool, cache: cache, frontURL: frontURL, onFallback: onFallback}
}

func (s *CombinedVerificationStore) FindAlive(ctx context.Context, hash string) (*auth.VerificationRecord, error) {
	// Fast-path Redis.
	if s.cache != nil {
		rec, hit, err := s.cache.Get(ctx, hash)
		if err != nil {
			s.onFallback("down")
		} else if hit {
			if rec.IsAlive(time.Now().UTC()) {
				return rec, nil
			}
			return nil, auth.ErrInvalidOrExpired
		} else {
			s.onFallback("miss")
		}
	}
	// Read-through Postgres + rehidrata Redis.
	rec, err := s.findAliveSQL(ctx, hash)
	if err != nil {
		return nil, err
	}
	if s.cache != nil {
		_ = s.cache.Put(ctx, rec)
	}
	return rec, nil
}

func (s *CombinedVerificationStore) findAliveSQL(ctx context.Context, hash string) (*auth.VerificationRecord, error) {
	const q = `SELECT user_id, token_hash, COALESCE(otp_hash,''), expires_at, attempts, consumed, superseded
		FROM verification_tokens WHERE token_hash=$1 OR (otp_hash IS NOT NULL AND otp_hash=$1)`
	var rec auth.VerificationRecord
	var uid uuid.UUID
	if err := s.pool.QueryRow(ctx, q, hash).Scan(
		&uid, &rec.TokenHash, &rec.OTPHash, &rec.ExpiresAt, &rec.Attempts, &rec.Consumed, &rec.Superseded,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrInvalidOrExpired
		}
		return nil, fmt.Errorf("select token: %w", err)
	}
	rec.UserID = uid.String()
	if !rec.IsAlive(time.Now().UTC()) {
		return nil, auth.ErrInvalidOrExpired
	}
	return &rec, nil
}

func (s *CombinedVerificationStore) ConsumeAtomically(ctx context.Context, userID, hash, method string) (*auth.ConsumedUser, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, auth.ErrInvalidOrExpired
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	var status, emailNorm string
	if err := tx.QueryRow(ctx, `SELECT status, email_normalized FROM users WHERE id=$1 FOR UPDATE`, uid).Scan(&status, &emailNorm); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrInvalidOrExpired
		}
		return nil, fmt.Errorf("select user: %w", err)
	}
	if status != string(user.StatusPendingVerification) {
		return nil, auth.ErrInvalidOrExpired
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE users SET status='ACTIVE', activated_at=$2, activated_method=$3, updated_at=$2
		WHERE id=$1 AND status='PENDING_VERIFICATION'`, uid, now, method)
	if err != nil || tag.RowsAffected() == 0 {
		return nil, auth.ErrInvalidOrExpired
	}
	tag, err = tx.Exec(ctx, `UPDATE verification_tokens SET consumed=TRUE, consumed_at=$3, activated_by=$2
		WHERE (token_hash=$2 OR (otp_hash IS NOT NULL AND otp_hash=$2)) AND user_id=$1
		AND consumed=FALSE AND superseded=FALSE AND expires_at>$3 AND attempts<3`,
		uid, hash, now)
	if err != nil || tag.RowsAffected() == 0 {
		return nil, auth.ErrInvalidOrExpired // carrera: otro request ganó.
	}
	_, _ = tx.Exec(ctx, `UPDATE verification_tokens SET consumed=TRUE, superseded=TRUE
		WHERE user_id=$1 AND consumed=FALSE AND NOT (token_hash=$2 OR (otp_hash IS NOT NULL AND otp_hash=$2))`,
		uid, hash)

	eh := sha256Hex(emailNorm)
	activatedPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "activated_at": now.Format("2006-01-02T15:04:05Z"),
		"method": method, "request_id": "",
	})
	auditPayload, _ := json.Marshal(map[string]any{
		"action": "user.verify", "user_id": uid.String(),
		"email_hash": "sha256:" + eh, "result": "success", "method": method,
	})
	for _, e := range []struct {
		typ, topic string
		body       []byte
	}{
		{"user.activated", "auth.user.activated.v1", activatedPayload},
		{"audit.user_verify", "auth.audit.v1", auditPayload},
	} {
		if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
			VALUES ($1,$2,$3,$4,$5,'pending')`, uuid.New(), e.typ, uid, e.topic, string(e.body)); err != nil {
			return nil, fmt.Errorf("insert outbox: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	// Invalidación Redis post-commit (best-effort, NO revierte).
	if s.cache != nil {
		s.cache.Invalidate(ctx, &auth.VerificationRecord{UserID: userID, TokenHash: hash, OTPHash: hash})
	}
	at, dot := splitEmail(emailNorm)
	_ = at
	return &auth.ConsumedUser{UserID: userID, EmailHash: eh, EmailDomain: dot, Method: method}, nil
}

func (s *CombinedVerificationStore) Register(ctx context.Context, rec *auth.VerificationRecord) error {
	uid, err := uuid.Parse(rec.UserID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	var emailNorm string
	if err := tx.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1`, uid).Scan(&emailNorm); err != nil {
		return fmt.Errorf("select user: %w", err)
	}
	// Supersede anterior atómicamente (solo 1 activo RN-02).
	_, _ = tx.Exec(ctx, `UPDATE verification_tokens SET consumed=TRUE, superseded=TRUE
		WHERE user_id=$1 AND consumed=FALSE`, uid)

	otpVal := any(rec.OTPHash)
	if rec.OTPHash == "" {
		otpVal = nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO verification_tokens
		(user_id, token_hash, otp_hash, expires_at, attempts, max_attempts, consumed, superseded)
		VALUES ($1,$2,$3,$4,0,$5,FALSE,FALSE)`,
		uid, rec.TokenHash, otpVal, rec.ExpiresAt, auth.VerifyMaxAttempts,
	); err != nil {
		return fmt.Errorf("insert token: %w", err)
	}

	// Outbox: evento dirigido al mailer (único con email plano, canal interno).
	verPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "email": emailNorm,
		"verification_token_hash": "sha256:" + rec.TokenHash,
		"otp_hash":                "sha256:" + rec.OTPHash,
		"expires_at":              rec.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		"is_resend":               true,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'email.verification_requested',$2,'auth.email.verification_requested.v1',$3,'pending')`,
		uuid.New(), uid, string(verPayload)); err != nil {
		return fmt.Errorf("insert outbox: %w", err)
	}

	// Cola de email durable con el secreto plano (link+OTP) para el worker SMTP.
	// El plano NUNCA va a Kafka; email_queue es tabla interna consumida por el worker.
	if rec.TokenPlain != "" {
		link := s.frontURL + "/verify?token=" + rec.TokenPlain
		body := "Verifica tu cuenta (expira en 15 minutos, un solo uso):\n\n" +
			"Enlace: " + link + "\nCodigo: " + rec.OTPPlain + "\n"
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES ($1,$2,'Verifica tu cuenta',$3,'pending')`,
			uuid.New(), emailNorm, body); err != nil {
			return fmt.Errorf("insert email_queue: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	// Dual-write Redis post-commit (best-effort).
	if s.cache != nil {
		if err := s.cache.Put(ctx, rec); err != nil {
			s.onFallback("down")
		}
		s.cache.NoteSent(ctx, rec.UserID)
	}
	return nil
}

func (s *CombinedVerificationStore) IncrementAttempts(ctx context.Context, hash string) (int, bool, error) {
	if s.cache != nil {
		n, err := s.cache.IncrAttempts(ctx, hash)
		if err == nil {
			if n >= auth.VerifyMaxAttempts {
				_, _ = s.pool.Exec(ctx, `UPDATE verification_tokens SET consumed=TRUE, burned_reason='max_attempts'
					WHERE (token_hash=$1 OR (otp_hash IS NOT NULL AND otp_hash=$1)) AND consumed=FALSE`, hash)
				return 0, true, nil
			}
			return auth.VerifyMaxAttempts - n, false, nil
		}
		s.onFallback("down")
	}
	var attempts int
	if err := s.pool.QueryRow(ctx, `UPDATE verification_tokens SET attempts=attempts+1
		WHERE (token_hash=$1 OR (otp_hash IS NOT NULL AND otp_hash=$1)) AND consumed=FALSE
		RETURNING attempts`, hash).Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, auth.ErrInvalidOrExpired
		}
		return 0, false, fmt.Errorf("increment: %w", err)
	}
	if attempts >= auth.VerifyMaxAttempts {
		_, _ = s.pool.Exec(ctx, `UPDATE verification_tokens SET consumed=TRUE, burned_reason='max_attempts'
			WHERE token_hash=$1 OR (otp_hash IS NOT NULL AND otp_hash=$1)`, hash)
		return 0, true, nil
	}
	return auth.VerifyMaxAttempts - attempts, false, nil
}

func (s *CombinedVerificationStore) ResendQuotaCheck(ctx context.Context, userID string) (bool, time.Duration, error) {
	if s.cache == nil {
		return true, 0, nil
	}
	allowed, retry, err := s.cache.QuotaCheck(ctx, userID)
	if err != nil {
		s.onFallback("down")
		return true, 0, nil // fail-open: no bloquea reenvío sin Redis.
	}
	return allowed, retry, nil
}

func (s *CombinedVerificationStore) WasActivatedBy(ctx context.Context, hash string) (string, bool, error) {
	var uid uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT user_id FROM verification_tokens
		WHERE (token_hash=$1 OR (otp_hash IS NOT NULL AND otp_hash=$1))
		AND consumed=TRUE AND activated_by=$1`, hash).Scan(&uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("select activated_by: %w", err)
	}
	return uid.String(), true, nil
}

// Reconcile limpia claves Redis huérfanas de tokens ya consumidos (worker cada 10s).
func (s *CombinedVerificationStore) Reconcile(ctx context.Context) {
	if s.cache == nil {
		return
	}
	rows, err := s.pool.Query(ctx, `SELECT user_id, token_hash, COALESCE(otp_hash,'') FROM verification_tokens
		WHERE consumed=TRUE AND consumed_at > now() - INTERVAL '1 hour' LIMIT 200`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var uid uuid.UUID
		var th, oh string
		if err := rows.Scan(&uid, &th, &oh); err != nil {
			continue
		}
		s.cache.Invalidate(ctx, &auth.VerificationRecord{UserID: uid.String(), TokenHash: th, OTPHash: oh})
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func splitEmail(email string) (local, domain string) {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			return email[:i], email[i+1:]
		}
	}
	return "", ""
}
