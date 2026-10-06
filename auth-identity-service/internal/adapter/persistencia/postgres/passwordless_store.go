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

// CombinedPasswordlessStore implementa auth.PasswordlessStore con
// Redis-como-verdad + Postgres-backup (igual CU-REG-02).
// Consumo: Postgres-Tx-primero + Redis-DEL-después (si el DEL falla se
// cuenta fallback, NO se revierte la Tx).
type CombinedPasswordlessStore struct {
	pool       *pgxpool.Pool
	cache      *redisadapter.PasswordlessCache
	frontURL   string
	onFallback func(reason string)
}

func NewCombinedPasswordlessStore(pool *pgxpool.Pool, cache *redisadapter.PasswordlessCache, frontURL string, onFallback func(string)) *CombinedPasswordlessStore {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &CombinedPasswordlessStore{pool: pool, cache: cache, frontURL: frontURL, onFallback: onFallback}
}

// Eligible resuelve ACTIVE (+mfa) sin revelar nada al cliente.
// Inexistente/no-ACTIVE → eligible=false.
func (s *CombinedPasswordlessStore) Eligible(ctx context.Context, normalizedEmail string) (string, bool, bool, error) {
	var uid uuid.UUID
	var status string
	var mfa bool
	err := s.pool.QueryRow(ctx, `SELECT id, status, COALESCE(mfa_enabled, FALSE)
		FROM users WHERE email_normalized = $1`, normalizedEmail).Scan(&uid, &status, &mfa)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, false, nil
		}
		return "", false, false, fmt.Errorf("select user %v: %w", err, auth.ErrSessionInfra)
	}
	if status != string(user.StatusActive) {
		return uid.String(), mfa, false, nil
	}
	return uid.String(), mfa, true, nil
}

// QuotaCheck delega a Redis; caído → fail-open (igual verify).
func (s *CombinedPasswordlessStore) QuotaCheck(ctx context.Context, key string) (bool, time.Duration, error) {
	if s.cache == nil {
		return true, 0, nil
	}
	allowed, retry, err := s.cache.QuotaCheck(ctx, key)
	if err != nil {
		s.onFallback("down")
		return true, 0, nil
	}
	return allowed, retry, nil
}

// Issue dual-write + supersede previo + outbox requested + email_queue.
func (s *CombinedPasswordlessStore) Issue(ctx context.Context, rec *auth.PasswordlessRecord) error {
	uid, err := uuid.Parse(rec.UserID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", auth.ErrPlessInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	var emailNorm string
	if err := tx.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1`, uid).Scan(&emailNorm); err != nil {
		return fmt.Errorf("select user %v: %w", err, auth.ErrSessionInfra)
	}
	// Supersede anterior atómicamente (solo 1 activo RN-01).
	_, _ = tx.Exec(ctx, `UPDATE passwordless_tokens SET consumed=TRUE, superseded=TRUE
		WHERE user_id=$1 AND consumed=FALSE`, uid)

	if _, err := tx.Exec(ctx, `INSERT INTO passwordless_tokens
		(token_hash, otp_hash, user_id, expires_at, attempts, consumed, superseded, ctx_ip_hash, ctx_ua_hash)
		VALUES ($1,$2,$3,$4,0,FALSE,FALSE,$5,$6)`,
		rec.TokenHash, rec.OTPHash, uid, rec.ExpiresAt, rec.Ctx.IPHash24, rec.Ctx.UAHash,
	); err != nil {
		return fmt.Errorf("insert token %v: %w", err, auth.ErrSessionInfra)
	}

	eh := plessSHA256(emailNorm)
	reqPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "email_hash": "sha256:" + eh,
		"expires_at": rec.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'passwordless.requested',$2,'auth.passwordless.v1',$3,'pending')`,
		uuid.New(), uid, string(reqPayload)); err != nil {
		return fmt.Errorf("insert outbox %v: %w", err, auth.ErrSessionInfra)
	}

	// Cola de email durable con el secreto plano (link+OTP) para el worker SMTP.
	// El plano NUNCA va a Kafka; email_queue es tabla interna.
	if rec.TokenPlain != "" {
		link := s.frontURL + "/passwordless?token=" + rec.TokenPlain
		body := "Hola,\n\nUsa este enlace o código para iniciar sesión " +
			"(expira en 10 minutos, un solo uso):\n\n" +
			"Enlace: " + link + "\nCódigo: " + rec.OTPPlain + "\n\n" +
			"Si el botón no funciona, copia el código en la pantalla de acceso.\n" +
			"Si no fuiste tú, ignora este mensaje.\n"
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES ($1,$2,'Inicia sesión sin contraseña',$3,'pending')`,
			uuid.New(), emailNorm, body); err != nil {
			return fmt.Errorf("insert email_queue %v: %w", err, auth.ErrSessionInfra)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
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

// FindAlive Redis→fallback PG read-through + rehidrata.
func (s *CombinedPasswordlessStore) FindAlive(ctx context.Context, hash string) (*auth.PasswordlessRecord, error) {
	if s.cache != nil {
		rec, hit, err := s.cache.Get(ctx, hash)
		if err != nil {
			s.onFallback("down")
		} else if hit {
			if rec.Alive(time.Now().UTC()) {
				return rec, nil
			}
			return nil, auth.ErrPlessInvalid
		} else {
			s.onFallback("miss")
		}
	}
	rec, err := s.findAliveSQL(ctx, hash)
	if err != nil {
		return nil, err
	}
	if s.cache != nil {
		_ = s.cache.Put(ctx, rec)
	}
	return rec, nil
}

func (s *CombinedPasswordlessStore) findAliveSQL(ctx context.Context, hash string) (*auth.PasswordlessRecord, error) {
	const q = `SELECT user_id, token_hash, otp_hash, expires_at, attempts, consumed, superseded, ctx_ip_hash, ctx_ua_hash
		FROM passwordless_tokens WHERE token_hash=$1 OR otp_hash=$1`
	var rec auth.PasswordlessRecord
	var uid uuid.UUID
	if err := s.pool.QueryRow(ctx, q, hash).Scan(
		&uid, &rec.TokenHash, &rec.OTPHash, &rec.ExpiresAt, &rec.Attempts,
		&rec.Consumed, &rec.Superseded, &rec.Ctx.IPHash24, &rec.Ctx.UAHash,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrPlessInvalid
		}
		return nil, fmt.Errorf("select token %v: %w", err, auth.ErrSessionInfra)
	}
	rec.UserID = uid.String()
	if !rec.Alive(time.Now().UTC()) {
		return nil, auth.ErrPlessInvalid
	}
	return &rec, nil
}

// ConsumeTx quema un solo uso en Tx atómica. risk=high → outbox mismatch + email alerta.
func (s *CombinedPasswordlessStore) ConsumeTx(ctx context.Context, userID, hash, method, risk, curIPHash, curUAHash string) (*auth.PlessConsumeResult, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, auth.ErrPlessInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	var status string
	var mfa bool
	var emailNorm string
	if err := tx.QueryRow(ctx, `SELECT status, COALESCE(mfa_enabled,FALSE), email_normalized
		FROM users WHERE id=$1 FOR UPDATE`, uid).Scan(&status, &mfa, &emailNorm); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrPlessInvalid
		}
		return nil, fmt.Errorf("select user %v: %w", err, auth.ErrSessionInfra)
	}
	if status != string(user.StatusActive) {
		return nil, auth.ErrPlessInvalid // cuenta ya no-ACTIVE al consumir.
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE passwordless_tokens SET consumed=TRUE
		WHERE (token_hash=$2 OR otp_hash=$2) AND user_id=$1
		AND consumed=FALSE AND superseded=FALSE AND expires_at>$3 AND attempts<$4`,
		uid, hash, now, auth.PlessMaxAttempts)
	if err != nil || tag.RowsAffected() == 0 {
		return nil, auth.ErrPlessInvalid // carrera: otro request ganó.
	}
	_, _ = tx.Exec(ctx, `UPDATE passwordless_tokens SET consumed=TRUE, superseded=TRUE
		WHERE user_id=$1 AND consumed=FALSE AND NOT (token_hash=$2 OR otp_hash=$2)`,
		uid, hash)
	_, _ = tx.Exec(ctx, `UPDATE users SET last_login=$2 WHERE id=$1`, uid, now)

	conPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "risk": risk, "method": method,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'passwordless.consumed',$2,'auth.passwordless.v1',$3,'pending')`,
		uuid.New(), uid, string(conPayload)); err != nil {
		return nil, fmt.Errorf("insert outbox %v: %w", err, auth.ErrSessionInfra)
	}
	if risk == "high" {
		mmPayload, _ := json.Marshal(map[string]any{
			"user_id": uid.String(), "ip_hash": "sha256:" + curIPHash,
			"ua_hash": "sha256:" + curUAHash, "risk": "high",
		})
		if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
			VALUES ($1,'security.context_mismatch',$2,'auth.security.context_mismatch.v1',$3,'pending')`,
			uuid.New(), uid, string(mmPayload)); err != nil {
			return nil, fmt.Errorf("insert mismatch outbox %v: %w", err, auth.ErrSessionInfra)
		}
		alertBody := "Hola,\n\nSe inició sesión sin contraseña en tu cuenta el " +
			now.Format("2006-01-02 15:04 UTC") +
			" desde una red o dispositivo distinto al que solicitó el enlace.\n" +
			"Si no fuiste tú, cambia tu contraseña y revisa tus sesiones.\n"
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES ($1,$2,'Nuevo acceso sin contraseña',$3,'pending')`,
			uuid.New(), emailNorm, alertBody); err != nil {
			return nil, fmt.Errorf("insert alert email %v: %w", err, auth.ErrSessionInfra)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}

	// Invalidación Redis post-commit (best-effort, NO revierte).
	if s.cache != nil {
		s.cache.Invalidate(ctx, &auth.PasswordlessRecord{UserID: userID, TokenHash: hash, OTPHash: hash})
	}
	return &auth.PlessConsumeResult{UserID: userID, MFAEnabled: mfa}, nil
}

// IncrementAttempts suma un fallo; al 3º quema (consumed=TRUE).
func (s *CombinedPasswordlessStore) IncrementAttempts(ctx context.Context, hash string) (bool, error) {
	if s.cache != nil {
		n, err := s.cache.IncrAttempts(ctx, hash)
		if err == nil {
			if n >= auth.PlessMaxAttempts {
				_, _ = s.pool.Exec(ctx, `UPDATE passwordless_tokens SET consumed=TRUE
					WHERE (token_hash=$1 OR otp_hash=$1) AND consumed=FALSE`, hash)
				return true, nil
			}
			return false, nil
		}
		s.onFallback("down")
	}
	var attempts int
	if err := s.pool.QueryRow(ctx, `UPDATE passwordless_tokens SET attempts=attempts+1
		WHERE (token_hash=$1 OR otp_hash=$1) AND consumed=FALSE
		RETURNING attempts`, hash).Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, auth.ErrPlessInvalid
		}
		return false, fmt.Errorf("increment %v: %w", err, auth.ErrSessionInfra)
	}
	if attempts >= auth.PlessMaxAttempts {
		_, _ = s.pool.Exec(ctx, `UPDATE passwordless_tokens SET consumed=TRUE
			WHERE token_hash=$1 OR otp_hash=$1`, hash)
		return true, nil
	}
	return false, nil
}

func plessSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

var _ auth.PasswordlessStore = (*CombinedPasswordlessStore)(nil)
