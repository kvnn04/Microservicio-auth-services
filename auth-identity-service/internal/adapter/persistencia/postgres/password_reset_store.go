package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
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

// CombinedPasswordResetStore implementa auth.PasswordResetStore con
// Redis-como-verdad + Postgres-backup (igual verify/pless).
// Consumo: Postgres-Tx-primero (cambio + corte global) + Redis-DEL-después.
type CombinedPasswordResetStore struct {
	pool       *pgxpool.Pool
	cache      *redisadapter.PasswordResetCache
	sessions   *redisadapter.SessionCache
	frontURL   string
	onFallback func(reason string)
}

func NewCombinedPasswordResetStore(pool *pgxpool.Pool, cache *redisadapter.PasswordResetCache, sessions *redisadapter.SessionCache, frontURL string, onFallback func(string)) *CombinedPasswordResetStore {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &CombinedPasswordResetStore{pool: pool, cache: cache, sessions: sessions, frontURL: frontURL, onFallback: onFallback}
}

// EligibleForReset: ACTIVE+hash → eligible; ACTIVE federated-only → hint.
func (s *CombinedPasswordResetStore) EligibleForReset(ctx context.Context, normalizedEmail string) (string, bool, bool, error) {
	var uid uuid.UUID
	var status string
	var pwHash sql.NullString
	err := s.pool.QueryRow(ctx, `SELECT id, status, password_hash
		FROM users WHERE email_normalized = $1`, normalizedEmail).Scan(&uid, &status, &pwHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, false, nil
		}
		return "", false, false, fmt.Errorf("select user %v: %w", err, auth.ErrSessionInfra)
	}
	if status != string(user.StatusActive) {
		return uid.String(), false, false, nil
	}
	if pwHash.Valid && pwHash.String != "" {
		return uid.String(), true, false, nil
	}
	return uid.String(), false, true, nil
}

// QuotaCheck delega a Redis; caído → fail-open (igual verify).
func (s *CombinedPasswordResetStore) QuotaCheck(ctx context.Context, key string) (bool, time.Duration, error) {
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

// Issue dual-write + supersede + outbox requested + email_queue con link.
func (s *CombinedPasswordResetStore) Issue(ctx context.Context, rec *auth.PasswordResetRecord) error {
	uid, err := uuid.Parse(rec.UserID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", auth.ErrPwdResetInvalid)
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
	_, _ = tx.Exec(ctx, `UPDATE password_reset_tokens SET consumed=TRUE, superseded=TRUE
		WHERE user_id=$1 AND consumed=FALSE`, uid)

	if _, err := tx.Exec(ctx, `INSERT INTO password_reset_tokens
		(token_hash, user_id, expires_at, attempts, consumed, superseded, ctx_ip_hash, ctx_ua_hash)
		VALUES ($1,$2,$3,0,FALSE,FALSE,$4,$5)`,
		rec.TokenHash, uid, rec.ExpiresAt, rec.Ctx.IPHash24, rec.Ctx.UAHash,
	); err != nil {
		return fmt.Errorf("insert token %v: %w", err, auth.ErrSessionInfra)
	}

	eh := pwdResetSHA256(emailNorm)
	reqPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "email_hash": "sha256:" + eh,
		"expires_at": rec.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'password.reset_requested',$2,'auth.password.v1',$3,'pending')`,
		uuid.New(), uid, string(reqPayload)); err != nil {
		return fmt.Errorf("insert outbox %v: %w", err, auth.ErrSessionInfra)
	}

	if rec.TokenPlain != "" {
		link := s.frontURL + "/reset?token=" + rec.TokenPlain
		body := "Hola,\n\nUsa este enlace para crear una contraseña nueva " +
			"(expira en 15 minutos, un solo uso):\n\n" +
			"Enlace: " + link + "\n\n" +
			"Si no fuiste tú, ignora este mensaje y asegura tu cuenta.\n"
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES ($1,$2,'Restablece tu contraseña',$3,'pending')`,
			uuid.New(), emailNorm, body); err != nil {
			return fmt.Errorf("insert email_queue %v: %w", err, auth.ErrSessionInfra)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}
	if s.cache != nil {
		if err := s.cache.Put(ctx, rec); err != nil {
			s.onFallback("down")
		}
		s.cache.NoteSent(ctx, rec.UserID)
	}
	return nil
}

// IssueHint encola aviso alternativo federated-only (sin link) + outbox.
func (s *CombinedPasswordResetStore) IssueHint(ctx context.Context, userID, email string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", auth.ErrPwdResetInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	eh := pwdResetSHA256(email)
	hintPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "email_hash": "sha256:" + eh,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'password.reset_federated_hint',$2,'auth.password.v1',$3,'pending')`,
		uuid.New(), uid, string(hintPayload)); err != nil {
		return fmt.Errorf("insert outbox %v: %w", err, auth.ErrSessionInfra)
	}
	body := "Hola,\n\nPediste restablecer tu contraseña, pero esta cuenta " +
		"entra con Google y no tiene contraseña.\n\n" +
		"Inicia sesión con Google desde la pantalla de acceso.\n" +
		"Si no fuiste tú, ignora este mensaje.\n"
	if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
		VALUES ($1,$2,'Tu cuenta usa Google',$3,'pending')`,
		uuid.New(), email, body); err != nil {
		return fmt.Errorf("insert email_queue %v: %w", err, auth.ErrSessionInfra)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}
	if s.cache != nil {
		s.cache.NoteSent(ctx, userID)
	}
	return nil
}

// FindAlive Redis→fallback PG read-through + rehidrata + usuario.
func (s *CombinedPasswordResetStore) FindAlive(ctx context.Context, hash string) (*auth.PasswordResetRecord, *user.User, error) {
	if s.cache != nil {
		if rec, hit, err := s.cache.Get(ctx, hash); err != nil {
			s.onFallback("down")
		} else if hit {
			if !rec.Alive(time.Now().UTC()) {
				return nil, nil, auth.ErrPwdResetInvalid
			}
			u, uerr := s.findUser(ctx, rec.UserID)
			if uerr != nil {
				return nil, nil, uerr
			}
			return rec, u, nil
		} else {
			s.onFallback("miss")
		}
	}
	rec, err := s.findAliveSQL(ctx, hash)
	if err != nil {
		return nil, nil, err
	}
	u, uerr := s.findUser(ctx, rec.UserID)
	if uerr != nil {
		return nil, nil, uerr
	}
	if s.cache != nil {
		_ = s.cache.Put(ctx, rec)
	}
	return rec, u, nil
}

func (s *CombinedPasswordResetStore) findAliveSQL(ctx context.Context, hash string) (*auth.PasswordResetRecord, error) {
	const q = `SELECT user_id, token_hash, expires_at, attempts, consumed, superseded, ctx_ip_hash, ctx_ua_hash
		FROM password_reset_tokens WHERE token_hash=$1`
	var rec auth.PasswordResetRecord
	var uid uuid.UUID
	if err := s.pool.QueryRow(ctx, q, hash).Scan(
		&uid, &rec.TokenHash, &rec.ExpiresAt, &rec.Attempts,
		&rec.Consumed, &rec.Superseded, &rec.Ctx.IPHash24, &rec.Ctx.UAHash,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrPwdResetInvalid
		}
		return nil, fmt.Errorf("select token %v: %w", err, auth.ErrSessionInfra)
	}
	rec.UserID = uid.String()
	if !rec.Alive(time.Now().UTC()) {
		return nil, auth.ErrPwdResetInvalid
	}
	return &rec, nil
}

func (s *CombinedPasswordResetStore) findUser(ctx context.Context, userID string) (*user.User, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, auth.ErrPwdResetInvalid
	}
	var u user.User
	var status string
	var pwHash sql.NullString
	if err := s.pool.QueryRow(ctx, `SELECT id, email_normalized, email_original, password_hash, password_algo,
		status, terms_version, privacy_version, terms_accepted_at, created_at, updated_at,
		COALESCE(mfa_enabled, FALSE)
		FROM users WHERE id=$1`, uid).Scan(
		&uid, &u.EmailNormalized, &u.EmailOriginal, &pwHash, &u.PasswordAlgo,
		&status, &u.TermsVersion, &u.PrivacyVersion, &u.TermsAcceptedAt, &u.CreatedAt, &u.UpdatedAt,
		&u.MFAEnabled,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrPwdResetInvalid
		}
		return nil, fmt.Errorf("select user %v: %w", err, auth.ErrSessionInfra)
	}
	u.PasswordHash = pwHash.String
	u.ID = uid.String()
	u.Status = user.Status(status)
	return &u, nil
}

// ConsumeTx cambia la clave y corta todo en Tx atómica + corte global.
// risk=high → outbox mismatch + email alerta. Sin auto-login.
func (s *CombinedPasswordResetStore) ConsumeTx(ctx context.Context, userID, hash, newHash, risk, curIPHash, curUAHash, requestID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return auth.ErrPwdResetInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	var status, emailNorm string
	if err := tx.QueryRow(ctx, `SELECT status, email_normalized FROM users WHERE id=$1 FOR UPDATE`,
		uid).Scan(&status, &emailNorm); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.ErrPwdResetInvalid
		}
		return fmt.Errorf("select user %v: %w", err, auth.ErrSessionInfra)
	}
	if status != string(user.StatusActive) {
		return auth.ErrPwdResetInvalid
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE password_reset_tokens SET consumed=TRUE
		WHERE token_hash=$2 AND user_id=$1
		AND consumed=FALSE AND superseded=FALSE AND expires_at>$3 AND attempts<$4`,
		uid, hash, now, auth.PwdResetMaxAttempts)
	if err != nil || tag.RowsAffected() == 0 {
		return auth.ErrPwdResetInvalid // carrera: otro request ganó.
	}
	_, _ = tx.Exec(ctx, `UPDATE password_reset_tokens SET consumed=TRUE, superseded=TRUE
		WHERE user_id=$1 AND consumed=FALSE AND token_hash!=$2`, uid, hash)
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2, password_algo='argon2id',
		updated_at=$3, tokens_valid_after=$3 WHERE id=$1`, uid, newHash, now); err != nil {
		return fmt.Errorf("update password %v: %w", err, auth.ErrSessionInfra)
	}

	// Corte global: revoca families + borra sesiones (PG) + junta claves Redis.
	type sessRef struct{ sid, fam, jti string }
	var refs []sessRef
	rows, err := tx.Query(ctx, `SELECT sid::text, family::text, jti_actual::text FROM sessions WHERE user_id=$1`, uid)
	if err == nil {
		for rows.Next() {
			var r sessRef
			if rerr := rows.Scan(&r.sid, &r.fam, &r.jti); rerr == nil {
				refs = append(refs, r)
			}
		}
		rows.Close()
	}
	_, _ = tx.Exec(ctx, `UPDATE refresh_families SET revoked=TRUE WHERE user_id=$1`, uid)
	_, _ = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, uid)

	changedPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "via": "reset", "risk": risk, "request_id": requestID,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'password.changed',$2,'auth.password.v1',$3,'pending')`,
		uuid.New(), uid, string(changedPayload)); err != nil {
		return fmt.Errorf("insert outbox %v: %w", err, auth.ErrSessionInfra)
	}
	revokedPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "reason": "password_reset",
		"valid_after": now.Format("2006-01-02T15:04:05Z"),
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'session.revoked_all',$2,'auth.session.revoked_all.v1',$3,'pending')`,
		uuid.New(), uid, string(revokedPayload)); err != nil {
		return fmt.Errorf("insert revoke outbox %v: %w", err, auth.ErrSessionInfra)
	}
	if risk == "high" {
		mmPayload, _ := json.Marshal(map[string]any{
			"user_id": uid.String(), "ip_hash": "sha256:" + curIPHash,
			"ua_hash": "sha256:" + curUAHash, "risk": "high",
		})
		if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
			VALUES ($1,'security.context_mismatch',$2,'auth.security.context_mismatch.v1',$3,'pending')`,
			uuid.New(), uid, string(mmPayload)); err != nil {
			return fmt.Errorf("insert mismatch outbox %v: %w", err, auth.ErrSessionInfra)
		}
	}
	changedBody := "Hola,\n\nCambiaste la contraseña de tu cuenta el " +
		now.Format("2006-01-02 15:04 UTC") +
		". Cerramos tus demás sesiones por seguridad.\n\n" +
		"Si no fuiste tú, solicita un nuevo enlace de recuperación cuanto antes.\n"
	if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
		VALUES ($1,$2,'Cambiaste tu contraseña',$3,'pending')`,
		uuid.New(), emailNorm, changedBody); err != nil {
		return fmt.Errorf("insert email_queue %v: %w", err, auth.ErrSessionInfra)
	}
	if risk == "high" {
		alertBody := "Hola,\n\nSe cambió la contraseña de tu cuenta el " +
			now.Format("2006-01-02 15:04 UTC") +
			" desde una red o dispositivo distinto al que pidió el enlace.\n" +
			"Si no fuiste tú, tu cuenta puede estar comprometida: cambia tu contraseña y revisa tus sesiones.\n"
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES ($1,$2,'Aviso de seguridad: cambio de contraseña',$3,'pending')`,
			uuid.New(), emailNorm, alertBody); err != nil {
			return fmt.Errorf("insert alert email %v: %w", err, auth.ErrSessionInfra)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}

	// Invalidación Redis post-commit (best-effort, NO revierte).
	if s.cache != nil {
		s.cache.Invalidate(ctx, &auth.PasswordResetRecord{UserID: userID, TokenHash: hash})
	}
	if s.sessions != nil && len(refs) > 0 {
		sids := make([]string, 0, len(refs))
		fams := make([]string, 0, len(refs))
		jtis := make([]string, 0, len(refs))
		for _, r := range refs {
			sids = append(sids, r.sid)
			fams = append(fams, r.fam)
			jtis = append(jtis, r.jti)
		}
		if derr := s.sessions.InvalidateSessions(ctx, sids, fams, jtis); derr != nil {
			s.onFallback("sessions-down")
		}
	}
	return nil
}

// IncrementAttempts suma un abuso; al 3º quema (consumed=TRUE).
func (s *CombinedPasswordResetStore) IncrementAttempts(ctx context.Context, hash string) (bool, error) {
	if s.cache != nil {
		n, err := s.cache.IncrAttempts(ctx, hash)
		if err == nil {
			if n >= auth.PwdResetMaxAttempts {
				_, _ = s.pool.Exec(ctx, `UPDATE password_reset_tokens SET consumed=TRUE
					WHERE token_hash=$1 AND consumed=FALSE`, hash)
				return true, nil
			}
			return false, nil
		}
		s.onFallback("down")
	}
	var attempts int
	if err := s.pool.QueryRow(ctx, `UPDATE password_reset_tokens SET attempts=attempts+1
		WHERE token_hash=$1 AND consumed=FALSE
		RETURNING attempts`, hash).Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, auth.ErrPwdResetInvalid
		}
		return false, fmt.Errorf("increment %v: %w", err, auth.ErrSessionInfra)
	}
	if attempts >= auth.PwdResetMaxAttempts {
		_, _ = s.pool.Exec(ctx, `UPDATE password_reset_tokens SET consumed=TRUE
			WHERE token_hash=$1`, hash)
		return true, nil
	}
	return false, nil
}

func pwdResetSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

var _ auth.PasswordResetStore = (*CombinedPasswordResetStore)(nil)
