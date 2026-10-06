package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-identity-service/internal/domain/user"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CombinedEmailChangeStore implementa user.EmailChangeStore con
// Redis-como-verdad + Postgres-backup (igual verify/pless/reset).
// Confirm: Postgres-Tx-primero (cambio + corte global) + Redis-DEL-después.
type CombinedEmailChangeStore struct {
	pool       *pgxpool.Pool
	cache      *redisadapter.EmailChangeCache
	sessions   *redisadapter.SessionCache
	frontURL   string
	onFallback func(reason string)
}

func NewCombinedEmailChangeStore(pool *pgxpool.Pool, cache *redisadapter.EmailChangeCache, sessions *redisadapter.SessionCache, frontURL string, onFallback func(string)) *CombinedEmailChangeStore {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &CombinedEmailChangeStore{pool: pool, cache: cache, sessions: sessions, frontURL: frontURL, onFallback: onFallback}
}

// QuotaCheck delega a Redis; caído → fail-open (igual verify).
func (s *CombinedEmailChangeStore) QuotaCheck(ctx context.Context, userID string) (bool, time.Duration, error) {
	if s.cache == nil {
		return true, 0, nil
	}
	allowed, retry, err := s.cache.QuotaCheck(ctx, userID)
	if err != nil {
		s.onFallback("down")
		return true, 0, nil
	}
	return allowed, retry, nil
}

// Taken indica si el email lo ocupa OTRA cuenta (auditado, no anónimo).
func (s *CombinedEmailChangeStore) Taken(ctx context.Context, newNormalized, requesterID string) (bool, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT id FROM users WHERE email_normalized=$1`, newNormalized).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("select taken %v: %w", err, user.ErrEmailChangeInvalid)
	}
	return id.String() != requesterID, nil
}

// Issue dual-write + supersede + outbox requested + doble-mail.
func (s *CombinedEmailChangeStore) Issue(ctx context.Context, rec *user.EmailChangeRecord) error {
	uid, err := uuid.Parse(rec.RequesterID)
	if err != nil {
		return fmt.Errorf("invalid requester: %w", user.ErrEmailChangeInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %v: %w", err, user.ErrEmailChangeInvalid)
	}
	defer tx.Rollback(ctx)

	var oldNorm, oldOrig string
	if err := tx.QueryRow(ctx, `SELECT email_normalized, email_original FROM users WHERE id=$1`,
		uid).Scan(&oldNorm, &oldOrig); err != nil {
		return fmt.Errorf("select user %v: %w", err, user.ErrEmailChangeInvalid)
	}
	_, _ = tx.Exec(ctx, `UPDATE email_change_tokens SET consumed=TRUE, superseded=TRUE
		WHERE requester=$1 AND consumed=FALSE`, uid)

	if _, err := tx.Exec(ctx, `INSERT INTO email_change_tokens
		(token_hash, requester, new_normalized, new_original, expires_at, attempts, consumed, superseded)
		VALUES ($1,$2,$3,$4,$5,0,FALSE,FALSE)`,
		rec.TokenHash, uid, rec.NewNormalized, rec.NewOriginal, rec.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert token %v: %w", err, user.ErrEmailChangeInvalid)
	}

	masked := user.MaskEmail(rec.NewNormalized)
	reqPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "old_hash": "sha256:" + emailChangeSHA256(oldNorm),
		"new_hash": "sha256:" + emailChangeSHA256(rec.NewNormalized), "new_masked": masked,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'email.change_requested',$2,'auth.email.v1',$3,'pending')`,
		uuid.New(), uid, string(reqPayload)); err != nil {
		return fmt.Errorf("insert outbox %v: %w", err, user.ErrEmailChangeInvalid)
	}

	// (a) Confirmación al NUEVO con link (plano una sola vez, TLS).
	if rec.TokenPlain != "" {
		link := s.frontURL + "/email-change?token=" + rec.TokenPlain
		newBody := "Hola,\n\nSe solicitó usar este correo en una cuenta " +
			"(expira en 15 minutos, un solo uso):\n\n" +
			"Enlace: " + link + "\n\n" +
			"Si no fuiste tú quien lo pidió, ignora este mensaje.\n"
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES ($1,$2,'Confirma tu nuevo correo',$3,'pending')`,
			uuid.New(), rec.NewNormalized, newBody); err != nil {
			return fmt.Errorf("insert new email %v: %w", err, user.ErrEmailChangeInvalid)
		}
	}
	// (b) Aviso al VIEJO sin token (mask, sin PII cruzada completa).
	oldBody := "Hola,\n\nSe solicitó cambiar el correo de tu cuenta a " + masked + ".\n\n" +
		"Si no fuiste tú, asegura tu cuenta cuanto antes.\n"
	if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
		VALUES ($1,$2,'Aviso: cambio de correo solicitado',$3,'pending')`,
		uuid.New(), oldNorm, oldBody); err != nil {
		return fmt.Errorf("insert old email %v: %w", err, user.ErrEmailChangeInvalid)
	}
	_ = oldOrig

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %v: %w", err, user.ErrEmailChangeInvalid)
	}
	if s.cache != nil {
		if err := s.cache.Put(ctx, rec); err != nil {
			s.onFallback("down")
		}
		s.cache.NoteSent(ctx, rec.RequesterID)
	}
	return nil
}

// FindAlive Redis→fallback PG read-through + rehidrata.
func (s *CombinedEmailChangeStore) FindAlive(ctx context.Context, hash string) (*user.EmailChangeRecord, error) {
	if s.cache != nil {
		rec, hit, err := s.cache.Get(ctx, hash)
		if err != nil {
			s.onFallback("down")
		} else if hit {
			if rec.Alive(time.Now().UTC()) {
				return rec, nil
			}
			return nil, user.ErrEmailChangeInvalid
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

func (s *CombinedEmailChangeStore) findAliveSQL(ctx context.Context, hash string) (*user.EmailChangeRecord, error) {
	const q = `SELECT requester, token_hash, new_normalized, new_original, expires_at, attempts, consumed, superseded
		FROM email_change_tokens WHERE token_hash=$1`
	var rec user.EmailChangeRecord
	var req uuid.UUID
	if err := s.pool.QueryRow(ctx, q, hash).Scan(
		&req, &rec.TokenHash, &rec.NewNormalized, &rec.NewOriginal,
		&rec.ExpiresAt, &rec.Attempts, &rec.Consumed, &rec.Superseded,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrEmailChangeInvalid
		}
		return nil, fmt.Errorf("select token %v: %w", err, user.ErrEmailChangeInvalid)
	}
	rec.RequesterID = req.String()
	if !rec.Alive(time.Now().UTC()) {
		return nil, user.ErrEmailChangeInvalid
	}
	return &rec, nil
}

// ConfirmTx aplica el cambio en Tx atómica + corte global + relogin.
// Race (otro tomó el nuevo) → quema el token y ErrEmailAlreadyInUse.
func (s *CombinedEmailChangeStore) ConfirmTx(ctx context.Context, hash string) (string, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", fmt.Errorf("begin %v: %w", err, user.ErrEmailChangeInvalid)
	}
	defer tx.Rollback(ctx)

	var req uuid.UUID
	var newNorm, newOrig string
	var consumed, superseded bool
	var exp time.Time
	var attempts int
	if err := tx.QueryRow(ctx, `SELECT requester, new_normalized, new_original, consumed, superseded, expires_at, attempts
		FROM email_change_tokens WHERE token_hash=$1 FOR UPDATE`, hash).Scan(
		&req, &newNorm, &newOrig, &consumed, &superseded, &exp, &attempts,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", user.ErrEmailChangeInvalid
		}
		return "", "", fmt.Errorf("select token %v: %w", err, user.ErrEmailChangeInvalid)
	}
	now := time.Now().UTC()
	if consumed || superseded || !exp.After(now) || attempts >= user.EmailChangeMaxAttempts {
		return "", "", user.ErrEmailChangeInvalid
	}
	var status string
	var oldNorm string
	if err := tx.QueryRow(ctx, `SELECT status, email_normalized FROM users WHERE id=$1`,
		req).Scan(&status, &oldNorm); err != nil {
		return "", "", user.ErrEmailChangeInvalid
	}
	if status != string(user.StatusActive) {
		return "", "", user.ErrEmailChangeInvalid
	}
	// Re-UNIQUE en Tx: si otro lo tomó entre medio → quema + 409.
	var other uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE email_normalized=$1`, newNorm).Scan(&other); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", "", fmt.Errorf("select taken %v: %w", err, user.ErrEmailChangeInvalid)
	} else if err == nil && other.String() != req.String() {
		_, _ = tx.Exec(ctx, `UPDATE email_change_tokens SET consumed=TRUE WHERE token_hash=$1`, hash)
		if cerr := tx.Commit(ctx); cerr != nil {
			return "", "", fmt.Errorf("commit burn %v: %w", err, user.ErrEmailChangeInvalid)
		}
		return "", "", user.ErrEmailAlreadyInUse
	}

	if _, err := tx.Exec(ctx, `UPDATE users SET email_normalized=$2, email_original=$3,
		updated_at=$4 WHERE id=$1`, req, newNorm, newOrig, now); err != nil {
		return "", "", fmt.Errorf("update email %v: %w", err, user.ErrEmailChangeInvalid)
	}
	if _, err := tx.Exec(ctx, `UPDATE email_change_tokens SET consumed=TRUE WHERE token_hash=$1`, hash); err != nil {
		return "", "", fmt.Errorf("consume %v: %w", err, user.ErrEmailChangeInvalid)
	}
	_, _ = tx.Exec(ctx, `UPDATE email_change_tokens SET consumed=TRUE, superseded=TRUE
		WHERE requester=$1 AND consumed=FALSE AND token_hash!=$2`, req, hash)

	// Corte global (incluida la actual): valid_after + revoke + DELETE.
	if _, err := tx.Exec(ctx, `UPDATE users SET tokens_valid_after=$2 WHERE id=$1`, req, now); err != nil {
		return "", "", fmt.Errorf("valid_after %v: %w", err, user.ErrEmailChangeInvalid)
	}
	type sessRef struct{ sid, fam, jti string }
	var refs []sessRef
	rows, err := tx.Query(ctx, `SELECT sid::text, family::text, jti_actual::text FROM sessions WHERE user_id=$1`, req)
	if err == nil {
		for rows.Next() {
			var r sessRef
			if rerr := rows.Scan(&r.sid, &r.fam, &r.jti); rerr == nil {
				refs = append(refs, r)
			}
		}
		rows.Close()
	}
	_, _ = tx.Exec(ctx, `UPDATE refresh_families SET revoked=TRUE WHERE user_id=$1`, req)
	_, _ = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, req)

	masked := user.MaskEmail(newNorm)
	changedPayload, _ := json.Marshal(map[string]any{
		"user_id": req.String(), "new_hash": "sha256:" + emailChangeSHA256(newNorm), "new_masked": masked,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'email.changed',$2,'auth.email.v1',$3,'pending')`,
		uuid.New(), req, string(changedPayload)); err != nil {
		return "", "", fmt.Errorf("insert outbox %v: %w", err, user.ErrEmailChangeInvalid)
	}
	revokedPayload, _ := json.Marshal(map[string]any{
		"user_id": req.String(), "reason": "email_change",
		"valid_after": now.Format("2006-01-02T15:04:05Z"),
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'session.revoked_all',$2,'auth.session.revoked_all.v1',$3,'pending')`,
		uuid.New(), req, string(revokedPayload)); err != nil {
		return "", "", fmt.Errorf("insert revoke outbox %v: %w", err, user.ErrEmailChangeInvalid)
	}
	changedBody := "Hola,\n\nEl correo de tu cuenta ahora es " + masked + ".\n\n" +
		"Tuvimos que cerrar todas tus sesiones: vuelve a iniciar sesión con tu nuevo correo.\n" +
		"Si no fuiste tú, asegura tu cuenta cuanto antes.\n"
	if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
		VALUES ($1,$2,'Tu correo cambió',$3,'pending')`,
		uuid.New(), newNorm, changedBody); err != nil {
		return "", "", fmt.Errorf("insert email_queue %v: %w", err, user.ErrEmailChangeInvalid)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("commit %v: %w", err, user.ErrEmailChangeInvalid)
	}

	if s.cache != nil {
		s.cache.Invalidate(ctx, &user.EmailChangeRecord{RequesterID: req.String(), TokenHash: hash})
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
	return req.String(), newNorm, nil
}

// IncrementAttempts suma un abuso; al 3º quema (consumed=TRUE).
func (s *CombinedEmailChangeStore) IncrementAttempts(ctx context.Context, hash string) (bool, error) {
	if s.cache != nil {
		n, err := s.cache.IncrAttempts(ctx, hash)
		if err == nil {
			if n >= user.EmailChangeMaxAttempts {
				_, _ = s.pool.Exec(ctx, `UPDATE email_change_tokens SET consumed=TRUE
					WHERE token_hash=$1 AND consumed=FALSE`, hash)
				return true, nil
			}
			return false, nil
		}
		s.onFallback("down")
	}
	var attempts int
	if err := s.pool.QueryRow(ctx, `UPDATE email_change_tokens SET attempts=attempts+1
		WHERE token_hash=$1 AND consumed=FALSE
		RETURNING attempts`, hash).Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, user.ErrEmailChangeInvalid
		}
		return false, fmt.Errorf("increment %v: %w", err, user.ErrEmailChangeInvalid)
	}
	if attempts >= user.EmailChangeMaxAttempts {
		_, _ = s.pool.Exec(ctx, `UPDATE email_change_tokens SET consumed=TRUE
			WHERE token_hash=$1`, hash)
		return true, nil
	}
	return false, nil
}

func emailChangeSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

var _ user.EmailChangeStore = (*CombinedEmailChangeStore)(nil)
