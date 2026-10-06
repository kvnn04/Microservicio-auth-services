package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// MFAStores implementa auth.MFASecretStore + auth.MFAChallengeStore +
// auth.BackupCodesPort con Redis-primario + Postgres-fallback.
// El login (CU-AUTH-01) registra el challenge vía RegisterChallenge.
type MFAStores struct {
	pool  *pgxpool.Pool
	cache *redisadapter.MFAChallengeCache
	rdb   *redis.Client
}

func NewMFAStores(pool *pgxpool.Pool, cache *redisadapter.MFAChallengeCache, rdb *redis.Client) *MFAStores {
	return &MFAStores{pool: pool, cache: cache, rdb: rdb}
}

func isRedisNil(err error) bool {
	return errors.Is(err, redis.Nil)
}

// --- Secretos ---

func (s *MFAStores) Stage(ctx context.Context, userID string, secretEnc []byte) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO mfa_totp_secrets
		(user_id, secret_enc, staged, staged_expires_at, verified)
		VALUES ($1,$2,TRUE,now()+INTERVAL '10 minutes',FALSE)
		ON CONFLICT (user_id) DO UPDATE SET secret_enc=EXCLUDED.secret_enc,
			staged=TRUE, staged_expires_at=now()+INTERVAL '10 minutes', verified=FALSE`,
		uid, secretEnc)
	return err
}

func (s *MFAStores) Staged(ctx context.Context, userID string) ([]byte, bool, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, false, err
	}
	var enc []byte
	var exp time.Time
	if err := s.pool.QueryRow(ctx, `SELECT secret_enc, staged_expires_at FROM mfa_totp_secrets
		WHERE user_id=$1 AND staged=TRUE`, uid).Scan(&enc, &exp); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, auth.ErrNoStaged
		}
		return nil, false, err
	}
	if time.Now().UTC().After(exp) {
		return nil, true, nil
	}
	return enc, false, nil
}

func (s *MFAStores) PromoteTx(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE mfa_totp_secrets SET staged=FALSE, verified=TRUE, enabled_at=now()
		WHERE user_id=$1 AND staged=TRUE`, uid)
	if err != nil || tag.RowsAffected() == 0 {
		return auth.ErrNoStaged
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET mfa_enabled=TRUE, updated_at=now() WHERE id=$1`, uid); err != nil {
		return err
	}
	actPayload, _ := json.Marshal(map[string]any{"user_id": uid.String(), "method": "totp"})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES (gen_random_uuid(),'mfa.enabled',$1,'auth.mfa.v1',$2,'pending')`, uid, string(actPayload)); err != nil {
		return err
	}
	mailTo := ""
	_ = tx.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1`, uid).Scan(&mailTo)
	if mailTo != "" {
		_, _ = tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES (gen_random_uuid(),$1,'MFA activado','Activaste la verificación en dos pasos. Si no fuiste tú, cambia tu contraseña.\n','pending')`, mailTo)
	}
	return tx.Commit(ctx)
}

func (s *MFAStores) GetActive(ctx context.Context, userID string) ([]byte, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	var enc []byte
	if err := s.pool.QueryRow(ctx, `SELECT secret_enc FROM mfa_totp_secrets
		WHERE user_id=$1 AND staged=FALSE AND verified=TRUE`, uid).Scan(&enc); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrNotFound
		}
		return nil, err
	}
	return enc, nil
}

func (s *MFAStores) DisableTx(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_totp_secrets WHERE user_id=$1`, uid); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET mfa_enabled=FALSE, updated_at=now() WHERE id=$1`, uid); err != nil {
		return err
	}
	disPayload, _ := json.Marshal(map[string]any{"user_id": uid.String()})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES (gen_random_uuid(),'mfa.disabled',$1,'auth.mfa.v1',$2,'pending')`, uid, string(disPayload)); err != nil {
		return err
	}
	mailTo := ""
	_ = tx.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1`, uid).Scan(&mailTo)
	if mailTo != "" {
		_, _ = tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES (gen_random_uuid(),$1,'MFA desactivado','Desactivaste la verificación en dos pasos. Si no fuiste tú, recupera tu cuenta.\n','pending')`, mailTo)
	}
	return tx.Commit(ctx)
}

// --- Challenges (Redis primario, DB fallback) ---

// RegisterChallenge persiste el challenge al emitir el pre-token (login).
// Nombre del puerto: Register (MFAChallengeStore).
func (s *MFAStores) Register(ctx context.Context, challengeID, userID string) error {
	if s.rdb != nil {
		if err := s.rdb.Set(ctx, "mfa:challenge:"+challengeID, userID, 5*time.Minute).Err(); err == nil {
			return nil
		}
	}
	cid, err := uuid.Parse(challengeID)
	if err != nil {
		return err
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO mfa_challenges (challenge_id, user_id, expires_at)
		VALUES ($1,$2,now()+INTERVAL '5 minutes') ON CONFLICT DO NOTHING`, cid, uid)
	return err
}

func (s *MFAStores) Consume(ctx context.Context, challengeID string) (string, error) {
	if s.rdb != nil {
		// Denylist quemados (miss redis.Nil vs caída conexión).
		if v, derr := s.rdb.Get(ctx, "mfa:deny:"+challengeID).Result(); derr == nil {
			if v == "1" {
				return "", user.ErrNotFound
			}
		} else if !isRedisNil(derr) {
			goto dbFallback
		}
		if uid, gerr := s.rdb.Get(ctx, "mfa:challenge:"+challengeID).Result(); gerr == nil {
			if uid == "" {
				return "", user.ErrNotFound
			}
			_ = s.rdb.Del(ctx, "mfa:challenge:"+challengeID).Err()
			return uid, nil
		} else if isRedisNil(gerr) {
			return "", user.ErrNotFound
		}
		// Redis caído → fallback DB.
	}
dbFallback:
	cid, err := uuid.Parse(challengeID)
	if err != nil {
		return "", user.ErrNotFound
	}
	var uid uuid.UUID
	var consumed bool
	var exp time.Time
	if qerr := s.pool.QueryRow(ctx, `SELECT user_id, consumed, expires_at FROM mfa_challenges
		WHERE challenge_id=$1`, cid).Scan(&uid, &consumed, &exp); qerr != nil {
		if errors.Is(qerr, pgx.ErrNoRows) {
			return "", user.ErrNotFound
		}
		return "", qerr
	}
	if consumed || time.Now().UTC().After(exp) {
		return "", user.ErrNotFound
	}
	if _, err := s.pool.Exec(ctx, `UPDATE mfa_challenges SET consumed=TRUE WHERE challenge_id=$1`, cid); err != nil {
		return "", err
	}
	return uid.String(), nil
}

func (s *MFAStores) RecordFail(ctx context.Context, challengeID string) (bool, error) {
	if s.rdb != nil {
		n, err := s.rdb.Incr(ctx, "mfa:fails:"+challengeID).Result()
		if err == nil {
			_ = s.rdb.Expire(ctx, "mfa:fails:"+challengeID, 5*time.Minute).Err()
			if n >= auth.MaxVerifyFails {
				_ = s.rdb.Del(ctx, "mfa:challenge:"+challengeID).Err()
				_ = s.rdb.Set(ctx, "mfa:deny:"+challengeID, "1", 5*time.Minute).Err()
				return true, nil
			}
			return false, nil
		}
		// Redis caído → fail-open sin quemar (documentado).
		return false, nil
	}
	return false, nil
}

func (s *MFAStores) MarkReplay(ctx context.Context, userID string, counter int64) (bool, error) {
	if s.rdb != nil {
		ok, err := s.rdb.SetNX(ctx, fmt.Sprintf("mfa:used:%s:%d", userID, counter), "1", auth.ReplayTTL).Result()
		if err == nil {
			return ok, nil
		}
		// Redis caído → fallback DB UNIQUE determinista.
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return false, err
	}
	var n int
	if err := s.pool.QueryRow(ctx, `WITH ins AS (
			INSERT INTO mfa_used_counters (user_id, counter) VALUES ($1,$2)
			ON CONFLICT DO NOTHING RETURNING 1
		) SELECT count(*) FROM ins`, uid, counter).Scan(&n); err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *MFAStores) Uncheckable(ctx context.Context) bool {
	if s.rdb != nil {
		if err := s.rdb.Ping(ctx).Err(); err == nil {
			return false
		}
	}
	var one int
	if err := s.pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return true
	}
	return false
}
