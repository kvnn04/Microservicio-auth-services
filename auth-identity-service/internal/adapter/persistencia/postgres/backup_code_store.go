package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackupCodeStore implementa auth.BackupCodeStore (CU-AUTH-03).
// Single-use irreversible en Tx (RN-02): nunca UPDATE a false ni DELETE.
type BackupCodeStore struct {
	pool *pgxpool.Pool
}

func NewBackupCodeStore(pool *pgxpool.Pool) *BackupCodeStore {
	return &BackupCodeStore{pool: pool}
}

// GenerateTx quema previos si supersede + inserta hashes (rellena hasta 10).
// Retorna superseded (previos invalidados) para el evento.
func (s *BackupCodeStore) GenerateTx(ctx context.Context, userID string, hashes []string, supersede bool) (int, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	superseded := 0
	if supersede {
		tag, err := tx.Exec(ctx, `UPDATE mfa_backup_codes SET used=TRUE, superseded=TRUE
			WHERE user_id=$1 AND used=FALSE`, uid)
		if err != nil {
			return 0, err
		}
		superseded = int(tag.RowsAffected())
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, `INSERT INTO mfa_backup_codes (code_hash, user_id)
			VALUES ($1,$2) ON CONFLICT (code_hash) DO NOTHING`, h, uid); err != nil {
			return 0, err
		}
	}
	// Verifica 10 activos (relleno del servicio si colisión global).
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mfa_backup_codes
		WHERE user_id=$1 AND used=FALSE`, uid).Scan(&active); err != nil {
		return 0, err
	}
	if active < auth.BackupCount {
		return 0, fmt.Errorf("short backup set %d: %w", active, auth.ErrInfra)
	}
	evPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "count": auth.BackupCount, "superseded": superseded,
	})
	typ := "backup.generated"
	if supersede {
		typ = "backup.regenerated"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES (gen_random_uuid(),$1,$2,'auth.backup.v1',$3,'pending')`, typ, uid, string(evPayload)); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return superseded, nil
}

// ConsumeTx quema un código + remaining + outbox en la misma Tx.
// Miss/used → ErrBackupNotFound|ErrBackupUsed (401 opaco). Carrera: 1×200/1×401.
func (s *BackupCodeStore) ConsumeTx(ctx context.Context, userID, hash, challengeID string) (int, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var stored, owner string
	var used bool
	if err := tx.QueryRow(ctx, `SELECT code_hash, user_id::text, used FROM mfa_backup_codes
		WHERE code_hash=$1 FOR UPDATE`, hash).Scan(&stored, &owner, &used); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, auth.ErrBackupNotFound
		}
		return 0, err
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 {
		return 0, auth.ErrBackupNotFound
	}
	if used || owner != uid.String() {
		if used {
			return 0, auth.ErrBackupUsed
		}
		return 0, auth.ErrBackupNotFound
	}
	cid, err := uuid.Parse(challengeID)
	if err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `UPDATE mfa_backup_codes SET used=TRUE, used_at=now(), used_challenge_id=$2
		WHERE code_hash=$1 AND used=FALSE`, hash, cid)
	if err != nil || tag.RowsAffected() == 0 {
		return 0, auth.ErrBackupUsed // carrera: otro ganó.
	}
	var remaining int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mfa_backup_codes
		WHERE user_id=$1 AND used=FALSE`, uid).Scan(&remaining); err != nil {
		return 0, err
	}
	prefix := hash
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	evPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "code_hash_prefix": prefix,
		"remaining": remaining, "challenge_id": challengeID,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES (gen_random_uuid(),'backup.consumed',$1,'auth.backup.v1',$2,'pending')`, uid, string(evPayload)); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return remaining, nil
}

// CountRemaining cuenta used=false (status + warnings).
func (s *BackupCodeStore) CountRemaining(ctx context.Context, userID string) (int, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return 0, err
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM mfa_backup_codes
		WHERE user_id=$1 AND used=FALSE`, uid).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// BurnAll marca used+superseded (disable MFA).
func (s *BackupCodeStore) BurnAll(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE mfa_backup_codes SET used=TRUE, superseded=TRUE
		WHERE user_id=$1 AND used=FALSE`, uid)
	return err
}
