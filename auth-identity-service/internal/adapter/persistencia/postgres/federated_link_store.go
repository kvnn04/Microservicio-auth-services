package postgres

import (
	"context"
	"errors"
	"fmt"

	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FederatedLinkStore implementa user.FederatedLinkStore (CU-REG-06).
// Reutiliza FederatedRepository para lookups; aquí link/unlink/listado.
type FederatedLinkStore struct {
	*FederatedRepository
	pool *pgxpool.Pool
}

func NewFederatedLinkStore(pool *pgxpool.Pool) *FederatedLinkStore {
	return &FederatedLinkStore{FederatedRepository: NewFederatedRepository(pool), pool: pool}
}

// LinkTx vincula con mapeo determinista (pre-checks + constraints de carrera):
// self→ErrAlreadyLinkedSelf, otro→ErrCollisionForeign, provider→ErrProviderTaken.
func (s *FederatedLinkStore) LinkTx(ctx context.Context, f *user.FederatedIdentity, outbox []user.OutboxPayload, mails []user.MailPayload) error {
	uid, err := uuid.Parse(f.UserID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}
	// 1. ¿Sub vinculado? (self vs ajeno sin escribir).
	var ownerID uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT user_id FROM federated_identities WHERE provider=$1 AND sub=$2`,
		string(f.Provider), f.Sub).Scan(&ownerID)
	if err == nil {
		if ownerID == uid {
			return user.ErrAlreadyLinkedSelf
		}
		return user.ErrCollisionForeign
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lookup sub: %w", err)
	}
	// 2. ¿Provider ya tomado por este usuario con otro sub?
	var taken bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM federated_identities WHERE provider=$1 AND user_id=$2)`,
		string(f.Provider), uid).Scan(&taken); err != nil {
		return fmt.Errorf("lookup taken: %w", err)
	}
	if taken {
		return user.ErrProviderTaken
	}
	// 3. INSERT (constraints resuelven la carrera igual que los pre-checks).
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO federated_identities
		(provider, sub, user_id, email_at_link, iss) VALUES ($1,$2,$3,$4,$5)`,
		string(f.Provider), f.Sub, uid, f.EmailAtLink, f.Iss,
	); err != nil {
		return mapLinkViolation(ctx, tx, s.pool, f, uid)
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET federated_only=FALSE, updated_at=now() WHERE id=$1`, uid); err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	for _, e := range outbox {
		eid, perr := uuid.Parse(e.EventID)
		if perr != nil {
			return fmt.Errorf("invalid event id: %w", perr)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO outbox
			(event_id, event_type, aggregate_id, topic, payload, status)
			VALUES ($1,$2,$3,$4,$5,'pending')`,
			eid, e.EventType, uid, e.Topic, string(e.PayloadJSON),
		); err != nil {
			return fmt.Errorf("insert outbox: %w", err)
		}
	}
	for _, m := range mails {
		if m.To == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES (gen_random_uuid(),$1,$2,$3,'pending')`, m.To, m.Subject, m.Body); err != nil {
			return fmt.Errorf("insert email_queue: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// mapLinkViolation re-lee tras violar UNIQUE para mapear la carrera.
func mapLinkViolation(ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool, f *user.FederatedIdentity, uid uuid.UUID) error {
	_ = tx.Rollback(ctx)
	var ownerID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT user_id FROM federated_identities WHERE provider=$1 AND sub=$2`,
		string(f.Provider), f.Sub).Scan(&ownerID); err == nil {
		if ownerID == uid {
			return user.ErrAlreadyLinkedSelf
		}
		return user.ErrCollisionForeign
	}
	return user.ErrProviderTaken
}

// UnlinkTx desvincula + outbox + aviso. linked=false si no existía.
func (s *FederatedLinkStore) UnlinkTx(ctx context.Context, userID string, p user.Provider, outbox []user.OutboxPayload, mail user.MailPayload) (bool, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return false, fmt.Errorf("invalid user id: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM federated_identities WHERE provider=$1 AND user_id=$2`,
		string(p), uid)
	if err != nil {
		return false, fmt.Errorf("delete link: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	for _, e := range outbox {
		eid, perr := uuid.Parse(e.EventID)
		if perr != nil {
			return false, fmt.Errorf("invalid event id: %w", perr)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO outbox
			(event_id, event_type, aggregate_id, topic, payload, status)
			VALUES ($1,$2,$3,$4,$5,'pending')`,
			eid, e.EventType, uid, e.Topic, string(e.PayloadJSON),
		); err != nil {
			return false, fmt.Errorf("insert outbox: %w", err)
		}
	}
	if mail.To != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES (gen_random_uuid(),$1,$2,$3,'pending')`, mail.To, mail.Subject, mail.Body); err != nil {
			return false, fmt.Errorf("insert email_queue: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

// ListByUser retorna vínculos + si tiene password local.
func (s *FederatedLinkStore) ListByUser(ctx context.Context, userID string) ([]user.FederatedIdentity, bool, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, false, fmt.Errorf("invalid user id: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT provider, sub, user_id, email_at_link, iss, created_at
		FROM federated_identities WHERE user_id=$1 ORDER BY created_at`, uid)
	if err != nil {
		return nil, false, fmt.Errorf("select links: %w", err)
	}
	var links []user.FederatedIdentity
	for rows.Next() {
		var fi user.FederatedIdentity
		var prov string
		var id uuid.UUID
		if err := rows.Scan(&prov, &fi.Sub, &id, &fi.EmailAtLink, &fi.Iss, &fi.CreatedAt); err != nil {
			rows.Close()
			return nil, false, err
		}
		fi.Provider = user.Provider(prov)
		fi.UserID = id.String()
		links = append(links, fi)
	}
	rows.Close()
	var hasPassword bool
	if err := s.pool.QueryRow(ctx, `SELECT password_hash IS NOT NULL FROM users WHERE id=$1`, uid).Scan(&hasPassword); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, user.ErrNotFound
		}
		return nil, false, fmt.Errorf("select user: %w", err)
	}
	return links, hasPassword, nil
}
