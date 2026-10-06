package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FederatedRepository implementa user.FederatedRepository (CU-REG-04).
type FederatedRepository struct {
	pool *pgxpool.Pool
}

func NewFederatedRepository(pool *pgxpool.Pool) *FederatedRepository {
	return &FederatedRepository{pool: pool}
}

func (r *FederatedRepository) FindByProviderSub(ctx context.Context, p user.Provider, sub string) (*user.FederatedIdentity, *user.User, error) {
	const q = `SELECT f.provider, f.sub, f.user_id, f.email_at_link, f.iss,
		u.email_normalized, u.email_original, u.password_algo, u.status,
		u.terms_version, u.privacy_version, u.terms_accepted_at, u.created_at, u.updated_at,
		COALESCE(u.mfa_enabled, FALSE)
		FROM federated_identities f JOIN users u ON u.id = f.user_id
		WHERE f.provider=$1 AND f.sub=$2`
	var fi user.FederatedIdentity
	var u user.User
	var uid uuid.UUID
	var prov, status string
	err := r.pool.QueryRow(ctx, q, string(p), sub).Scan(
		&prov, &fi.Sub, &uid, &fi.EmailAtLink, &fi.Iss,
		&u.EmailNormalized, &u.EmailOriginal, &u.PasswordAlgo, &status,
		&u.TermsVersion, &u.PrivacyVersion, &u.TermsAcceptedAt, &u.CreatedAt, &u.UpdatedAt,
		&u.MFAEnabled,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, user.ErrNotFound
		}
		return nil, nil, fmt.Errorf("select federated: %w", err)
	}
	fi.Provider = user.Provider(prov)
	fi.UserID = uid.String()
	u.ID = uid.String()
	u.Status = user.Status(status)
	return &fi, &u, nil
}

func (r *FederatedRepository) FindUserByEmailNormalized(ctx context.Context, email string) (*user.User, error) {
	const q = `SELECT id, email_normalized, email_original, password_algo, status,
		terms_version, privacy_version, terms_accepted_at, created_at, updated_at
		FROM users WHERE email_normalized=$1`
	var u user.User
	var id uuid.UUID
	var status string
	if err := r.pool.QueryRow(ctx, q, email).Scan(
		&id, &u.EmailNormalized, &u.EmailOriginal, &u.PasswordAlgo, &status,
		&u.TermsVersion, &u.PrivacyVersion, &u.TermsAcceptedAt, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrNotFound
		}
		return nil, fmt.Errorf("select user by email: %w", err)
	}
	u.ID = id.String()
	u.Status = user.Status(status)
	return &u, nil
}

func (r *FederatedRepository) CreateUserWithFederation(ctx context.Context, u *user.User, f *user.FederatedIdentity, outbox []user.OutboxPayload, mail user.MailPayload, reg user.RegistrationContext) error {
	uid, err := uuid.Parse(u.ID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `INSERT INTO users
		(id, email_normalized, email_original, password_hash, password_algo, status,
		 terms_version, privacy_version, terms_accepted_at, created_at, updated_at,
		 federated_only, terms_source)
		VALUES ($1,$2,$3,NULL,'federated',$4,$5,$6,$7,$8,$9,TRUE,$10)
		ON CONFLICT (email_normalized) DO NOTHING`,
		uid, u.EmailNormalized, u.EmailOriginal, string(u.Status),
		u.TermsVersion, u.PrivacyVersion, u.TermsAcceptedAt, u.CreatedAt, u.UpdatedAt,
		nullIfEmpty(u.TermsSource),
	)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Email ya registrado con otra credencial → colisión (anti-takeover).
		return user.ErrEmailCollision
	}

	if _, err := tx.Exec(ctx, `INSERT INTO federated_identities
		(provider, sub, user_id, email_at_link, iss) VALUES ($1,$2,$3,$4,$5)`,
		string(f.Provider), f.Sub, uid, f.EmailAtLink, f.Iss,
	); err != nil {
		if isUniqueViolation(err) {
			return user.ErrAlreadyLinked
		}
		return fmt.Errorf("insert federated: %w", err)
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
	if mail.To != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES (gen_random_uuid(),$1,$2,$3,'pending')`, mail.To, mail.Subject, mail.Body); err != nil {
			return fmt.Errorf("insert email_queue: %w", err)
		}
	}
	// CU-REG-05: ledger legal en la misma Tx (source=federated_*).
	if err := insertConsentsTx(ctx, tx, uid, u, reg); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool {
	s := err.Error()
	return strings.Contains(s, "23505") || strings.Contains(s, "duplicate key")
}
