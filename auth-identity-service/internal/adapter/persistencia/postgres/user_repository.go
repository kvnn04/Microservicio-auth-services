package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserRepository implementa user.UserRepository + service.OutboxEnqueuer.
type UserRepository struct {
	pool     *pgxpool.Pool
	frontURL string
}

func NewUserRepository(pool *pgxpool.Pool, frontURL string) *UserRepository {
	return &UserRepository{pool: pool, frontURL: frontURL}
}

func (r *UserRepository) FindByEmailNormalized(ctx context.Context, email string) (*user.User, error) {
	const q = `SELECT id, email_normalized, email_original, password_hash, password_algo,
		status, terms_version, privacy_version, terms_accepted_at, created_at, updated_at,
		COALESCE(mfa_enabled, FALSE)
		FROM users WHERE email_normalized = $1`
	var u user.User
	var id uuid.UUID
	var status string
	var pwHash sql.NullString
	err := r.pool.QueryRow(ctx, q, email).Scan(
		&id, &u.EmailNormalized, &u.EmailOriginal, &pwHash, &u.PasswordAlgo,
		&status, &u.TermsVersion, &u.PrivacyVersion, &u.TermsAcceptedAt, &u.CreatedAt, &u.UpdatedAt,
		&u.MFAEnabled,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrNotFound
		}
		return nil, fmt.Errorf("select user: %w", err)
	}
	u.PasswordHash = pwHash.String
	u.ID = id.String()
	u.Status = user.Status(status)
	return &u, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*user.User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, user.ErrNotFound
	}
	const q = `SELECT id, email_normalized, email_original, password_hash, password_algo,
		status, terms_version, privacy_version, terms_accepted_at, created_at, updated_at,
		COALESCE(mfa_enabled, FALSE)
		FROM users WHERE id = $1`
	var u user.User
	var dbID uuid.UUID
	var status string
	var pwHash2 sql.NullString
	if err := r.pool.QueryRow(ctx, q, uid).Scan(
		&dbID, &u.EmailNormalized, &u.EmailOriginal, &pwHash2, &u.PasswordAlgo,
		&status, &u.TermsVersion, &u.PrivacyVersion, &u.TermsAcceptedAt, &u.CreatedAt, &u.UpdatedAt,
		&u.MFAEnabled,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrNotFound
		}
		return nil, fmt.Errorf("select user by id: %w", err)
	}
	u.PasswordHash = pwHash2.String
	u.ID = dbID.String()
	u.Status = user.Status(status)
	return &u, nil
}

func (r *UserRepository) CreateWithOutbox(ctx context.Context, u *user.User, outbox []user.OutboxPayload, tokenHash string, requestID string, mail *user.VerificationMail) error {
	return r.createTx(ctx, u, outbox, tokenHash, requestID, nil, mail)
}

// CreateWithConsents extiende la Tx con ledger legal (CU-REG-05): 2 filas
// consent_records (ON CONFLICT DO NOTHING) + evento legal.consent_recorded.
// Sin consentimiento no hay cuenta: todo revierte junto.
func (r *UserRepository) CreateWithConsents(ctx context.Context, u *user.User, outbox []user.OutboxPayload, tokenHash string, reg user.RegistrationContext, mail *user.VerificationMail) error {
	return r.createTx(ctx, u, outbox, tokenHash, reg.RequestID, &reg, mail)
}

func (r *UserRepository) createTx(ctx context.Context, u *user.User, outbox []user.OutboxPayload, tokenHash string, requestID string, reg *user.RegistrationContext, mail *user.VerificationMail) error {
	uid, err := uuid.Parse(u.ID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `INSERT INTO users
		(id, email_normalized, email_original, password_hash, password_algo, status,
		 terms_version, privacy_version, terms_accepted_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (email_normalized) DO NOTHING`,
		uid, u.EmailNormalized, u.EmailOriginal, u.PasswordHash, u.PasswordAlgo,
		string(u.Status), u.TermsVersion, u.PrivacyVersion, u.TermsAcceptedAt, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return user.ErrDuplicateShadow
	}
	expiresAt := time.Now().UTC().Add(auth.VerificationTTL)
	otpHash := sql.NullString{}
	if mail != nil && mail.OTPHash != "" {
		otpHash = sql.NullString{String: mail.OTPHash, Valid: true}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO verification_tokens
		(user_id, token_hash, otp_hash, expires_at, attempts, max_attempts, consumed)
		VALUES ($1,$2,$3,$4,0,$5,FALSE)`,
		uid, tokenHash, otpHash, expiresAt, auth.VerificationMaxAttempts,
	); err != nil {
		return fmt.Errorf("insert verification token: %w", err)
	}
	// Fix email inicial (2026-10-07): encola link+OTP en la MISMA Tx
	// (plantilla idéntica al resend). Si falla → rollback total (fail-closed).
	// Sin mail (nil o sin plano) no se encola nada (rama shadow/legacy).
	if mail != nil && mail.TokenPlain != "" {
		link := r.frontURL + "/verify?token=" + mail.TokenPlain
		body := "Verifica tu cuenta (expira en 15 minutos, un solo uso):\n\n" +
			"Enlace: " + link + "\n"
		if mail.OTPPlain != "" {
			body += "Codigo: " + mail.OTPPlain + "\n"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
			VALUES (gen_random_uuid(),$1,'Verifica tu cuenta',$2,'pending')`,
			u.EmailOriginal, body); err != nil {
			return fmt.Errorf("insert verification email: %w", err)
		}
	}
	for _, e := range outbox {
		eid, perr := uuid.Parse(e.EventID)
		if perr != nil {
			return fmt.Errorf("invalid event id: %w", perr)
		}
		agg, perr := uuid.Parse(e.AggregateID)
		if perr != nil {
			return fmt.Errorf("invalid aggregate id: %w", perr)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO outbox
			(event_id, event_type, aggregate_id, topic, payload, status)
			VALUES ($1,$2,$3,$4,$5,'pending')`,
			eid, e.EventType, agg, e.Topic, string(e.PayloadJSON),
		); err != nil {
			return fmt.Errorf("insert outbox: %w", err)
		}
	}
	if requestID != "" {
		if rid, perr := uuid.Parse(requestID); perr == nil {
			_, _ = tx.Exec(ctx, `INSERT INTO idempotency_keys (request_id, response_hash, expires_at)
				VALUES ($1,'pending_verification', now() + INTERVAL '24 hours')
				ON CONFLICT (request_id) DO NOTHING`, rid)
		}
	}
	if reg != nil {
		if err := insertConsentsTx(ctx, tx, uid, u, *reg); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// insertConsentsTx escribe el ledger (terms+privacy) + evento legal en la Tx
// de alta. Comparte helper con federated_repository.go.
func insertConsentsTx(ctx context.Context, tx pgx.Tx, uid uuid.UUID, u *user.User, reg user.RegistrationContext) error {
	now := time.Now().UTC()
	for _, doc := range []string{"terms", "privacy"} {
		ver := u.TermsVersion
		if doc == "privacy" {
			ver = u.PrivacyVersion
		}
		if _, err := tx.Exec(ctx, `INSERT INTO consent_records
			(id, user_id, doc_type, version, accepted_at, ip_hash, ua_hash, source, request_id)
			VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8::uuid)
			ON CONFLICT (user_id, doc_type, version) DO NOTHING`,
			uid, doc, ver, now, reg.IPHash, reg.UAHash, reg.Source, reg.RequestID,
		); err != nil {
			return fmt.Errorf("insert consent %s: %w", doc, err)
		}
	}
	consentPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(),
		"consents": []any{
			map[string]string{"doc_type": "terms", "version": u.TermsVersion},
			map[string]string{"doc_type": "privacy", "version": u.PrivacyVersion},
		},
		"source": reg.Source, "ip_hash": "sha256:" + reg.IPHash, "request_id": reg.RequestID,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox
		(event_id, event_type, aggregate_id, topic, payload, status)
		VALUES (gen_random_uuid(),'legal.consent_recorded',$1,'auth.legal.v1',$2,'pending')`,
		uid, string(consentPayload),
	); err != nil {
		return fmt.Errorf("insert consent outbox: %w", err)
	}
	return nil
}

// Enqueue implementa service.OutboxEnqueuer para la rama shadow.
func (r *UserRepository) Enqueue(ctx context.Context, events []user.OutboxPayload) error {
	for _, e := range events {
		eid, err := uuid.Parse(e.EventID)
		if err != nil {
			continue
		}
		var agg any = uuid.Nil
		if a, err := uuid.Parse(e.AggregateID); err == nil {
			agg = a
		}
		_, _ = r.pool.Exec(ctx, `INSERT INTO outbox
			(event_id, event_type, aggregate_id, topic, payload, status)
			VALUES ($1,$2,$3,$4,$5,'pending')
			ON CONFLICT (event_id) DO NOTHING`,
			eid, e.EventType, agg, e.Topic, string(e.PayloadJSON),
		)
	}
	return nil
}
