package auth

import (
	"context"
	"errors"
	"time"

	"auth-identity-service/internal/domain/user"
)

var (
	// ErrPwdResetThrottled: quota 60s/5-24h excedida → 202 genérico (sin oráculo).
	ErrPwdResetThrottled = errors.New("password reset throttled")
	// ErrPwdResetInvalid: miss/expirado/consumido/quemado/superseded/no-ACTIVE →
	// 400 INVALID_OR_EXPIRED idéntico (sin 404/410, sin user_id).
	ErrPwdResetInvalid = errors.New("invalid or expired reset secret")
	// ErrPwdResetBurned: 3º abuso quema el secreto (exige start nuevo) → mismo 400.
	ErrPwdResetBurned = errors.New("reset secret burned after max attempts")
	// ErrPasswordReused: nueva == actual (Verify true) → 400 PASSWORD_REUSED.
	// Solo visible para quien posee el link (posesión del correo probada).
	ErrPasswordReused = errors.New("new password equals current password")
)

// PasswordResetStore puerto de persistencia (CU-CRED-01 Q6).
// Implementación: Redis-verdad + Postgres-backup + outbox (igual verify/pless).
type PasswordResetStore interface {
	// EligibleForReset resuelve elegibilidad sin revelar nada al cliente:
	// ACTIVE + hash → eligible; ACTIVE federated-only sin hash → hint;
	// resto/inexistente → ambos false.
	EligibleForReset(ctx context.Context, normalizedEmail string) (userID string, eligible bool, federatedHint bool, err error)
	// QuotaCheck evalúa cooldown 60s + 5/24h por clave (uid o "anon:"+emailHash).
	QuotaCheck(ctx context.Context, key string) (allowed bool, retry time.Duration, err error)
	// Issue dual-write + supersede previo + outbox requested + email_queue.
	Issue(ctx context.Context, rec *PasswordResetRecord) error
	// IssueHint encola aviso alternativo federated-only (sin link).
	IssueHint(ctx context.Context, userID, email string) error
	// FindAlive busca por hash. Miss/inactivo → ErrPwdResetInvalid.
	// Retorna también el usuario (hash actual + ACTIVE recheck en confirm).
	FindAlive(ctx context.Context, hash string) (*PasswordResetRecord, *user.User, error)
	// ConsumeTx cambia la clave y corta todo en Tx atómica: re-verifica
	// ≠old (TOCTOU), UPDATE users(hash, valid_after) + token consumed +
	// supersede resto + revoke families/sessions + outbox + emails.
	// Carrera/no-ACTIVE → ErrPwdResetInvalid.
	ConsumeTx(ctx context.Context, userID, hash, newHash, risk, curIPHash, curUAHash, requestID string) error
	// IncrementAttempts suma un abuso; al 3º quema. Retorna burned.
	IncrementAttempts(ctx context.Context, hash string) (burned bool, err error)
}
