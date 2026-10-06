package user

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrEmailChangeInvalid: miss/expirado/consumido/quemado/superseded →
	// 400 INVALID_OR_EXPIRED idéntico (sin 404/410).
	ErrEmailChangeInvalid = errors.New("invalid or expired email change secret")
	// ErrEmailChangeBurned: 3º abuso quema el secreto (exige start nuevo).
	ErrEmailChangeBurned = errors.New("email change secret burned after max attempts")
)

// EmailChangeStore puerto de persistencia (CU-CRED-03 Q3/Q6).
// Implementación: Redis-verdad + Postgres-backup + outbox + doble-mail.
type EmailChangeStore interface {
	// QuotaCheck evalúa cooldown 60s + 5/24h por uid (solo lectura).
	QuotaCheck(ctx context.Context, userID string) (allowed bool, retry time.Duration, err error)
	// Taken indica si el email lo ocupa OTRA cuenta (true) u otra causa.
	// Devuelve (takenByOther bool). El propio requester con pendiente no bloquea.
	Taken(ctx context.Context, newNormalized, requesterID string) (takenByOther bool, err error)
	// Issue dual-write + supersede previo + outbox requested + doble-mail
	// (confirmación al nuevo con link, aviso al viejo sin token).
	Issue(ctx context.Context, rec *EmailChangeRecord) error
	// FindAlive busca por hash. Miss/inactivo → ErrEmailChangeInvalid.
	FindAlive(ctx context.Context, hash string) (*EmailChangeRecord, error)
	// ConfirmTx aplica el cambio en Tx atómica: re-UNIQUE del nuevo (race →
	// ErrEmailAlreadyInUse + quema el token), UPDATE users (nuevo + verified
	// implícito + valid_after) + token consumed + supersede resto + revoke
	// families/sessions TODAS + outbox + email al nuevo. Sin auto-login.
	ConfirmTx(ctx context.Context, hash string) (requesterID, newNormalized string, err error)
	// IncrementAttempts suma un abuso; al 3º quema. Retorna burned.
	IncrementAttempts(ctx context.Context, hash string) (burned bool, err error)
}
