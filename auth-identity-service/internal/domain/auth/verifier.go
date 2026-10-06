package auth

import (
	"context"
	"time"
)

// VerificationStore es el puerto de verificación (CU-REG-02).
// Implementación: Redis-como-verdad + Postgres-backup (failover automático).
type VerificationStore interface {
	// FindAlive busca un registro vigente por hash (token u OTP).
	// Retorna ErrNotFound si no existe, expiró, consumido, superseded o quemado.
	FindAlive(ctx context.Context, hash string) (*VerificationRecord, error)
	// ConsumeAtomically activa el usuario y quema el secreto en Tx atómica.
	// Retorna el usuario activado o ErrInvalidOrExpired (carrera/consumido).
	ConsumeAtomically(ctx context.Context, userID, hash, method string) (*ConsumedUser, error)
	// Register persiste un par nuevo (dual-write) supersediendo el anterior.
	Register(ctx context.Context, rec *VerificationRecord) error
	// IncrementAttempts suma un intento; burned=true al llegar a MaxAttempts.
	IncrementAttempts(ctx context.Context, hash string) (left int, burned bool, err error)
	// ResendQuotaCheck evalúa cooldown 60s + cuota 5/24h.
	ResendQuotaCheck(ctx context.Context, userID string) (allowed bool, retryAfter time.Duration, err error)
	// WasActivatedBy indica si hash fue el activador (idempotencia already_verified).
	WasActivatedBy(ctx context.Context, hash string) (userID string, ok bool, err error)
}

// ConsumedUser resume el usuario tras activación (sin exponer PII al servicio).
type ConsumedUser struct {
	UserID      string
	EmailHash   string
	EmailDomain string
	Method      string
}
