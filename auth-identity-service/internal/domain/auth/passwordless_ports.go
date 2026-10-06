package auth

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrPlessThrottled: quota 60s/5-24h excedida → 202 genérico (sin oráculo).
	ErrPlessThrottled = errors.New("passwordless throttled")
	// ErrPlessInvalid: miss/expirado/consumido/quemado/superseded/no-ACTIVE →
	// 400 INVALID_OR_EXPIRED idéntico (sin 404/410, sin user_id).
	ErrPlessInvalid = errors.New("invalid or expired passwordless secret")
	// ErrPlessBurned: 3º fallo quema el secreto (exige start nuevo) → mismo 400.
	ErrPlessBurned = errors.New("passwordless secret burned after max attempts")
)

// PlessConsumeResult resume el consumo atómico (sin exponer secreto).
type PlessConsumeResult struct {
	UserID     string
	MFAEnabled bool
}

// PasswordlessStore puerto de persistencia (CU-AUTH-05 Q6).
// Implementación: Redis-verdad + Postgres-backup + outbox (igual CU-REG-02).
type PasswordlessStore interface {
	// Eligible resuelve ACTIVE (+mfa) sin revelar nada al cliente.
	// Inexistente/no-ACTIVE → eligible=false (uid "" salvo conocido).
	Eligible(ctx context.Context, normalizedEmail string) (userID string, mfaEnabled bool, eligible bool, err error)
	// QuotaCheck evalúa cooldown 60s + 5/24h por clave (uid o "anon:"+emailHash).
	// Excedida → (false, retry, nil): el servicio responde 202 genérico.
	QuotaCheck(ctx context.Context, key string) (allowed bool, retry time.Duration, err error)
	// Issue dual-write + supersede previo + outbox requested + email_queue.
	Issue(ctx context.Context, rec *PasswordlessRecord) error
	// FindAlive busca por hash (link u OTP). Miss/inactivo → ErrPlessInvalid.
	FindAlive(ctx context.Context, hash string) (*PasswordlessRecord, error)
	// ConsumeTx quema un solo uso en Tx atómica (+last_login, outbox consumed
	// y mismatch/email si risk=high). Carrera o no-ACTIVE → ErrPlessInvalid.
	// curIPHash/curUAHash son la huella de consumo (para mismatch forense).
	ConsumeTx(ctx context.Context, userID, hash, method, risk, curIPHash, curUAHash string) (*PlessConsumeResult, error)
	// IncrementAttempts suma un fallo; al 3º quema. Retorna burned.
	IncrementAttempts(ctx context.Context, hash string) (burned bool, err error)
}
