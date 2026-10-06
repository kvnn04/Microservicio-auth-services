package user

import (
	"context"
)

// RegistrationContext atribución legal para la Tx de alta (CU-REG-05).
// El adapter inserta 2 ConsentRecords + evento legal.consent_recorded
// en la MISMA Tx que users/outbox. Sin consentimiento no hay cuenta.
type RegistrationContext struct {
	IPHash    string
	UAHash    string
	Source    string // "classic" | "federated_google"
	RequestID string
}

// UserRepository es el puerto de persistencia (implementa Postgres).
type UserRepository interface {
	FindByEmailNormalized(ctx context.Context, emailNormalized string) (*User, error)
	FindByID(ctx context.Context, id string) (*User, error)
	// CreateWithOutbox persiste usuario + eventos outbox + token verificación
	// + idempotency key en UNA transacción atómica (legado CU-REG-01, sin ledger).
	CreateWithOutbox(ctx context.Context, u *User, outbox []OutboxPayload, tokenHash string, requestID string) error
	// CreateWithConsents extiende CreateWithOutbox con ledger legal (CU-REG-05):
	// misma Tx + 2 consent_records + evento legal.consent_recorded.
	CreateWithConsents(ctx context.Context, u *User, outbox []OutboxPayload, tokenHash string, reg RegistrationContext) error
}

// OutboxPayload es el DTO de dominio para la fila outbox (sin imports infra).
type OutboxPayload struct {
	EventID     string
	EventType   string
	AggregateID string
	Topic       string
	PayloadJSON []byte
}
