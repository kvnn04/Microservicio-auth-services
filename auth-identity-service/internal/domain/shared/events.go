package shared

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidInput = errors.New("invalid input")
	ErrInfraFailure = errors.New("infrastructure failure")
)

// Event sobre unificado de integración.
type Event struct {
	EventID    string
	EventType  string
	OccurredAt time.Time
	Key        string
	Topic      string
	Payload    any
}

// OutboxEvent fila pendiente en tabla outbox.
type OutboxEvent struct {
	EventID     string
	EventType   string
	AggregateID string
	Topic       string
	PayloadJSON []byte
	CreatedAt   time.Time
}

// EventPublisher puerto de mensajería (Kafka vía outbox+worker).
type EventPublisher interface {
	Publish(ctx context.Context, e Event) error
}

// AuditLogger auditoría inmutable (solo hashes, jamás PII/plano).
type AuditLogger interface {
	Log(ctx context.Context, action string, fields map[string]string) error
}

// IdempotencyStore guarda respuestas por X-Request-ID (TTL 24h).
type IdempotencyStore interface {
	Get(ctx context.Context, requestID string) (responseHash string, found bool, err error)
	Put(ctx context.Context, requestID, responseHash string, ttl time.Duration) error
}
