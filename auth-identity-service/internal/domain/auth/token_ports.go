package auth

import (
	"context"
	"errors"
	"time"

	"auth-identity-service/internal/domain/user"
)

var (
	// ErrNoKey: sin clave Ed25519 activa (fail-fast al arrancar + 500 si
	// rota en caliente sin clave). Nunca emitir sin firmar, nunca none/HMAC.
	ErrNoKey = errors.New("no signing key available")
	// ErrSessionInfra: PG/Redis/KMS caídos (el servicio decide 500 sin
	// entregar JWT huérfano, o degradar a PG si solo cae Redis).
	ErrSessionInfra = errors.New("session infrastructure failure")
	// ErrSessionConflict: colisión sid/family/jti/hash (reintentar 1 vez).
	ErrSessionConflict = errors.New("session id collision")
)

// AccessSigner firma Access JWT Ed25519 (adapter/security).
// claims ya validados por el dominio; el signer añade header kid/alg.
type AccessSigner interface {
	Sign(ctx context.Context, claims AccessClaims) (jwt string, kid string, err error)
	// KID actual (para métricas/tracing sin exponer privada).
	ActiveKID() string
}

// RefreshGenerator genera Refresh opaco 32B + hash (adapter/security).
// plain 43ch base64url; hash hex(SHA-256(plain)) único global.
type RefreshGenerator interface {
	Generate(ctx context.Context) (plain string, hash string, err error)
	Hash(plain string) string
}

// SessionStore persistencia transaccional (PG verdad).
// Create es atómico: sessions + families + hashes + outbox + LRU.
// Si COUNT>=MaxSessionsPerUser evicta la más vieja (last_seen) y retorna
// su SID; outbox incluye session.issued (+ session.evicted si hubo).
type SessionStore interface {
	Create(ctx context.Context, sess Session, fam RefreshFamily, h RefreshHash, evt user.OutboxPayload, evictEvt *user.OutboxPayload) (evictedSID string, err error)
}

// SessionCache espejo rápido (Redis). Best-effort post-commit:
// Save escribe sess/fam/jti con EX; LoadRehydrate rehidrata tras caída.
// Error de caché NUNCA bloquea la entrega (el servicio cuenta fallback).
type SessionCache interface {
	Save(ctx context.Context, sess Session, fam RefreshFamily, jti string) error
}

// SessionIssuer puerto interno ÚNICO que firma Access y crea families.
// Lo invocan Login/MFAVerify/RegisterFederated (y futuro refresh en SES-04
// vía Rotate, aquí solo Issue crea family). Sin HTTP aquí.
type SessionIssuer interface {
	Issue(ctx context.Context, req SessionRequest) (IssuedPair, error)
}

// SessionIssueMetrics telemetría CU-AUTH-04 (T-05). Sin SDK directo.
type SessionIssueMetrics interface {
	IncIssued(method, amr string)
	ObserveIssueDuration(seconds float64)
	IncEvicted(reason string)
	IncRedisFallback()
	IncInfraError(op string)
}

// SessionAudit evento mínimo (el servicio lo traduce a AuditLogger/outbox).
type SessionAudit struct {
	UserID     string
	SID        string
	Family     string
	JTI        string
	KID        string
	Method     string
	AMR        []string
	DeviceHash string
	TraceID    string
	OccurredAt time.Time
}
