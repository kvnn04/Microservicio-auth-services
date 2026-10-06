package auth

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrRefreshNotFound hash desconocido (nunca existió o purgado):
	// 401 INVALID_REFRESH opaco, sin alarma (sin family que acusar).
	ErrRefreshNotFound = errors.New("refresh not found")
	// ErrRefreshExpired absolute o sliding pasado: 401 SESSION_EXPIRED,
	// front re-loguea (marca revoked best-effort, sin alarma).
	ErrRefreshExpired = errors.New("refresh expired")
	// ErrRefreshRevoked family muerta por logout: 401 FAMILY_REVOKED,
	// front re-loguea (sin alarma robo — ya estaba muerta).
	ErrRefreshRevoked = errors.New("refresh family revoked")
	// ErrRefreshConcurrent race legítima paralela: 409 reintentable con
	// algoritmo cliente (re-lee jar). Sin alarma.
	ErrRefreshConcurrent = errors.New("concurrent rotation")
	// ErrRefreshCompromised reuso fuera de gracia: robo → GLOBAL + P1 +
	// email crítico; front muestra login + banner. 401 explícito a propósito.
	ErrRefreshCompromised = errors.New("refresh reuse detected")
)

// FamilyState foto de la cadena para decidir (del Lookup + Tx fresca).
type FamilyState struct {
	Family        string
	UserID        string
	SID           string
	CurrentHash   string
	ParentHash    string
	Counter       int
	AbsoluteExp   time.Time
	Revoked       bool
	RotatedAt     time.Time
	DeviceHash    string
	Email         string
	// Contexto de emisión (para re-firmar preservando auth_time/amr/roles).
	AuthTime time.Time
	AMR      []string
	Roles    []string
	RolesVer int
}

// RotationLookup resultado del lookup por hash (decisión pre-Tx).
type RotationLookup struct {
	State            FamilyState
	PresentedHash    string
	SlidingExp       time.Time // expires_at del hash PRESENTADO
	CounterPresented int       // counter del hash presentado (evento reuse)
	IsCurrent        bool
	IsParent         bool
}

// RotatedPair par emitido (para respuesta + idempotencia RequestID 60s).
// El Refresh PLANO solo vive aquí y en el idem-key 60s (excepción
// documentada); en DB/logs/eventos solo su hash.
type RotatedPair struct {
	AccessJWT  string
	Refresh    string
	ExpiresAt  time.Time
	SID        string
	Family     string
	JTI        string
	Counter    int
}

// RotateCASInput entrada a la rotación atómica (par ya generado por el
// servicio con Signer/Generator; el store persiste + cache + outbox).
// PresentedFP refresca families.device_hash (misma huella que el Issue).
type RotateCASInput struct {
	State       FamilyState // foto pre-Tx (revalidada FOR UPDATE dentro)
	OldHash     string
	NewPair     RotatedPair
	NewHash     string
	SlidingTo   time.Time
	PresentedFP string
}

// ReuseGlobalInput evidencia del robo (tras el corte SES-02 aplicado).
type ReuseGlobalInput struct {
	State            FamilyState
	PresentedHash    string
	PresentedDevice  string
	PresentedAt      time.Time
	IP               string
	CounterPresented int
}

// RotationStore puerto de rotación (CU-SES-04 T-02). Implementación:
// Tx PG (CAS + hashes + sessions + denylist + outbox) + espejo Redis +
// idempotency/flaps en Redis. Redis down → PG verdad + WARN (gracia
// idempotente degradada a 409, documentado).
type RotationStore interface {
	// Lookup resuelve hash→family+estado (lectura con JOIN; miss→NotFound).
	Lookup(ctx context.Context, refreshHash string) (RotationLookup, error)
	// RotateCAS persiste la rotación si current==old (CAS). Si la Tx fresca
	// ve otro current → ErrRefreshConcurrent; si ve revoked → ErrRefreshRevoked.
	RotateCAS(ctx context.Context, in RotateCASInput) (RotatedPair, error)
	// ExpireFamily marca revoked best-effort (sliding/absolute pasado).
	ExpireFamily(ctx context.Context, family string) error
	// IncrFlaps cuenta eventos concurrentes con el viejo (EX 10s).
	IncrFlaps(ctx context.Context, oldHash string) (int64, error)
	// ReuseGlobal ejecuta corte SES-02 + evidencia reuse (P1 + email crítico).
	ReuseGlobal(ctx context.Context, in ReuseGlobalInput) (GlobalRevokeResult, error)
}

// HashPrefix8 para logs/eventos (nunca el hash completo, nunca el plano).
func HashPrefix8(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// RotationMetrics telemetría CU-SES-04 (T-05). Sin SDK directo (DIP).
// reuse_detected_total es la señal P1 (el pager/ops alerta sobre ella);
// concurrent_409_total cuenta races legítimos (ruido vs robo).
type RotationMetrics interface {
	IncRotation(result string)
	ObserveRotationDuration(seconds float64)
	IncReuseDetected()
	IncConcurrent()
}
