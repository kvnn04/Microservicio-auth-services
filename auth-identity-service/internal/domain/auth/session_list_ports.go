package auth

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrUseLogout el objetivo es la sesión actual: debe cerrarse por
	// POST /logout (contrato explícito), no por bisturí → 400 USE_LOGOUT.
	ErrUseLogout = errors.New("use logout for current session")
	// ErrSessionNotFound objetivo ajeno/inexistente/muerto: 404 único
	// idéntico (supuesto Q4 confirmado: no distingue causa, +jitter).
	ErrSessionNotFound = errors.New("session not found")
)

// SessionLister puerto de lectura y bisturí (CU-SES-03 T-02).
// Implementación: PG verdad ordenada + fast-path Redis all-or-nothing.
type SessionLister interface {
	// List devuelve las sesiones vivas del usuario ordenadas por
	// last_seen DESC (PG verdad; Redis solo si trae el set completo).
	List(ctx context.Context, userID string) ([]SessionView, error)
	// RevokeOne mata la sesión objetivo (triple-capa + outbox + email).
	// target==current → ErrUseLogout (sin tocar nada); miss → ErrNotFound.
	RevokeOne(ctx context.Context, userID, currentSID, targetSID string) (RevokedOne, error)
}

// RevokedOne resultado del bisturí (para audit/email/DTO).
type RevokedOne struct {
	SID         string
	DeviceLabel string
	IPMasked    string
}

// SessionToucher actualiza last_seen best-effort con debounce (supuesto Q5
// confirmado: sin heartbeat; Issue+Rotate escriben, touch solo refresca).
// Implementación: debounce Redis touch:<sid> EX 5min + UPDATE PG + espejo
// Redis. Errores se tragan (WARN) sin bloquear la respuesta.
type SessionToucher interface {
	Touch(ctx context.Context, userID, sid string, now time.Time) error
}

// SessionsMetrics telemetría CU-SES-03 (T-05). Sin SDK directo (DIP).
type SessionsMetrics interface {
	IncListed(result string)
	ObserveListDuration(seconds float64)
	IncRevokedOne(result string)
	ObserveRevokeOneDuration(seconds float64)
}

// Reuso SES-01: verifier tolerante (firma+exp) y limiter genérico.
