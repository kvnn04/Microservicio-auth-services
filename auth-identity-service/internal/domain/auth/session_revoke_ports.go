package auth

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrLogoutNotFound sesión/family ya muerta → 200 already_logged_out
	// (idempotencia §4.2, nunca 404 ni 401 aquí).
	ErrLogoutNotFound = errors.New("session not found")
	// ErrLogoutUnauthorized Bearer inválido/expirado o sin identificador
	// (sin Bearer y sin refresh-alt, §4.1/4.5) → 401 UNAUTHORIZED.
	ErrLogoutUnauthorized = errors.New("logout unauthorized")
)

// RevokedSession salida del Revoker (PG verdad + Redis best-effort).
// Identity va resuelta (con Family) para audit/métricas sin PII extra.
type RevokedSession struct {
	Result   LogoutResult
	Identity LogoutIdentity
}

// SessionRevoker puerto de revocación individual (CU-SES-01 T-02).
// Implementación: Tx PG + write-through Redis + outbox (postgres
// CombinedSessionRevoker). Redis down → PG verdad + WARN, igual 200.
// PG down → ErrSessionInfra (el handler NO envía Clear-Cookie).
type SessionRevoker interface {
	// RevokeSID revoca family+sess+jti del sid del Bearer.
	// Miss (0 filas) → {AlreadyLoggedOut} + ErrLogoutNotFound envuelto?
	// Vinculante: retorna Already SIN error para idempotencia 200;
	// solo PG down retorna ErrSessionInfra.
	RevokeSID(ctx context.Context, id LogoutIdentity) (RevokedSession, error)
	// RevokeByRefreshHash localiza family→sid vía hash SHA-256 hex del
	// refresh plano y revoca igual. Hash desconocido → Already (200,
	// sin oráculo). Formato inválido lo rechaza el servicio con 401
	// antes de llamar (aquí solo hashes hex 64ch).
	RevokeByRefreshHash(ctx context.Context, refreshHash string) (RevokedSession, error)
}

// LogoutVerifier verifica firma/kid/iss/aud/exp del Bearer (tolerante a
// revocado: NO chequea denylist ni valid_after aquí — la idempotencia
// exige verificar firma aunque el jti esté denylisteado).
// Implementación: *security.Ed25519Signer (misma JWKS/kid, aud=api).
type LogoutVerifier interface {
	Verify(token string) (AccessClaims, error)
}

// LogoutLimiter rate-check logout:user 30/min + logout:ip 60/min.
// Implementación: *redis.RateLimiter (Allow con misma firma).
type LogoutLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error)
}

// LogoutMetrics telemetría CU-SES-01 (T-05). Sin SDK directo (DIP).
type LogoutMetrics interface {
	IncLogout(result string)
	ObserveLogoutDuration(seconds float64)
	SetDenylistSize(n float64)
}
