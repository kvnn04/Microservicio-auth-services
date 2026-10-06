package auth

import (
	"context"
	"errors"
)

var (
	// ErrGlobalUserNotFound el usuario del Bearer ya no existe (borrado).
	// A diferencia del miss de sesión individual (Already 200), aquí no hay
	// nada que cortar y el llamante es inválido → el servicio lo traduce a
	// 401 base (sin distinguir causa, anti-enumeración).
	ErrGlobalUserNotFound = errors.New("global logout user not found")
)

// GlobalSessionRevoker puerto de revocación masiva (CU-SES-02 T-02).
// Implementación: Tx única PG (valid_after + families + sessions + outbox
// revoked_all + audit + email) + sweep Redis post-commit + PUBLISH.
// Redis down → PG verdad + WARN + igual 200 (reconciliador/worker).
// PG down → ErrSessionInfra (el handler NO envía Clear-Cookie).
// Reason del corte siempre "user_request" (SES-04 invocará el mismo efecto
// con audit "reuse_detected" — punto de extensión documentado).
type GlobalSessionRevoker interface {
	// RevokeAll corta TODO del usuario (incluida la sesión llamante).
	// Siempre bumpea valid_after (incluso repeat con 0/0 — harmless).
	// ip alimenta el email de alerta (hora/IP); nunca va a logs/eventos.
	RevokeAll(ctx context.Context, userID, ip string) (GlobalRevokeResult, error)
}

// GlobalLogoutMetrics telemetría CU-SES-02 (T-05). Sin SDK directo (DIP).
type GlobalLogoutMetrics interface {
	IncGlobal(result string)
	ObserveGlobalDuration(seconds float64)
	ObserveSessionsRevoked(n int)
}

// Nota: verificación de entrada y rate-limit reusan los puertos de SES-01
// (auth.LogoutVerifier: firma+exp sin denylist/valid_after para entrar;
// auth.LogoutLimiter: Allow genérico). Sin duplicarlos aquí (ISP).
