package auth

import (
	"errors"
	"time"
)

// Constantes CU-SES-01: estados de salida + TTL denylist.
// Access 15min (CU-AUTH-04); la denylist jti vive hasta exp natural.
const (
	// LogoutUserLimit 30/min por usuario (Q5, §2).
	LogoutUserLimit = 30
	// LogoutIPLimit 60/min por IP (Q5, §2).
	LogoutIPLimit = 60
	// LogoutRateWindow ventana de rate-limit.
	LogoutRateWindow = time.Minute
	// LogoutBodyMax 4KB (contracts §1, body ignorado salvo refresh-alt).
	LogoutBodyMax = 4 << 10
	// LogoutRefreshPath Path de la cookie refresh (MISMO que Issue, RN-05).
	LogoutRefreshPath = "/api/v1/auth/refresh"
)

// LogoutResult desenlace del logout (200 en ambos, idempotente).
type LogoutResult string

const (
	// LogoutLoggedOut revocado ahora (triple-capa: family+sess+jti).
	LogoutLoggedOut LogoutResult = "logged_out"
	// LogoutAlreadyLoggedOut ya estaba muerto (revocado/evicted/SES-02/03).
	LogoutAlreadyLoggedOut LogoutResult = "already_logged_out"
)

// LogoutIdentity identifica el par a matar (del Bearer o del Refresh-alt).
// Family se resuelve en persistencia (vacía en el request, llena en out).
type LogoutIdentity struct {
	UserID    string
	SID       string
	JTI       string
	Family    string
	ExpiresAt time.Time
}

var ErrInvalidLogoutIdentity = errors.New("invalid logout identity")

// Validate forma pura (presencia de sub/sid/jti; exp la exige el verifier).
func (id LogoutIdentity) Validate() error {
	if id.UserID == "" || id.SID == "" || id.JTI == "" {
		return ErrInvalidLogoutIdentity
	}
	if id.ExpiresAt.IsZero() {
		return ErrInvalidLogoutIdentity
	}
	return nil
}

// DenylistTTL calcula EX=max(1, exp-now) clamp 1s..15min (RN-03).
// Si ya expiró (el servicio lo rechaza con 401 antes), devuelve 1s
// para no escribir TTL 0 en Redis.
func DenylistTTL(expiresAt, now time.Time) time.Duration {
	rest := expiresAt.Sub(now.UTC())
	if rest <= 0 {
		return time.Second
	}
	if rest > AccessTTL {
		return AccessTTL
	}
	if rest < time.Second {
		return time.Second
	}
	return rest
}
