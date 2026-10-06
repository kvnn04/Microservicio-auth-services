package auth

import (
	"context"
	"time"

	"auth-identity-service/internal/domain/user"
)

// CredentialStore lookup de credenciales (adapta UserRepository).
type CredentialStore interface {
	FindForLogin(ctx context.Context, normalizedEmail string) (*user.User, error)
}

// AttemptTracker contadores/bloqueos/rate (Redis; fail-open si cae).
type AttemptTracker interface {
	// CheckLimits evalúa ip+cuenta por minuto; excede → ErrRateLimited (429).
	CheckLimits(ctx context.Context, ip, acctHash string) error
	// IsLocked indica bloqueo vigente de la llave (user_id o acct:hash).
	IsLocked(ctx context.Context, key string) (locked bool, err error)
	// RecordFail suma fallo; al umbral bloquea exponencial y pide email
	// (sendEmail=true solo 1º bloqueo/hora). Retorna lockedNow.
	RecordFail(ctx context.Context, key string) (lockedNow bool, sendEmail bool, err error)
	// ResetOnSuccess limpia fails/lock tras éxito.
	ResetOnSuccess(ctx context.Context, key string) error
}

// MFAPreTokenIssuer emite desafío MFA (aud=mfa-challenge, 5min, un challenge_id).
// Válido SOLO en POST /mfa/verify (CU-AUTH-02); negocio lo rechaza por aud.
type MFAPreTokenIssuer interface {
	IssueChallenge(ctx context.Context, userID string) (token string, challengeID string, expiresIn int, err error)
}

// PreTokenClaims pasaporte MFA (solo lo que verify necesita, sin secreto).
type PreTokenClaims struct {
	Sub         string
	ChallengeID string
	ExpiresAt   int64
}

// MFAPreTokenValidator valida firma+aud+exp del pre-token (CU-AUTH-02 lo usa;
// el middleware de negocio lo rechaza por aud).
type MFAPreTokenValidator interface {
	ValidateChallenge(token string) (PreTokenClaims, error)
}

// LoginDevice + LoginSession resumen lo que el Issuer necesita (sin secretos).
type LoginDevice struct {
	IPHash string
	UAHash string
}

// MFA constants re-exportadas para el adapter de pre-token.
const (
	MFAChallengeAUD = "mfa-challenge"
	MFAChallengeTTL = 5 * time.Minute
)
