package auth

import "time"

// Constantes CU-AUTH-06: fast-pass 5min (igual StepUpMaxAge de CU-REG-06)
// y token scopeado de un uso con TTL 5min.
const (
	StepUpMaxAge   = 5 * time.Minute
	StepUpTokenTTL = 5 * time.Minute
	StepUpAud      = "step-up"
)

// StepUpScope operación crítica que exige revalidación (lista cerrada RN-01).
type StepUpScope string

const (
	ScopeChangePassword  StepUpScope = "cred:change-password"
	ScopeChangeEmail     StepUpScope = "cred:change-email"
	ScopeMFADisable      StepUpScope = "mfa:disable"
	ScopeMFARotate       StepUpScope = "mfa:rotate"
	ScopeFederatedLink   StepUpScope = "federated:link"
	ScopeFederatedUnlink StepUpScope = "federated:unlink"
	ScopeBackupRegen     StepUpScope = "backup:regenerate"
	ScopeAPIKeysWrite    StepUpScope = "apikeys:write"
	ScopeAccountDelete   StepUpScope = "account:delete"
	ScopeRolesChange     StepUpScope = "roles:change"
)

// Valid indica si el scope pertenece a la lista cerrada (otro → 400).
func (s StepUpScope) Valid() bool {
	switch s {
	case ScopeChangePassword, ScopeChangeEmail,
		ScopeMFADisable, ScopeMFARotate,
		ScopeFederatedLink, ScopeFederatedUnlink,
		ScopeBackupRegen, ScopeAPIKeysWrite,
		ScopeAccountDelete, ScopeRolesChange:
		return true
	}
	return false
}

// StepUpDecision desenlace del guard ante una op crítica.
type StepUpDecision string

const (
	StepUpFastPass         StepUpDecision = "fast_pass"
	StepUpRequireChallenge StepUpDecision = "require_challenge"
	StepUpRequireRelogin   StepUpDecision = "require_relogin"
)

// DecideStepUp: fresco (≤5min) → FastPass; stale con factores locales →
// Challenge; stale federated-only sin nada local → Relogin (re-login IdP).
func DecideStepUp(authTime, now time.Time, hasLocalFactors bool) StepUpDecision {
	if !authTime.IsZero() && !now.UTC().After(authTime.UTC().Add(StepUpMaxAge)) {
		return StepUpFastPass
	}
	if hasLocalFactors {
		return StepUpRequireChallenge
	}
	return StepUpRequireRelogin
}

// StepUpClaims payload del step_up_token (Ed25519, aud aislado).
// Sin PII: sub UUID, scope y jti. Nunca roles ni ampliación de permisos.
type StepUpClaims struct {
	Iss      string   `json:"iss"`
	Aud      string   `json:"aud"`
	Sub      string   `json:"sub"`
	JTI      string   `json:"jti"`
	Scope    string   `json:"scope"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
}
