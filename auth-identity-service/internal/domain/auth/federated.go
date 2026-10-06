package auth

import (
	"errors"
	"time"
)

// Constantes CU-REG-04 (Q2/Q7): state/nonce 32B, verifier 64B, state TTL 10min.
const (
	FederatedStateBytes    = 32
	FederatedNonceBytes    = 32
	FederatedVerifierBytes = 64
	FederatedStateTTL      = 10 * time.Minute
	FederatedCodeTTL       = 10 * time.Minute
)

var (
	ErrInvalidState = errors.New("invalid federated state")
	ErrInvalidCode  = errors.New("invalid federated code")
	ErrInvalidToken = errors.New("invalid id token")
	ErrIDPUnavailable = errors.New("identity provider unavailable")
	ErrLinkRequired = errors.New("account link required")
	ErrProviderNotSupported = errors.New("provider not supported")
	ErrFederatedCancelled = errors.New("federated login cancelled")
	ErrTermsRequired = errors.New("terms acceptance required")
	ErrUseLinkFlow = errors.New("use account linking flow")
	ErrAccountUnavailable = errors.New("account unavailable")
	ErrIDPEmailMissing = errors.New("idp email missing")
)

// OIDClaims subconjunto OIDC validado (nunca tokens crudos en dominio).
type OIDClaims struct {
	Sub           string
	Email         string
	EmailVerified *bool
	Nonce         string
	Iss           string
	Aud           string
	Exp           int64
	Iat           int64
}

// IsVerified exige bool estricto true (RN-02: "true" string/null/ausente → false).
func (c *OIDClaims) IsVerified() bool {
	return c != nil && c.EmailVerified != nil && *c.EmailVerified
}
