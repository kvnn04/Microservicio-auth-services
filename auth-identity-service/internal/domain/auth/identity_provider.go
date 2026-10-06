package auth

import (
	"context"

	"auth-identity-service/internal/domain/user"
)

// AuthorizeReq entrada para construir la URL del IdP.
type AuthorizeReq struct {
	Provider    user.Provider
	RedirectURI string
	Scopes      []string
	ReturnTo    string
}

// AuthURL resultado de authorize (sin secretos: el verifier viaja aparte).
type AuthURL struct {
	URL   string
	State string
	Nonce string
}

// TokenSet par canjeado. AccessToken vive solo en memoria del request (SEC-02).
type TokenSet struct {
	IDToken     string
	AccessToken string
}

// IdentityProviderClient puerto IdP (CU-REG-04 Q7). Implementa OIDC + PKCE.
type IdentityProviderClient interface {
	// BuildAuthorizeURL genera state/nonce/verifier y la URL del IdP.
	BuildAuthorizeURL(ctx context.Context, req AuthorizeReq) (authURL AuthURL, verifier string, err error)
	// ExchangeCode canjea code+verifier (timeout 5s+1retry en adapter).
	ExchangeCode(ctx context.Context, provider user.Provider, code, verifier, redirectURI string) (TokenSet, error)
	// VerifyIDToken valida firma JWKS + claims + nonce (ConstantTime).
	VerifyIDToken(ctx context.Context, provider user.Provider, idToken, expectedNonce string) (OIDClaims, error)
}

// FederatedState representa el estado CSRF/PKCE guardado (Redis EX 600, un uso).
// CU-REG-05: porta además las versiones legales aceptadas en authorize para
// revalidarlas en callback (exact match en creación).
type FederatedState struct {
	Nonce          string
	Verifier       string
	IPHash         string
	ReturnTo       string
	CreatedAt      int64
	TermsVersion   string
	PrivacyVersion string
}

// FederatedStateStore puerto de estado (fail-closed si cae, §4.3).
type FederatedStateStore interface {
	SaveState(ctx context.Context, state string, st FederatedState) error
	// ConsumeState GET+DEL atómico; ErrNotFound → 400 invalid_state.
	ConsumeState(ctx context.Context, state string) (FederatedState, error)
}

// NOTE CU-AUTH-04: el puerto de emisión vive en token_ports.go
// (SessionIssuer con SessionRequest → IssuedPair, implementado en
// internal/service/issue_session.go). Se mantiene aquí solo el alias
// legacy para compatibilidad de tests en transición.
type LegacySessionIssuer interface {
	Issue(ctx context.Context, userID string) (accessToken string, refreshTokenID string, expiresAt int64, err error)
}
