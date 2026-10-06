package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
)

// GoogleOIDCClient implementa auth.IdentityProviderClient (OIDC Code + PKCE).
// Endpoints configurables para apuntar a un fake-IdP en tests/E2E.
// Discovery cache 24h, JWKS cache 1h (10min ante rotación: refresh en kid-miss).
type GoogleOIDCClient struct {
	issuer         string
	clientID       string
	clientSecret   string
	redirectURI    string
	discoveryURL   string
	tokenURL       string
	jwksURL        string
	authEndpoint   string
	allowedIssuers []string
	http           *http.Client

	mu            sync.RWMutex
	discoveryExp  time.Time
	jwks          map[string]any // kid → *rsa.PublicKey | *ecdsa.PublicKey
	jwksFetchedAt time.Time
}

func NewGoogleOIDCClient(issuer, clientID, clientSecret, redirectURI, discoveryURL, tokenURL, jwksURL string) *GoogleOIDCClient {
	if issuer == "" {
		issuer = "https://accounts.google.com"
	}
	if discoveryURL == "" {
		discoveryURL = strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	}
	return &GoogleOIDCClient{
		issuer: issuer, clientID: clientID, clientSecret: clientSecret,
		redirectURI: redirectURI, discoveryURL: discoveryURL,
		tokenURL: tokenURL, jwksURL: jwksURL,
		allowedIssuers: []string{issuer, strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")},
		http:           &http.Client{Timeout: 5 * time.Second},
		jwks:           map[string]any{},
	}
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// BuildAuthorizeURL genera state/nonce/verifier CSPRNG + URL con PKCE S256.
func (c *GoogleOIDCClient) BuildAuthorizeURL(ctx context.Context, req auth.AuthorizeReq) (auth.AuthURL, string, error) {
	state, err := randHex(auth.FederatedStateBytes)
	if err != nil {
		return auth.AuthURL{}, "", err
	}
	nonce, err := randHex(auth.FederatedNonceBytes)
	if err != nil {
		return auth.AuthURL{}, "", err
	}
	vb := make([]byte, auth.FederatedVerifierBytes)
	if _, err := rand.Read(vb); err != nil {
		return auth.AuthURL{}, "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(vb)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	endpoint, err := c.AuthEndpoint(ctx)
	if err != nil {
		return auth.AuthURL{}, "", err
	}
	q := url.Values{}
	q.Set("client_id", c.clientID)
	// redirect_uri exacta por flujo (SEC-01): link usa .../link/callback,
	// distinta de la anónima. El request la fija; default la del cliente.
	redirectURI := c.redirectURI
	if req.RedirectURI != "" {
		redirectURI = req.RedirectURI
	}
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(req.Scopes, " "))
	if len(req.Scopes) == 0 {
		q.Set("scope", "openid email profile")
	}
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return auth.AuthURL{URL: endpoint + "?" + q.Encode(), State: state, Nonce: nonce}, verifier, nil
}

func (c *GoogleOIDCClient) AuthEndpoint(ctx context.Context) (string, error) {
	c.mu.RLock()
	if c.authEndpoint != "" && time.Now().Before(c.discoveryExp) {
		ep := c.authEndpoint
		c.mu.RUnlock()
		return ep, nil
	}
	c.mu.RUnlock()
	if err := c.refreshDiscovery(ctx); err != nil {
		// Fallback Google conocido si hay discovery configurado de Google.
		if c.authEndpoint != "" {
			return c.authEndpoint, nil
		}
		return "", err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authEndpoint, nil
}

func (c *GoogleOIDCClient) refreshDiscovery(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	var d struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &d); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if d.AuthorizationEndpoint != "" {
		c.authEndpoint = d.AuthorizationEndpoint
	} else if c.authEndpoint == "" {
		c.authEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	}
	if c.tokenURL == "" {
		c.tokenURL = d.TokenEndpoint
	}
	if c.jwksURL == "" {
		c.jwksURL = d.JwksURI
	}
	c.discoveryExp = time.Now().Add(24 * time.Hour)
	return nil
}

// ExchangeCode canjea code+PKCE (timeout 5s, 1 reintento en red/5xx).
func (c *GoogleOIDCClient) ExchangeCode(ctx context.Context, _ user.Provider, code, verifier, redirectURI string) (auth.TokenSet, error) {
	if c.tokenURL == "" {
		if err := c.refreshDiscovery(ctx); err != nil || c.tokenURL == "" {
			return auth.TokenSet{}, auth.ErrIDPUnavailable
		}
	}
	if redirectURI == "" {
		redirectURI = c.redirectURI
	}
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", verifier)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return auth.TokenSet{}, auth.ErrIDPUnavailable
			case <-time.After(500 * time.Millisecond):
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue // red: reintenta una vez.
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("token status %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode >= 400 {
			return auth.TokenSet{}, auth.ErrInvalidCode
		}
		var t struct {
			IDToken     string `json:"id_token"`
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(body, &t); err != nil || t.IDToken == "" {
			return auth.TokenSet{}, auth.ErrInvalidCode
		}
		return auth.TokenSet{IDToken: t.IDToken, AccessToken: t.AccessToken}, nil
	}
	_ = lastErr
	return auth.TokenSet{}, auth.ErrIDPUnavailable
}

// VerifyIDToken valida firma JWKS (allowlist alg) + iss/aud/exp/iat/nonce/sub.
func (c *GoogleOIDCClient) VerifyIDToken(ctx context.Context, _ user.Provider, idToken, expectedNonce string) (auth.OIDClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	// Allowlist alg: RS256/ES256. Nunca none ni HS*.
	if header.Alg != "RS256" && header.Alg != "ES256" {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	if header.Kid == "" {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	key, err := c.keyForKid(ctx, header.Kid)
	if err != nil {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	digest := sha256.Sum256([]byte(signingInput))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if header.Alg != "RS256" {
			return auth.OIDClaims{}, auth.ErrInvalidToken
		}
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return auth.OIDClaims{}, auth.ErrInvalidToken
		}
	case *ecdsa.PublicKey:
		if header.Alg != "ES256" {
			return auth.OIDClaims{}, auth.ErrInvalidToken
		}
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return auth.OIDClaims{}, auth.ErrInvalidToken
		}
	default:
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	var claims struct {
		Sub           string      `json:"sub"`
		Email         string      `json:"email"`
		EmailVerified *bool       `json:"email_verified"`
		Nonce         string      `json:"nonce"`
		Iss           string      `json:"iss"`
		Aud           any         `json:"aud"`
		Exp           int64       `json:"exp"`
		Iat           int64       `json:"iat"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	now := time.Now().Unix()
	// iss estricto (allowlist).
	issOK := false
	for _, a := range c.allowedIssuers {
		if subtle.ConstantTimeCompare([]byte(claims.Iss), []byte(a)) == 1 && claims.Iss != "" {
			issOK = true
			break
		}
	}
	if !issOK {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	// aud debe contener nuestro client_id (string o array).
	if !audContains(claims.Aud, c.clientID) {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	// exp con skew 30s: el token debe seguir válido 30s más.
	if claims.Exp == 0 || claims.Exp-now < 30 {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	// iat no futuro más allá de 60s.
	if claims.Iat > now+60 {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	// nonce ConstantTime.
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 || claims.Nonce == "" {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	if len(claims.Sub) < 1 || len(claims.Sub) > 255 {
		return auth.OIDClaims{}, auth.ErrInvalidToken
	}
	return auth.OIDClaims{
		Sub: claims.Sub, Email: claims.Email, EmailVerified: claims.EmailVerified,
		Nonce: claims.Nonce, Iss: claims.Iss, Aud: c.clientID, Exp: claims.Exp, Iat: claims.Iat,
	}, nil
}

func audContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return subtle.ConstantTimeCompare([]byte(v), []byte(clientID)) == 1 && v != ""
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

func (c *GoogleOIDCClient) keyForKid(ctx context.Context, kid string) (any, error) {
	c.mu.RLock()
	k, ok := c.jwks[kid]
	fresh := time.Since(c.jwksFetchedAt) < time.Hour
	c.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	// Refresh (1 intento ante kid-miss / rotación).
	if err := c.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if k, ok := c.jwks[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown kid")
}

func (c *GoogleOIDCClient) refreshJWKS(ctx context.Context) error {
	if c.jwksURL == "" {
		if err := c.refreshDiscovery(ctx); err != nil {
			return err
		}
	}
	if c.jwksURL == "" {
		return errors.New("no jwks_uri")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	keys := map[string]any{}
	for _, raw := range doc.Keys {
		var meta struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil || meta.Kid == "" {
			continue
		}
		switch meta.Kty {
		case "RSA":
			var j struct {
				N string `json:"n"`
				E string `json:"e"`
			}
			if err := json.Unmarshal(raw, &j); err != nil {
				continue
			}
			nb, err := base64.RawURLEncoding.DecodeString(j.N)
			if err != nil {
				continue
			}
			eb, err := base64.RawURLEncoding.DecodeString(j.E)
			if err != nil {
				continue
			}
			e := 0
			for _, b := range eb {
				e = e<<8 | int(b)
			}
			keys[meta.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
		case "EC":
			var j struct {
				Crv string `json:"crv"`
				X   string `json:"x"`
				Y   string `json:"y"`
			}
			if err := json.Unmarshal(raw, &j); err != nil || j.Crv != "P-256" {
				continue
			}
			xb, err1 := base64.RawURLEncoding.DecodeString(j.X)
			yb, err2 := base64.RawURLEncoding.DecodeString(j.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[meta.Kid] = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xb),
				Y:     new(big.Int).SetBytes(yb),
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.jwks = keys
	c.jwksFetchedAt = time.Now()
	return nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		// Compat: padding.
		if b2, err2 := base64.URLEncoding.DecodeString(seg); err2 == nil {
			b = b2
		} else {
			return err
		}
	}
	return json.Unmarshal(b, v)
}
