package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"
)

// Ed25519Signer implementa auth.AccessSigner (CU-AUTH-04 Q1/SEC-01).
// Clave privada 64B (seed+pub) en KMS/env SESSION_SIGNING_KEY (base64),
// nunca en repo/logs. kid obligatorio en header; nunca alg none/HMAC.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
	iss  string
	aud  string
}

func NewEd25519Signer(priv ed25519.PrivateKey, kid, iss, aud string) (*Ed25519Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 key: %w", auth.ErrNoKey)
	}
	if kid == "" {
		return nil, fmt.Errorf("kid required: %w", auth.ErrNoKey)
	}
	if iss == "" {
		iss = auth.DefaultIssuer
	}
	if aud == "" {
		aud = auth.DefaultAudience
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Signer{priv: priv, pub: pub, kid: kid, iss: iss, aud: aud}, nil
}

// NewEd25519SignerFromSeed construye desde seed 32B (env/KMS) + kid.
func NewEd25519SignerFromSeed(seed []byte, kid, iss, aud string) (*Ed25519Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed 32B: %w", auth.ErrNoKey)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return NewEd25519Signer(priv, kid, iss, aud)
}

// ParseEd25519PrivateKey acepta base64(std/raw) de 32B seed o 64B privada.
func ParseEd25519PrivateKey(b64 string) (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(b64)
	if raw == "" {
		return nil, fmt.Errorf("empty key: %w", auth.ErrNoKey)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(raw); err == nil {
			if len(b) == ed25519.SeedSize {
				return ed25519.NewKeyFromSeed(b), nil
			}
			if len(b) == ed25519.PrivateKeySize {
				return ed25519.PrivateKey(b), nil
			}
		}
	}
	return nil, fmt.Errorf("bad key encoding: %w", auth.ErrNoKey)
}

// GenerateEd25519Key genera par efímero (tests + script gen_ed25519.sh).
func GenerateEd25519Key() (priv ed25519.PrivateKey, pubB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	return priv, base64.RawStdEncoding.EncodeToString(pub), nil
}

func (s *Ed25519Signer) ActiveKID() string { return s.kid }

// PublicB64 expone solo la pública (para JWKS CU-CRYP-01, sin privada).
func (s *Ed25519Signer) PublicB64() string {
	return base64.RawStdEncoding.EncodeToString(s.pub)
}

// Sign firma claims (header EdDSA/kid + payload mínimo). Fail-fast sin key.
func (s *Ed25519Signer) Sign(_ context.Context, claims auth.AccessClaims) (string, string, error) {
	if len(s.priv) == 0 {
		return "", "", auth.ErrNoKey
	}
	if claims.Sub == "" || claims.SID == "" || claims.JTI == "" {
		return "", "", auth.ErrInvalidSessionRequest
	}
	header := map[string]string{"alg": "EdDSA", "kid": s.kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	h64 := base64.RawURLEncoding.EncodeToString(hb)
	p64 := base64.RawURLEncoding.EncodeToString(pb)
	// Límite 8KB (nunca Access gigante; si excede, el dominio ya truncó roles).
	if len(h64)+len(p64) > auth.MaxAccessBytes {
		return "", "", auth.ErrClaimsTooLarge
	}
	msg := h64 + "." + p64
	sig := ed25519.Sign(s.priv, []byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig), s.kid, nil
}

// Verify valida firma Ed25519 + iss/aud/exp (skew 30s) + kid esperado.
// No toca DB (tokens_valid_after/denylist los chequea el gateway con PG/Redis).
func (s *Ed25519Signer) Verify(token string) (auth.AccessClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return auth.AccessClaims{}, fmt.Errorf("bad shape")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return auth.AccessClaims{}, fmt.Errorf("bad header")
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return auth.AccessClaims{}, fmt.Errorf("bad header")
	}
	if header.Alg != "EdDSA" {
		return auth.AccessClaims{}, fmt.Errorf("unexpected alg")
	}
	if header.Kid == "" || header.Kid != s.kid {
		return auth.AccessClaims{}, fmt.Errorf("unknown kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return auth.AccessClaims{}, fmt.Errorf("bad sig")
	}
	if !ed25519.Verify(s.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return auth.AccessClaims{}, fmt.Errorf("bad signature")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return auth.AccessClaims{}, fmt.Errorf("bad payload")
	}
	var claims auth.AccessClaims
	if err := json.Unmarshal(pb, &claims); err != nil {
		return auth.AccessClaims{}, fmt.Errorf("bad claims")
	}
	now := time.Now().UTC().Unix()
	if claims.Iss != s.iss || claims.Aud != s.aud {
		return auth.AccessClaims{}, fmt.Errorf("bad iss/aud")
	}
	if claims.Sub == "" || claims.SID == "" || claims.JTI == "" {
		return auth.AccessClaims{}, fmt.Errorf("bad sub/sid/jti")
	}
	if now > claims.Exp+int64((auth.ClockSkew/time.Second)) {
		return auth.AccessClaims{}, fmt.Errorf("expired")
	}
	if claims.Exp-claims.Iat != int64((auth.AccessTTL/time.Second)) {
		return auth.AccessClaims{}, fmt.Errorf("bad ttl")
	}
	return claims, nil
}

var _ auth.AccessSigner = (*Ed25519Signer)(nil)
