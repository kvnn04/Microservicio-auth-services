package security

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// StepUpTokenIssuer implementa auth.StepUpTokenIssuer (CU-AUTH-06 Q4/SEC-03).
// JWT Ed25519 de un uso (`jti` en Redis EX 300), `aud=step-up` aislado del
// mundo Access (`aud=api`): el middleware de negocio lo rechaza por `aud`.
// Misma clave (`kid`) que sesiones; `aud` distinto. Nunca `none`.
type StepUpTokenIssuer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
	iss  string
}

func NewStepUpTokenIssuer(priv ed25519.PrivateKey, kid, iss string) (*StepUpTokenIssuer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 key: %w", auth.ErrNoKey)
	}
	if kid == "" {
		return nil, fmt.Errorf("kid required: %w", auth.ErrNoKey)
	}
	if iss == "" {
		iss = auth.DefaultIssuer
	}
	return &StepUpTokenIssuer{
		priv: priv, pub: priv.Public().(ed25519.PublicKey), kid: kid, iss: iss,
	}, nil
}

// IssueToken firma {sub, jti UUIDv7, aud:step-up, scope, exp:+300s, amr}.
func (s *StepUpTokenIssuer) IssueToken(_ context.Context, userID string, scope auth.StepUpScope, amr []string) (string, string, error) {
	if len(s.priv) == 0 {
		return "", "", auth.ErrNoKey
	}
	if userID == "" || !scope.Valid() {
		return "", "", auth.ErrUnknownScope
	}
	jti, err := uuid.NewV7()
	if err != nil {
		return "", "", fmt.Errorf("jti: %w", auth.ErrSessionInfra)
	}
	now := time.Now().UTC()
	claims := auth.StepUpClaims{
		Iss: s.iss, Aud: auth.StepUpAud, Sub: userID, JTI: jti.String(),
		Scope: string(scope), Iat: now.Unix(), Exp: now.Add(auth.StepUpTokenTTL).Unix(),
		AuthTime: now.Unix(), AMR: amr,
	}
	header := map[string]string{"alg": "EdDSA", "kid": s.kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	token := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(s.priv, []byte(token))
	return token + "." + base64.RawURLEncoding.EncodeToString(sig), jti.String(), nil
}

// VerifyToken valida firma + alg + kid + iss/aud(exp, TTL exacto 300s).
// Cualquier fallo → error genérico (el servicio mapea a 401 opaco).
func (s *StepUpTokenIssuer) VerifyToken(token string) (auth.StepUpClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return auth.StepUpClaims{}, fmt.Errorf("bad shape")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return auth.StepUpClaims{}, fmt.Errorf("bad header")
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return auth.StepUpClaims{}, fmt.Errorf("bad header")
	}
	if header.Alg != "EdDSA" {
		return auth.StepUpClaims{}, fmt.Errorf("unexpected alg")
	}
	if header.Kid == "" || header.Kid != s.kid {
		return auth.StepUpClaims{}, fmt.Errorf("unknown kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return auth.StepUpClaims{}, fmt.Errorf("bad sig")
	}
	if !ed25519.Verify(s.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return auth.StepUpClaims{}, fmt.Errorf("bad signature")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return auth.StepUpClaims{}, fmt.Errorf("bad payload")
	}
	var claims auth.StepUpClaims
	if err := json.Unmarshal(pb, &claims); err != nil {
		return auth.StepUpClaims{}, fmt.Errorf("bad claims")
	}
	if claims.Iss != s.iss || claims.Aud != auth.StepUpAud {
		return auth.StepUpClaims{}, fmt.Errorf("bad iss/aud")
	}
	if claims.Sub == "" || claims.JTI == "" || claims.Scope == "" {
		return auth.StepUpClaims{}, fmt.Errorf("bad sub/jti/scope")
	}
	if !auth.StepUpScope(claims.Scope).Valid() {
		return auth.StepUpClaims{}, fmt.Errorf("unknown scope")
	}
	now := time.Now().UTC().Unix()
	if now > claims.Exp+int64((auth.ClockSkew/time.Second)) {
		return auth.StepUpClaims{}, fmt.Errorf("expired")
	}
	if claims.Exp-claims.Iat != int64((auth.StepUpTokenTTL / time.Second)) {
		return auth.StepUpClaims{}, fmt.Errorf("bad ttl")
	}
	return claims, nil
}

var _ auth.StepUpTokenIssuer = (*StepUpTokenIssuer)(nil)
