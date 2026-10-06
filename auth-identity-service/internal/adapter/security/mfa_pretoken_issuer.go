package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// MFAPreTokenIssuer implementa auth.MFAPreTokenIssuer (CU-AUTH-01 §8).
// JWT HS256 con aud=mfa-challenge, sub, challenge_id UUIDv7, methods,
// exp=i at+5min. Válido SOLO en POST /mfa/verify (CU-AUTH-02); el middleware
// de negocio lo rechaza por aud. Nunca es sesión.
type MFAPreTokenIssuer struct {
	secret []byte
}

func NewMFAPreTokenIssuer(secret []byte) *MFAPreTokenIssuer {
	return &MFAPreTokenIssuer{secret: secret}
}

func (m *MFAPreTokenIssuer) IssueChallenge(ctx context.Context, userID string) (token, challengeID string, expiresIn int, err error) {
	_ = ctx
	if len(m.secret) == 0 {
		return "", "", 0, fmt.Errorf("mfa secret not configured")
	}
	cid, cerr := uuid.NewV7()
	if cerr != nil {
		return "", "", 0, cerr
	}
	challengeID = cid.String()
	exp := time.Now().UTC().Add(5 * time.Minute).Unix()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadMap := map[string]any{
		"sub": userID, "aud": "mfa-challenge", "challenge_id": challengeID,
		"methods": []string{"totp"}, "exp": exp, "iat": time.Now().UTC().Unix(),
	}
	payloadBytes, _ := json.Marshal(payloadMap)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(header + "." + payload))
	token = header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return token, challengeID, 300, nil
}

// ValidateChallenge verifica firma + aud=mfa-challenge + exp (CU-AUTH-02).
// Cualquier fallo → auth.ErrInvalidMFA opaco (el servicio no distingue).
func (m *MFAPreTokenIssuer) ValidateChallenge(token string) (auth.PreTokenClaims, error) {
	parts := splitJWT(token)
	if len(parts) != 3 {
		return auth.PreTokenClaims{}, auth.ErrInvalidMFA
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return auth.PreTokenClaims{}, auth.ErrInvalidMFA
	}
	if subtle.ConstantTimeCompare(sig, mac.Sum(nil)) != 1 {
		return auth.PreTokenClaims{}, auth.ErrInvalidMFA
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return auth.PreTokenClaims{}, auth.ErrInvalidMFA
	}
	var claims struct {
		Sub         string `json:"sub"`
		Aud         string `json:"aud"`
		ChallengeID string `json:"challenge_id"`
		Exp         int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return auth.PreTokenClaims{}, auth.ErrInvalidMFA
	}
	if claims.Aud != auth.MFAChallengeAUD || claims.Sub == "" || claims.ChallengeID == "" {
		return auth.PreTokenClaims{}, auth.ErrInvalidMFA
	}
	if time.Now().UTC().Unix() > claims.Exp {
		return auth.PreTokenClaims{}, auth.ErrInvalidMFA
	}
	return auth.PreTokenClaims{Sub: claims.Sub, ChallengeID: claims.ChallengeID, ExpiresAt: claims.Exp}, nil
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}
