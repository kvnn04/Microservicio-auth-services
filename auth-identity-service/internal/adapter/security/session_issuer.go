package security

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// SessionIssuer interino (CU-REG-04): emite Access JWT HS256 15min + Refresh
// opaco 32B hasheado en Redis 7d. CU-AUTH-04/SES-04 lo reemplazarán con
// rotación asimétrica; la interfaz auth.SessionIssuer no cambia.
type SessionIssuer struct {
	secret    []byte
	rdb       *redis.Client
	accessTTL time.Duration
}

func NewSessionIssuer(secret []byte, rdb *redis.Client) *SessionIssuer {
	return &SessionIssuer{secret: secret, rdb: rdb, accessTTL: 15 * time.Minute}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Issue genera access JWT + refresh opaco (hash en Redis sess:rt:<hash>).
func (s *SessionIssuer) Issue(ctx context.Context, userID string) (accessToken, refreshTokenID string, expiresAt int64, err error) {
	if len(s.secret) == 0 {
		return "", "", 0, fmt.Errorf("session secret not configured")
	}
	now := time.Now().UTC()
	exp := now.Add(s.accessTTL).Unix()
	header := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadMap := map[string]any{"sub": userID, "exp": exp, "iat": now.Unix()}
	payloadBytes, _ := json.Marshal(payloadMap)
	payload := b64(payloadBytes)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(header + "." + payload))
	sig := b64(mac.Sum(nil))
	accessToken = header + "." + payload + "." + sig

	rb := make([]byte, 32)
	if _, err := rand.Read(rb); err != nil {
		return "", "", 0, err
	}
	refreshTokenID = hex.EncodeToString(rb)
	if s.rdb != nil {
		sum := sha256.Sum256([]byte(refreshTokenID))
		key := "sess:rt:" + hex.EncodeToString(sum[:])
		_ = s.rdb.Set(ctx, key, userID, 7*24*time.Hour).Err()
	}
	return accessToken, refreshTokenID, exp, nil
}

// VerifiedSession resume un access token válido (interino HS256; AUTH-04
// lo reemplazará con verificación asimétrica vía JWKS).
type VerifiedSession struct {
	UserID   string
	AuthTime time.Time
	Expires  time.Time
}

// VerifyBusiness valida como Verify y además rechaza tokens con aud
// (pre-tokens MFA aud=mfa-challenge NUNCA entran a APIs negocio, SEC-04).
// Los access interinos no llevan aud → pasan.
func (s *SessionIssuer) VerifyBusiness(token string) (*VerifiedSession, error) {
	sess, err := s.Verify(token)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("bad token shape")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad payload")
	}
	var claims struct {
		Aud any `json:"aud"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("bad claims")
	}
	switch a := claims.Aud.(type) {
	case string:
		if a != "" {
			return nil, fmt.Errorf("non-business audience")
		}
	case []any:
		if len(a) > 0 {
			return nil, fmt.Errorf("non-business audience")
		}
	}
	return sess, nil
}

// Verify valida firma HS256 + exp y extrae sub/iat (iat = auth_time).
func (s *SessionIssuer) Verify(token string) (*VerifiedSession, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("bad token shape")
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	actual, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding")
	}
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return nil, fmt.Errorf("bad signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad payload")
	}
	var claims struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("bad claims")
	}
	now := time.Now().UTC()
	if claims.Sub == "" || now.Unix() > claims.Exp {
		return nil, fmt.Errorf("expired")
	}
	return &VerifiedSession{
		UserID:   claims.Sub,
		AuthTime: time.Unix(claims.Iat, 0).UTC(),
		Expires:  time.Unix(claims.Exp, 0).UTC(),
	}, nil
}
