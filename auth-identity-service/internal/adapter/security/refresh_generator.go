package security

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"auth-identity-service/internal/domain/auth"
)

// RefreshGenerator implementa auth.RefreshGenerator (CU-AUTH-04 Q2/SEC-02).
// Refresh 32B CSPRNG → 43ch base64url; en DB solo hash SHA-256 hex.
// Comparaciones en tiempo constante donde aplique (SES-04 lo usa).
type RefreshGenerator struct{}

func NewRefreshGenerator() *RefreshGenerator { return &RefreshGenerator{} }

func (RefreshGenerator) Generate(_ context.Context) (plain string, hash string, err error) {
	b := make([]byte, auth.RefreshBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(plain))
	return plain, hex.EncodeToString(sum[:]), nil
}

func (RefreshGenerator) Hash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// EqualHash compara hashes en tiempo constante (anti-timing, SES-04).
func (RefreshGenerator) EqualHash(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

var _ auth.RefreshGenerator = RefreshGenerator{}
