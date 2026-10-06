package security

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"

	"auth-identity-service/internal/domain/auth"
)

// TOTPProvider implementa auth.TOTPProvider (RFC4226/6238 SHA1/6/30).
type TOTPProvider struct{}

func NewTOTPProvider() *TOTPProvider { return &TOTPProvider{} }

// GenerateSecret 20B CSPRNG + base32 sin padding (una exhibición).
func (TOTPProvider) GenerateSecret(_ context.Context) ([]byte, string, error) {
	raw := make([]byte, auth.TOTPSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	return raw, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// hotp Dynamic Truncation RFC4226 (SHA1).
func hotp(raw []byte, counter int64) uint32 {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff
	return code % 1000000
}

// CodeAt código para counter (tests/vectores RFC).
func (TOTPProvider) CodeAt(_ context.Context, raw []byte, counter int64) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("empty secret")
	}
	return auth.FormatCode(hotp(raw, counter)), nil
}

// Validate prueba ±1 con ConstantTime; retorna counter coincidente.
func (TOTPProvider) Validate(_ context.Context, raw []byte, code string, counter int64) (int64, bool) {
	if len(code) != auth.TOTPDigits || len(raw) == 0 {
		return 0, false
	}
	for _, c := range auth.Candidates(counter) {
		expected := auth.FormatCode(hotp(raw, c))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}
