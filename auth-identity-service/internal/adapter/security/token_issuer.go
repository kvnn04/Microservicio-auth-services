package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// TokenIssuer implementa auth.VerificationTokenIssuer (32B CSPRNG).
type TokenIssuer struct{}

func NewTokenIssuer() *TokenIssuer { return &TokenIssuer{} }

func (TokenIssuer) Generate() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("rand token: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(b)
	return plain, TokenIssuer{}.HashToken(plain), nil
}

func (TokenIssuer) HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// GeneratePair genera el par link+OTP (CU-REG-02): token 32B CSPRNG base64url
// sin padding + OTP 8 dígitos CSPRNG zero-padded, con sus hashes SHA-256.
func (t TokenIssuer) GeneratePair() (tokenPlain, tokenHash, otpPlain, otpHash string, err error) {
	tokenPlain, tokenHash, err = t.Generate()
	if err != nil {
		return "", "", "", "", err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", "", "", "", fmt.Errorf("rand otp: %w", err)
	}
	otpPlain = fmt.Sprintf("%08d", n.Int64())
	sum := sha256.Sum256([]byte(otpPlain))
	otpHash = hex.EncodeToString(sum[:])
	return tokenPlain, tokenHash, otpPlain, otpHash, nil
}
