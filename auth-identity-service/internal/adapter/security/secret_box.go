package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SecretBox implementa auth.SecretBox (AES-256-GCM, AAD=user_id).
// Constructor fail-fast: key debe ser 32B (env MFA_SECRETS_KEY hex).
type SecretBox struct {
	key []byte
}

// NewSecretBox valida longitud (fail-fast: el servicio no levanta sin key).
func NewSecretBox(key []byte) (*SecretBox, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("mfa secrets key must be 32 bytes, got %d", len(key))
	}
	return &SecretBox{key: key}, nil
}

// ParseSecretsKey acepta hex64 o raw32.
func ParseSecretsKey(s string) ([]byte, error) {
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("bad hex key")
		}
		return b, nil
	}
	if len(s) == 32 {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("mfa secrets key must be 64 hex chars or 32 bytes")
}

// Encrypt: nonce 12B aleatorio + AES-GCM(AAD=user_id). Formato nonce||ct.
func (b *SecretBox) Encrypt(_ context.Context, userID string, raw []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, raw, []byte(userID))
	return append(nonce, ct...), nil
}

// Decrypt verifica AAD=user_id (mismatch → error, anti-swap entre cuentas).
func (b *SecretBox) Decrypt(_ context.Context, userID string, sealed []byte) ([]byte, error) {
	if len(sealed) < 12+16 {
		return nil, fmt.Errorf("sealed too short")
	}
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, sealed[:12], sealed[12:], []byte(userID))
}
