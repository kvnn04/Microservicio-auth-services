package security

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"

	"auth-identity-service/internal/domain/auth"
)

// BackupCodeIssuer implementa auth.BackupCodeIssuer (CU-AUTH-03 Q1/Q2):
// 10ch Crockford CSPRNG, SHA-256(canónico+pepper), ConstantTime, rotación.
type BackupCodeIssuer struct {
	pepper []byte
	prev   []byte // ventana de rotación (PEPPER_PREV); nil = sin rotación.
}

func NewBackupCodeIssuer(pepper, prev []byte) *BackupCodeIssuer {
	return &BackupCodeIssuer{pepper: pepper, prev: prev}
}

// Generate retorna plano canónico + hash (el servicio reintenta colisión).
func (b *BackupCodeIssuer) Generate(_ context.Context) (plain, hash string, err error) {
	buf := make([]byte, auth.BackupChars)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	out := make([]byte, auth.BackupChars)
	for i := range out {
		out[i] = auth.BackupAlphabet[int(buf[i])%len(auth.BackupAlphabet)]
	}
	plain = string(out)
	return plain, b.Hash(plain), nil
}

// Hash con pepper actual (sin pepper → SHA puro + el caller loguea WARN).
func (b *BackupCodeIssuer) Hash(canonical string) string {
	return auth.HashWithPepper(canonical, b.pepper)
}

// HashPrev hash con pepper previo (rotación); ok=false si no hay previo.
func (b *BackupCodeIssuer) HashPrev(canonical string) (string, bool) {
	if len(b.prev) == 0 {
		return "", false
	}
	return auth.HashWithPepper(canonical, b.prev), true
}

// Verify compara ConstantTime probando actual y previo (rotación).
func (b *BackupCodeIssuer) Verify(_ context.Context, canonical, storedHash string) bool {
	actual, err := hex.DecodeString(b.Hash(canonical))
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(storedHash)
	if err != nil || len(actual) != len(expected) {
		return false
	}
	if subtle.ConstantTimeCompare(actual, expected) == 1 {
		return true
	}
	if prev, ok := b.HashPrev(canonical); ok {
		if p, err := hex.DecodeString(prev); err == nil && len(p) == len(expected) {
			return subtle.ConstantTimeCompare(p, expected) == 1
		}
	}
	return false
}
