package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Códigos de respaldo CU-AUTH-03 (Q1): 10×10ch Crockford (~50 bits).
// Display `XXXX-XXXXXX` (solo UX); canónico 10ch upper sin guion.
const (
	BackupCount      = 10
	BackupChars      = 10
	BackupAlphabet   = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
	BackupDisplaySep = 4
)

var (
	ErrBackupNotFound = errors.New("backup code not found")
	ErrBackupUsed     = errors.New("backup code already used")
)

// Canonicalize normaliza: trim, upper, sin guiones/espacios.
// Exige ^[Alphabet]{10}$ (rechaza 0/O/1 minúsculas ambiguas tras upper).
func Canonicalize(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) != BackupChars {
		return "", fmt.Errorf("backup length: %w", ErrValidation)
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(BackupAlphabet, rune(s[i])) {
			return "", fmt.Errorf("backup alphabet: %w", ErrValidation)
		}
	}
	return s, nil
}

// Display formatea XXXX-XXXXXX para exhibición (única vez, TLS).
func Display(canonical string) string {
	if len(canonical) != BackupChars {
		return canonical
	}
	return canonical[:BackupDisplaySep] + "-" + canonical[BackupDisplaySep:]
}

// HashWithPepper hex(sha256(canónico + pepper)). Sin pepper → SHA puro + WARN.
func HashWithPepper(canonical string, pepper []byte) string {
	h := sha256.Sum256([]byte(canonical + string(pepper)))
	return hex.EncodeToString(h[:])
}
