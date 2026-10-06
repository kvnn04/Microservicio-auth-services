package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Constantes CU-CRED-01 (Q1/Q6): solo link 32B, TTL 15min, 1 activo
// (supersede), 1 uso, attempts ≤3, quotas 60s cooldown + 5/24h.
const (
	PwdResetTTL         = 15 * time.Minute
	PwdResetTokenBytes  = 32
	PwdResetMaxAttempts = 3
	PwdResetCooldown    = 60 * time.Second
	PwdResetMaxDay      = 5
)

// PasswordResetRecord secreto de un uso (solo link, sin OTP débil).
// Solo hash SHA-256 hex persistido; plano solo transitorio para el email.
type PasswordResetRecord struct {
	UserID     string
	TokenHash  string // SHA-256 del link 43ch
	ExpiresAt  time.Time
	Attempts   int
	Consumed   bool
	Superseded bool
	Ctx        PlessContext // reuso huella CU-AUTH-05 (ip/24 + UA)
	// Transitorio (nunca persistido ni logueado): el adapter lo usa SOLO
	// para encolar el email con el secreto plano.
	TokenPlain string
}

// Alive indica si admite confirm: vigente, no consumido ni superseded,
// con intentos restantes.
func (r *PasswordResetRecord) Alive(now time.Time) bool {
	return r != nil && !r.Consumed && !r.Superseded &&
		r.Attempts < PwdResetMaxAttempts && now.UTC().Before(r.ExpiresAt)
}

// ParseResetToken normaliza el link: trim, base64url estricto → 32B exactos.
// Retorna SHA-256 hex para lookup. Error → 400 VALIDATION_FAILED (formato).
func ParseResetToken(raw string) (hash string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty token: %w", ErrValidation)
	}
	b, derr := base64.RawURLEncoding.DecodeString(s)
	if derr != nil {
		return "", fmt.Errorf("token decode: %w", ErrValidation)
	}
	if len(b) != PwdResetTokenBytes {
		return "", fmt.Errorf("token must be 32B: %w", ErrValidation)
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}
