package user

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Constantes CU-CRED-03 (Q3/Q6): link 32B, TTL 15min, 1 activo por cuenta
// (supersede), 1 uso, attempts ≤3, rate 3/hora + quotas 60s/5-24h.
const (
	EmailChangeTTL         = 15 * time.Minute
	EmailChangeTokenBytes  = 32
	EmailChangeMaxAttempts = 3
	EmailChangeRatePerHour = 3
	EmailChangeRateWindow  = time.Hour
	EmailChangeCooldown    = 60 * time.Second
	EmailChangeMaxDay      = 5
)

// EmailChangeRecord prueba de control del NUEVO correo (link 32B).
// Solo hash SHA-256 hex persistido; plano solo transitorio para el email.
type EmailChangeRecord struct {
	RequesterID   string
	TokenHash     string // SHA-256 del link 43ch
	NewNormalized string
	NewOriginal   string
	ExpiresAt     time.Time
	Attempts      int
	Consumed      bool
	Superseded    bool
	// Transitorio (nunca persistido ni logueado): el adapter lo usa SOLO
	// para encolar el email de confirmación al nuevo buzón.
	TokenPlain string
}

// Alive indica si admite confirm: vigente, no consumido ni superseded,
// con intentos restantes.
func (r *EmailChangeRecord) Alive(now time.Time) bool {
	return r != nil && !r.Consumed && !r.Superseded &&
		r.Attempts < EmailChangeMaxAttempts && now.UTC().Before(r.ExpiresAt)
}

// ParseEmailChangeToken normaliza el link: trim, base64url estricto → 32B.
// Retorna SHA-256 hex para lookup. Error → 400 VALIDATION_FAILED (formato).
func ParseEmailChangeToken(raw string) (hash string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty token: %w", ErrInvalidEmail)
	}
	b, derr := base64.RawURLEncoding.DecodeString(s)
	if derr != nil {
		return "", fmt.Errorf("token decode: %w", ErrInvalidEmail)
	}
	if len(b) != EmailChangeTokenBytes {
		return "", fmt.Errorf("token must be 32B: %w", ErrInvalidEmail)
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

// MaskEmail enmascara para respuestas/auditoría (`u***@dominio`).
// El buzón nuevo completo solo viaja en su propio correo.
func MaskEmail(normalized string) string {
	at := strings.Index(normalized, "@")
	if at <= 0 {
		return "***"
	}
	return normalized[:1] + "***" + normalized[at:]
}
