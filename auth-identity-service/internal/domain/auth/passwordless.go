package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Constantes CU-AUTH-05 (Q1/Q2/Q6): secreto efímero dual por email.
// TTL ultra-corto 10min, un solo uso, ≤1 activo por cuenta (supersede),
// quotas anti-spam 60s cooldown + 5/24h (throttled → 202 genérico, sin oráculo).
const (
	PlessTTL         = 10 * time.Minute
	PlessTokenBytes  = 32
	PlessOTPLen      = 8
	PlessMaxAttempts = 3
	PlessCooldown    = 60 * time.Second
	PlessMaxDay      = 5
)

// PlessContext huella de emisión (solo hashes, nunca PII completa).
// IPHash24 liga al /24 de emisión; IPHash16 permite comparación laxa (/16);
// UAFamily es la familia del cliente (no bloqueante, solo risk).
type PlessContext struct {
	IPHash24 string
	IPHash16 string
	UAHash   string
	UAFamily string
}

// MaskIP24 enmascara IPv4 al /24 ("a.b.c.d" → "a.b.c.0"); resto se hashea tal cual.
func MaskIP24(ip string) string {
	ip = strings.TrimSpace(ip)
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		allNum := true
		for _, p := range parts {
			if p == "" {
				allNum = false
				break
			}
			for i := 0; i < len(p); i++ {
				if p[i] < '0' || p[i] > '9' {
					allNum = false
					break
				}
			}
		}
		if allNum {
			return parts[0] + "." + parts[1] + "." + parts[2] + ".0"
		}
	}
	return ip
}

// MaskIP16 enmascara IPv4 al /16 ("a.b.c.d" → "a.b.0.0"); resto tal cual.
func MaskIP16(ip string) string {
	ip = strings.TrimSpace(ip)
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + "." + parts[1] + ".0.0"
	}
	return ip
}

// UAFamily extrae la familia del User-Agent (heurístico, no bloqueante).
func UAFamily(ua string) string {
	s := strings.ToLower(strings.TrimSpace(ua))
	if s == "" {
		return "unknown"
	}
	switch {
	case strings.Contains(s, "okhttp"):
		return "okhttp"
	case strings.Contains(s, "curl"):
		return "curl"
	case strings.Contains(s, "edg"):
		return "edge"
	case strings.Contains(s, "firefox"):
		return "firefox"
	case strings.Contains(s, "chrome"):
		return "chrome"
	case strings.Contains(s, "safari"):
		return "safari"
	case strings.Contains(s, "mozilla"):
		return "mozilla"
	}
	if i := strings.IndexAny(s, "/ ;("); i > 0 {
		if i > 24 {
			i = 24
		}
		return s[:i]
	}
	if len(s) > 24 {
		return s[:24]
	}
	return s
}

// NewPlessContext calcula la huella de emisión/consumo desde IP+UA crudos.
func NewPlessContext(ip, ua string) PlessContext {
	if strings.TrimSpace(ip) == "" {
		ip = "unknown"
	}
	h24 := sha256.Sum256([]byte(MaskIP24(ip)))
	h16 := sha256.Sum256([]byte(MaskIP16(ip)))
	uh := sha256.Sum256([]byte(strings.TrimSpace(ua)))
	return PlessContext{
		IPHash24: hex.EncodeToString(h24[:]),
		IPHash16: hex.EncodeToString(h16[:]),
		UAHash:   hex.EncodeToString(uh[:]),
		UAFamily: UAFamily(ua),
	}
}

// PasswordlessRecord secreto efímero dual (link 32B + OTP 8d, mismo registro).
// Solo hashes SHA-256 hex persistidos; planos solo transitorios para el email.
type PasswordlessRecord struct {
	UserID     string
	TokenHash  string // SHA-256 del link 43ch
	OTPHash    string // SHA-256 del OTP 8 dígitos
	ExpiresAt  time.Time
	Attempts   int
	Consumed   bool
	Superseded bool
	Ctx        PlessContext
	// Transitorios (nunca persistidos ni logueados): el adapter los usa SOLO
	// para encolar el email con el secreto plano.
	TokenPlain string
	OTPPlain   string
}

// Alive indica si admite verificación: vigente, no consumido ni superseded,
// con intentos restantes.
func (r *PasswordlessRecord) Alive(now time.Time) bool {
	return r != nil && !r.Consumed && !r.Superseded &&
		r.Attempts < PlessMaxAttempts && now.UTC().Before(r.ExpiresAt)
}

// ParsePlessToken normaliza el link: trim, base64url estricto → 32B exactos.
// Retorna SHA-256 hex para lookup. Error → 400 VALIDATION_FAILED (formato).
func ParsePlessToken(raw string) (hash string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty token: %w", ErrValidation)
	}
	b, derr := base64.RawURLEncoding.DecodeString(s)
	if derr != nil {
		return "", fmt.Errorf("token decode: %w", ErrValidation)
	}
	if len(b) != PlessTokenBytes {
		return "", fmt.Errorf("token must be 32B: %w", ErrValidation)
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

// ParsePlessOTP normaliza el código: trim, ^[0-9]{8}$.
// Retorna SHA-256 hex para lookup. Error → 400 VALIDATION_FAILED (formato).
func ParsePlessOTP(raw string) (hash string, err error) {
	s := strings.TrimSpace(raw)
	if len(s) != PlessOTPLen {
		return "", fmt.Errorf("otp must be 8 digits: %w", ErrValidation)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", fmt.Errorf("otp must be 8 digits: %w", ErrValidation)
		}
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

// RiskOf compara huella de emisión vs consumo (laxo, alerta sin bloqueo).
// "low" solo si /16 coincide Y familia UA coincide; cualquier diferencia → "high".
func RiskOf(emit, consume PlessContext) string {
	if emit.IPHash16 != "" && emit.IPHash16 == consume.IPHash16 &&
		strings.EqualFold(emit.UAFamily, consume.UAFamily) {
		return "low"
	}
	return "high"
}
