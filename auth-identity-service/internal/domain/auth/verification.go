package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Constantes CU-REG-02 (Q1/Q7): dual OTP 8 dígitos + Magic Link 32B, TTL 15min, 3 intentos.
const (
	VerifyTokenBytes  = 32
	VerifyOTPLen      = 8
	VerifyTTL         = 15 * time.Minute
	VerifyMaxAttempts = 3
	ResendCooldown    = 60 * time.Second
	ResendQuota24h    = 5
	VerifyJitterMin   = 40 * time.Millisecond
	VerifyJitterMax   = 80 * time.Millisecond
)

var (
	ErrInvalidOrExpired = errors.New("invalid or expired verification secret")
	ErrAlreadyConsumed  = errors.New("verification secret already consumed")
	ErrBurned           = errors.New("verification secret burned after max attempts")
	ErrInvalidTransition = errors.New("invalid user status transition")
	ErrThrottled        = errors.New("resend throttled")
)

var otpRegex = regexp.MustCompile(`^[0-9]{8}$`)

// VerificationRecord es el registro de verificación dual (link + OTP).
// Solo hashes SHA-256 hex, nunca planos (SEC-03).
type VerificationRecord struct {
	UserID      string
	TokenHash   string // SHA-256 del Magic Link (puede ser "" si solo-OTP, no en este CU)
	OTPHash     string // SHA-256 del OTP 8 dígitos (puede ser "" en filas legacy CU-REG-01)
	ExpiresAt   time.Time
	Attempts    int
	Consumed    bool
	Superseded  bool
	ActivatedBy *string
	// Transitorios (nunca persistidos en verification_tokens ni logueados):
	// el adapter los usa SOLO para encolar el email con el secreto plano.
	TokenPlain string
	OTPPlain   string
}

// IsAlive indica si el registro admite verificación: vigente, no consumido,
// no superseded y con intentos restantes.
func (v *VerificationRecord) IsAlive(now time.Time) bool {
	return v != nil && !v.Consumed && !v.Superseded &&
		v.Attempts < VerifyMaxAttempts && now.UTC().Before(v.ExpiresAt)
}

// CanAttempt alias semántico de IsAlive para el servicio.
func (v *VerificationRecord) CanAttempt(now time.Time) bool {
	return v.IsAlive(now)
}

// ParseTokenInput normaliza un Magic Link: trim, base64url estricto → 32B exactos.
// Retorna el SHA-256 hex del string canónico (igual que TokenIssuer.HashToken)
// para lookup. Error → 400 VALIDATION_FAILED (formato).
func ParseTokenInput(raw string) (hash string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty token: %w", ErrValidation)
	}
	b, derr := base64.RawURLEncoding.DecodeString(s)
	if derr != nil {
		return "", fmt.Errorf("token decode: %w", ErrValidation)
	}
	if len(b) != VerifyTokenBytes {
		return "", fmt.Errorf("token must be 32B: %w", ErrValidation)
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

// ParseOTPInput normaliza un OTP: trim, ^[0-9]{8}$.
// Retorna el SHA-256 hex para lookup. Error → 400 VALIDATION_FAILED (formato).
func ParseOTPInput(raw string) (hash string, err error) {
	s := strings.TrimSpace(raw)
	if !otpRegex.MatchString(s) {
		return "", fmt.Errorf("otp must be 8 digits: %w", ErrValidation)
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}
