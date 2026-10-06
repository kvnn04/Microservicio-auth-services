package auth

import (
	"fmt"
	"time"
)

// Constantes TOTP CU-AUTH-02 (Q1): SHA1, 6 dígitos, step 30s, secreto 20B,
// ventana ±1, leeway +5s, staged 10min, pre-token 5min, 5 fallos, replay 90s.
const (
	TOTPAlgo        = "SHA1"
	TOTPDigits      = 6
	TOTPStep        = 30 * time.Second
	TOTPSecretBytes = 20
	TOTPWindow      = 1
	TOTPLeeway      = 5 * time.Second
	StagedTTL       = 10 * time.Minute
	MaxVerifyFails  = 5
	ReplayTTL       = 90 * time.Second
)

// TOTPSecret representa el secreto del usuario (cifrado en reposo).
type TOTPSecret struct {
	UserID    string
	Staged    bool
	Verified  bool
	ExpiresAt time.Time // staged_expires_at si Staged
}

// NewCounter floor((now+leeway)/30): el counter de referencia.
func NewCounter(now time.Time) int64 {
	return now.UTC().Add(TOTPLeeway).Unix() / int64(TOTPStep.Seconds())
}

// Candidates ventana ±1 alrededor del counter.
func Candidates(counter int64) []int64 {
	return []int64{counter - 1, counter, counter + 1}
}

// FormatCode zero-pad 6 dígitos (mod 10^6).
func FormatCode(v uint32) string {
	return fmt.Sprintf("%06d", v%1000000)
}
