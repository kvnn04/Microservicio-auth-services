package user

import (
	"errors"
	"time"
)

// Política de vinculación CU-REG-06 (Q1-Q5).
const (
	MaxLinkedProviders = 5
	StepUpMaxAge       = 5 * time.Minute
)

var (
	ErrStepUpRequired    = errors.New("fresh authentication required")
	ErrInvalidStepUp     = errors.New("invalid step-up proof")
	ErrLastAuthFactor    = errors.New("cannot remove last auth factor")
	ErrProviderTaken     = errors.New("provider already linked to this account")
	ErrNotLinked         = errors.New("provider not linked")
	ErrCollisionForeign  = errors.New("identity linked to another account")
	ErrAlreadyLinkedSelf = errors.New("identity already linked to this account")
)

// CountFactors cuenta factores: password (1 si existe) + federados.
func CountFactors(hasPassword bool, federated int) int {
	n := federated
	if hasPassword {
		n++
	}
	return n
}

// CanUnlink indica si quitar target deja ≥1 factor (RN-04 último inamovible).
func CanUnlink(hasPassword bool, federated int, target Provider) (bool, string) {
	_ = target
	left := CountFactors(hasPassword, federated) - 1
	if left < 1 {
		return false, "LAST_AUTH_FACTOR"
	}
	return true, ""
}

// RequireFreshAuth exige auth_time ≤5min (RN-03). Cero/viejo → ErrStepUpRequired.
func RequireFreshAuth(authTime, now time.Time, maxAge time.Duration) error {
	if authTime.IsZero() {
		return ErrStepUpRequired
	}
	if maxAge <= 0 {
		maxAge = StepUpMaxAge
	}
	if now.UTC().Sub(authTime.UTC()) > maxAge {
		return ErrStepUpRequired
	}
	return nil
}
