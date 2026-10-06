package auth

import (
	"time"

	"auth-identity-service/internal/domain/user"
)

// Constantes CU-AUTH-01 (Q5/Q7): rate, fails, lock exponencial, pre-token, timing.
const (
	LoginIPLimit    = 10
	LoginIPWindow   = time.Minute
	LoginAcctLimit  = 5
	LoginAcctWindow = time.Minute
	LoginMaxFails   = 5
	LoginFailWindow = 15 * time.Minute
	LoginLockBase   = 15 * time.Minute
	PreTokenTTL     = 5 * time.Minute
	LoginJitterMin  = 80 * time.Millisecond
	LoginJitterMax  = 120 * time.Millisecond
	DummyLoginPassword = "Dummy-Login-12ch!"
)

// LoginOutcome desenlace INTERNO (al handler solo llega ok/401 opaco).
type LoginOutcome string

const (
	LoginSuccess     LoginOutcome = "success"
	LoginMFARequired LoginOutcome = "mfa_required"
	LoginInvalid     LoginOutcome = "invalid"
)

// Device huella operativa (base SES-03/SEC-07; no bloquea aquí).
type Device struct {
	IPHash string
	UAHash string
}

// DecideLogin: solo found + verify + !locked + ACTIVE emite.
// mfa decide 200 vs 202. Todo lo demás es Invalid opaco (RN-01, §4.2).
func DecideLogin(found, verifyOK, locked bool, status user.Status, mfa bool) LoginOutcome {
	if !found || !verifyOK || locked || status != user.StatusActive {
		return LoginInvalid
	}
	if mfa {
		return LoginMFARequired
	}
	return LoginSuccess
}

// ShouldLock: a los MaxFails fallos se bloquea.
func ShouldLock(fails int) bool {
	return fails >= LoginMaxFails
}

// LockDuration exponencial 15/30/60... por reincidencia (lockCount ≥1).
func LockDuration(lockCount int) time.Duration {
	if lockCount < 1 {
		lockCount = 1
	}
	d := LoginLockBase
	for i := 1; i < lockCount; i++ {
		d *= 2
		if d > time.Hour {
			return time.Hour
		}
	}
	return d
}
