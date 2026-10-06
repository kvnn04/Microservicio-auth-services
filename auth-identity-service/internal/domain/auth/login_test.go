package auth

import (
	"testing"
	"time"

	"auth-identity-service/internal/domain/user"
)

func TestDecideLogin(t *testing.T) {
	tests := []struct {
		name              string
		found, verify, lock bool
		status            user.Status
		mfa               bool
		want              LoginOutcome
	}{
		{"ok sin mfa", true, true, false, user.StatusActive, false, LoginSuccess},
		{"ok con mfa", true, true, false, user.StatusActive, true, LoginMFARequired},
		{"no existe", false, false, false, "", false, LoginInvalid},
		{"pass mala", true, false, false, user.StatusActive, false, LoginInvalid},
		{"bloqueada", true, true, true, user.StatusActive, false, LoginInvalid},
		{"pending aunque ok", true, true, false, user.StatusPendingVerification, false, LoginInvalid},
		{"locked aunque ok", true, true, false, user.StatusLocked, false, LoginInvalid},
		{"borrada aunque ok", true, true, false, user.StatusSoftDeleted, false, LoginInvalid},
		{"federated-only (sin verify)", true, false, false, user.StatusActive, false, LoginInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecideLogin(tt.found, tt.verify, tt.lock, tt.status, tt.mfa); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestShouldLockAndDuration(t *testing.T) {
	if ShouldLock(4) || !ShouldLock(5) || !ShouldLock(9) {
		t.Fatal("umbral 5")
	}
	if LockDuration(1) != 15*time.Minute || LockDuration(2) != 30*time.Minute || LockDuration(3) != 60*time.Minute {
		t.Fatal("exponencial 15/30/60")
	}
	if LockDuration(0) != 15*time.Minute {
		t.Fatal("mínimo 15")
	}
}
