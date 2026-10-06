package user

import (
	"testing"
	"time"
)

func TestActivate(t *testing.T) {
	now := time.Now().UTC()
	u := &User{Status: StatusPendingVerification}
	if err := u.Activate(now); err != nil {
		t.Fatalf("activate PENDING: %v", err)
	}
	if u.Status != StatusActive || !u.CanAuthenticate() {
		t.Fatal("debe quedar ACTIVE y autenticar")
	}
	// Doble Activate → error.
	if err := u.Activate(now); err == nil {
		t.Fatal("doble Activate debe fallar")
	}
	// LOCKED / SOFT_DELETED nunca se activan por verify.
	for _, s := range []Status{StatusLocked, StatusSoftDeleted, StatusActive} {
		v := &User{Status: s}
		if err := v.Activate(now); err == nil {
			t.Fatalf("%s no debe activar", s)
		}
	}
	var nilUser *User
	if err := nilUser.Activate(now); err == nil {
		t.Fatal("nil no debe activar")
	}
}
