package user

import (
	"testing"
	"time"
)

func TestNewUser(t *testing.T) {
	now := time.Now().UTC()
	u, err := NewUser("0193a2ef-test-id", "Test@Example.com", "test@example.com", "$argon2id$v=19$m=65536,t=3,p=4$salt$hash", "v2026.10", "v2026.10", now)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if u.Status != StatusPendingVerification {
		t.Fatalf("status = %q", u.Status)
	}
	if u.CanAuthenticate() {
		t.Fatal("PENDING no debe autenticar")
	}
	if _, err := NewUser("", "a@b.co", "a@b.co", "$argon2id$h", "v", "v", now); err == nil {
		t.Fatal("esperaba error sin id")
	}
	if _, err := NewUser("id", "a@b.co", "", "$argon2id$h", "v", "v", now); err == nil {
		t.Fatal("esperaba error sin email")
	}
	if _, err := NewUser("id", "a@b.co", "a@b.co", "", "v", "v", now); err == nil {
		t.Fatal("esperaba error sin hash")
	}
	if _, err := NewUser("id", "a@b.co", "a@b.co", "$argon2id$h", "", "v", now); err == nil {
		t.Fatal("esperaba error sin terms")
	}
}

func TestCanAuthenticateOnlyActive(t *testing.T) {
	u := &User{Status: StatusActive}
	if !u.CanAuthenticate() {
		t.Fatal("ACTIVE debe autenticar")
	}
	for _, s := range []Status{StatusPendingVerification, StatusLocked, StatusSoftDeleted} {
		u.Status = s
		if u.CanAuthenticate() {
			t.Fatalf("%s no debe autenticar", s)
		}
	}
	var nilUser *User
	if nilUser.CanAuthenticate() {
		t.Fatal("nil no debe autenticar")
	}
}
