package user

import (
	"strings"
	"testing"
)

func TestNewFederatedIdentity(t *testing.T) {
	f, err := NewFederatedIdentity(ProviderGoogle, "google123", "user-1", "test@example.com")
	if err != nil || f.Provider != ProviderGoogle {
		t.Fatalf("err=%v f=%+v", err, f)
	}
	// Provider inválido.
	if _, err := NewFederatedIdentity("facebook", "s", "u", "a@b.co"); err == nil {
		t.Fatal("provider inválido debe fallar")
	}
	// Sub vacío / largo / control.
	if _, err := NewFederatedIdentity(ProviderGoogle, "", "u", "a@b.co"); err == nil {
		t.Fatal("sub vacío debe fallar")
	}
	if _, err := NewFederatedIdentity(ProviderGoogle, strings.Repeat("s", 256), "u", "a@b.co"); err == nil {
		t.Fatal("sub >255 debe fallar")
	}
	if _, err := NewFederatedIdentity(ProviderGoogle, "ab\x00cd", "u", "a@b.co"); err == nil {
		t.Fatal("sub con control debe fallar")
	}
	if _, err := NewFederatedIdentity(ProviderGoogle, "s", "", "a@b.co"); err == nil {
		t.Fatal("sin userID debe fallar")
	}
	if !ProviderGoogle.IsSupported() || Provider("x").IsSupported() {
		t.Fatal("IsSupported")
	}
}
