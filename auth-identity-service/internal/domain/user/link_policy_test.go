package user

import (
	"testing"
	"time"
)

func TestCountFactors(t *testing.T) {
	if CountFactors(true, 0) != 1 || CountFactors(false, 1) != 1 {
		t.Fatal("1 factor")
	}
	if CountFactors(true, 2) != 3 {
		t.Fatal("3 factores")
	}
	if CountFactors(false, 0) != 0 {
		t.Fatal("0 factores")
	}
}

func TestCanUnlink(t *testing.T) {
	// Último inamovible: solo password, solo 1 federado.
	if ok, code := CanUnlink(true, 0, ProviderGoogle); ok || code != "LAST_AUTH_FACTOR" {
		t.Fatal("único password inamovible")
	}
	if ok, _ := CanUnlink(false, 1, ProviderGoogle); ok {
		t.Fatal("único federado inamovible")
	}
	// Con 2 factores sí.
	if ok, _ := CanUnlink(true, 1, ProviderGoogle); !ok {
		t.Fatal("password+google debe permitir quitar google")
	}
	if ok, _ := CanUnlink(false, 2, ProviderGoogle); !ok {
		t.Fatal("2 federados debe permitir quitar uno")
	}
}

func TestRequireFreshAuth(t *testing.T) {
	now := time.Now().UTC()
	if err := RequireFreshAuth(now.Add(-time.Minute), now, 0); err != nil {
		t.Fatalf("1min fresco: %v", err)
	}
	if err := RequireFreshAuth(now.Add(-4*time.Minute-59*time.Second), now, 0); err != nil {
		t.Fatal("4:59 debe pasar")
	}
	if err := RequireFreshAuth(now.Add(-5*time.Minute-time.Second), now, 0); err == nil {
		t.Fatal("5:01 debe fallar")
	}
	if err := RequireFreshAuth(time.Time{}, now, 0); err == nil {
		t.Fatal("cero debe fallar")
	}
}
