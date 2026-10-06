package user

import (
	"strings"
	"testing"
)

func TestDecideProbe(t *testing.T) {
	tests := []struct {
		name          string
		found         bool
		throttleAllow bool
		want          ProbeOutcome
	}{
		{"nuevo prosigue", false, true, ProbeUnique},
		{"nuevo ignora throttle", false, false, ProbeUnique},
		{"existente notifica", true, true, ProbeShadowDuplicate},
		{"existente throttled", true, false, ProbeThrottledNotify},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecideProbe(tt.found, tt.throttleAllow); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
			if ShouldNotify(tt.found, tt.throttleAllow) != (tt.want == ProbeShadowDuplicate) {
				t.Fatalf("ShouldNotify inconsistente para %v", tt)
			}
		})
	}
}

func TestUniquenessHashDeterminista(t *testing.T) {
	// Misma normalización → mismo hash; casing distinto colapsa (RN-02).
	n1, _, _ := Normalize("Test@Example.com ")
	n2, _, _ := Normalize("test@example.com")
	if n1 != n2 {
		t.Fatal("normalización debe colapsar casing/espacios")
	}
	// Plus-tag y puntos se preservan (no colapsan identidades distintas).
	n3, _, _ := Normalize("user+tag@example.com")
	n4, _, _ := Normalize("user@example.com")
	if n3 == n4 {
		t.Fatal("plus-tag debe preservarse")
	}
	if !strings.Contains(n3, "+tag") {
		t.Fatalf("plus-tag perdido: %q", n3)
	}
}
