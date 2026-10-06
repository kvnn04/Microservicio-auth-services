package auth

import (
	"testing"
	"time"
)

func TestDecideRotate_Matriz(t *testing.T) {
	cases := []struct {
		name                       string
		cur, par, grace, sameDev   bool
		flaps                      int
		want                       RotateDecision
	}{
		{"current→rotate", true, false, false, false, 0, DecideRotateCurrent},
		{"current ignora flaps", true, false, true, true, 99, DecideRotateCurrent},
		{"parent+gracia+device→concurrent", false, true, true, true, 0, DecideConcurrent},
		{"parent+gracia+device+flap3→concurrent", false, true, true, true, 3, DecideConcurrent},
		{"4º flap→reuse", false, true, true, true, 4, DecideReuse},
		{"parent fuera gracia→reuse", false, true, false, true, 0, DecideReuse},
		{"parent distinto device→reuse", false, true, true, false, 0, DecideReuse},
		{"antiguo→reuse", false, false, false, false, 0, DecideReuse},
		{"antiguo en gracia→reuse igual", false, false, true, true, 0, DecideReuse},
	}
	for _, tc := range cases {
		if got := DecideRotate(tc.cur, tc.par, tc.grace, tc.sameDev, tc.flaps); got != tc.want {
			t.Errorf("%s: %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestDeviceMatch_Esquemas(t *testing.T) {
	ip, ua := "203.0.113.42", "Mozilla/5.0 Chrome/126.0"
	// Esquema S1 (login/mfa/federated) redondo.
	if !DeviceMatch(fingerprintS1(ip, ua), ip, ua) {
		t.Fatal("S1 exacto")
	}
	// Con puerto (directa sin proxy) matchea por variante stripped.
	if !DeviceMatch(fingerprintS1(ip, ua), ip+":5678", ua) {
		t.Fatal("S1 con puerto")
	}
	// Esquema S2 (passwordless) redondo.
	if !DeviceMatch(fingerprintS2(ip, ua), ip, ua) {
		t.Fatal("S2 exacto")
	}
	// Otro device/IP no matchea (ni gemelo cercano).
	if DeviceMatch(fingerprintS1(ip, ua), "203.0.113.99", ua) {
		t.Fatal("IP distinta no matchea")
	}
	if DeviceMatch(fingerprintS1(ip, ua), ip, "Mozilla/5.0 Firefox/127.0") {
		t.Fatal("UA distinto no matchea")
	}
	// Vacío jamás matchea (familias viejas sin device → decide por
	// ventana/flaps, nunca por match fantasma).
	if DeviceMatch("", ip, ua) {
		t.Fatal("stored vacío no matchea")
	}
}

func TestRotationConsts(t *testing.T) {
	if GraceWindow != 10*time.Second || IdempotencyWindow != 60*time.Second {
		t.Fatal("ventanas 10s/60s")
	}
	if ConcurrentLimit != 3 || ConcurrentWindow != 10*time.Second {
		t.Fatal("anti-flapping 3/10s")
	}
	if RefreshRateIP != 30 || RefreshRateFam != 10 {
		t.Fatal("buckets 30/min ip + 10/min fam")
	}
}
