package auth

import (
	"testing"
	"time"
)

func TestParsePlessToken(t *testing.T) {
	// 32B fijos → 43ch b64url.
	raw := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
	if len(raw) != 43 {
		t.Fatalf("fixture debe ser 43ch, got %d", len(raw))
	}
	h1, err := ParsePlessToken(raw)
	if err != nil {
		t.Fatalf("válido: %v", err)
	}
	if len(h1) != 64 {
		t.Fatalf("sha256 hex 64, got %q", h1)
	}
	h2, _ := ParsePlessToken("  " + raw + "  ")
	if h1 != h2 {
		t.Fatal("trim canónico")
	}
	cases := []struct {
		name string
		raw  string
	}{
		{"vacío", ""},
		{"espacios", "   "},
		{"no-b64", "!!!no-base64!!!"},
		{"corto", "YWJj"},
		{"largo-33B", raw + "A"},
		{"otp-8d", "12345678"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePlessToken(tc.raw); err == nil {
				t.Fatal("debía fallar formato")
			}
		})
	}
}

func TestParsePlessOTP(t *testing.T) {
	h, err := ParsePlessOTP("87654321")
	if err != nil || len(h) != 64 {
		t.Fatalf("válido: %v %q", err, h)
	}
	for _, bad := range []string{"", "1234567", "123456789", "abcdefgh", "1234 567", "1234567a"} {
		if _, err := ParsePlessOTP(bad); err == nil {
			t.Fatalf("debía fallar: %q", bad)
		}
	}
}

func TestPasswordlessRecord_Alive(t *testing.T) {
	now := time.Now().UTC()
	base := &PasswordlessRecord{ExpiresAt: now.Add(PlessTTL)}
	if !base.Alive(now) {
		t.Fatal("vivo")
	}
	if PlessTTL != 10*time.Minute {
		t.Fatalf("TTL 10min, got %v", PlessTTL)
	}
	cases := []struct {
		name string
		mut  func(*PasswordlessRecord)
	}{
		{"expirado", func(r *PasswordlessRecord) { r.ExpiresAt = now.Add(-time.Second) }},
		{"consumido", func(r *PasswordlessRecord) { r.Consumed = true }},
		{"superseded", func(r *PasswordlessRecord) { r.Superseded = true }},
		{"3 intentos", func(r *PasswordlessRecord) { r.Attempts = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &PasswordlessRecord{ExpiresAt: now.Add(PlessTTL)}
			tc.mut(r)
			if r.Alive(now) {
				t.Fatal("debía estar inactivo")
			}
		})
	}
	r2 := &PasswordlessRecord{ExpiresAt: now.Add(PlessTTL), Attempts: 2}
	if !r2.Alive(now) {
		t.Fatal("2 intentos aún vivo")
	}
	var nilRec *PasswordlessRecord
	if nilRec.Alive(now) {
		t.Fatal("nil no vivo")
	}
}

func TestRiskOf(t *testing.T) {
	emit := NewPlessContext("192.168.1.10", "Mozilla/5.0 (Windows) Chrome/120")
	same := NewPlessContext("192.168.1.10", "Mozilla/5.0 (Windows) Chrome/120")
	if got := RiskOf(emit, same); got != "low" {
		t.Fatalf("mismo contexto low, got %q", got)
	}
	// Mismo /16, distinta IP, misma familia → low.
	same16 := NewPlessContext("192.168.9.99", "Mozilla/5.0 (Mac) Chrome/121")
	if got := RiskOf(emit, same16); got != "low" {
		t.Fatalf("/16+familia low, got %q", got)
	}
	// /16 distinto → high.
	diffIP := NewPlessContext("10.20.30.40", "Mozilla/5.0 (Windows) Chrome/120")
	if got := RiskOf(emit, diffIP); got != "high" {
		t.Fatalf("IP distinta high, got %q", got)
	}
	// Misma IP, UA radicalmente distinta → high.
	diffUA := NewPlessContext("192.168.1.10", "okhttp/4.12")
	if got := RiskOf(emit, diffUA); got != "high" {
		t.Fatalf("UA distinta high, got %q", got)
	}
	// Vacío → high (fail-safe alerta).
	if got := RiskOf(PlessContext{}, PlessContext{}); got != "high" {
		t.Fatalf("vacío high, got %q", got)
	}
}

func TestUAFamily_MaskIP(t *testing.T) {
	if got := MaskIP24("192.168.1.10"); got != "192.168.1.0" {
		t.Fatalf("/24: %q", got)
	}
	if got := MaskIP16("192.168.1.10"); got != "192.168.0.0" {
		t.Fatalf("/16: %q", got)
	}
	if MaskIP24("no-ip") != "no-ip" {
		t.Fatal("no-ip tal cual")
	}
	for ua, want := range map[string]string{
		"Mozilla/5.0 Chrome/120": "chrome",
		"okhttp/4.12.0":          "okhttp",
		"curl/8.0":               "curl",
		"":                      "unknown",
		"Mozilla/5.0 Firefox/121": "firefox",
	} {
		if got := UAFamily(ua); got != want {
			t.Fatalf("ua %q: got %q want %q", ua, got, want)
		}
	}
}

func TestPlessConsts(t *testing.T) {
	if PlessTokenBytes != 32 || PlessOTPLen != 8 || PlessMaxAttempts != 3 {
		t.Fatal("32B/8d/3")
	}
	if PlessCooldown != 60*time.Second || PlessMaxDay != 5 {
		t.Fatal("60s/5-día")
	}
}
