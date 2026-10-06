package user

import (
	"strings"
	"testing"
	"time"
)

func TestParseEmailChangeToken(t *testing.T) {
	raw := strings.Repeat("A", 43) // 32B cero
	h1, err := ParseEmailChangeToken(raw)
	if err != nil {
		t.Fatalf("válido: %v", err)
	}
	if len(h1) != 64 {
		t.Fatalf("sha256 hex 64, got %q", h1)
	}
	h2, _ := ParseEmailChangeToken("  " + raw + "  ")
	if h1 != h2 {
		t.Fatal("trim canónico")
	}
	for name, bad := range map[string]string{
		"vacío": "", "espacios": "   ", "no-b64": "!!!no-base64!!!",
		"corto": "YWJj", "largo": raw + "A",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEmailChangeToken(bad); err == nil {
				t.Fatal("debía fallar formato")
			}
		})
	}
}

func TestEmailChangeRecord_Alive(t *testing.T) {
	now := time.Now().UTC()
	if EmailChangeTTL != 15*time.Minute {
		t.Fatalf("TTL 15min, got %v", EmailChangeTTL)
	}
	base := &EmailChangeRecord{ExpiresAt: now.Add(EmailChangeTTL)}
	if !base.Alive(now) {
		t.Fatal("vivo")
	}
	cases := []struct {
		name string
		mut  func(*EmailChangeRecord)
	}{
		{"expirado", func(r *EmailChangeRecord) { r.ExpiresAt = now.Add(-time.Second) }},
		{"consumido", func(r *EmailChangeRecord) { r.Consumed = true }},
		{"superseded", func(r *EmailChangeRecord) { r.Superseded = true }},
		{"3 intentos", func(r *EmailChangeRecord) { r.Attempts = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &EmailChangeRecord{ExpiresAt: now.Add(EmailChangeTTL)}
			tc.mut(r)
			if r.Alive(now) {
				t.Fatal("debía estar inactivo")
			}
		})
	}
	var nilRec *EmailChangeRecord
	if nilRec.Alive(now) {
		t.Fatal("nil no vivo")
	}
}

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"nuevo@example.com": "n***@example.com",
		"a@b.co":            "a***@b.co",
		"":                 "***",
		"sin-arroba":       "***",
		"@dominio.com":     "***",
	}
	for in, want := range cases {
		if got := MaskEmail(in); got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
	// El dominio queda visible (typo/abuso reconocible), el local no.
	masked := MaskEmail("victima@example.com")
	if len(masked) >= len("victima@example.com") || !strings.HasSuffix(masked, "@example.com") {
		t.Fatalf("mask: %q", masked)
	}
}

func TestEmailChangeConsts(t *testing.T) {
	if EmailChangeTokenBytes != 32 || EmailChangeMaxAttempts != 3 {
		t.Fatal("32B/3")
	}
	if EmailChangeRatePerHour != 3 || EmailChangeCooldown != 60*time.Second || EmailChangeMaxDay != 5 {
		t.Fatal("3/h, 60s/5-día")
	}
}
