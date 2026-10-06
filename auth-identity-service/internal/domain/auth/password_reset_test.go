package auth

import (
	"strings"
	"testing"
	"time"
)

func TestParseResetToken(t *testing.T) {
	raw := strings.Repeat("A", 43) // 32B cero
	h1, err := ParseResetToken(raw)
	if err != nil {
		t.Fatalf("válido: %v", err)
	}
	if len(h1) != 64 {
		t.Fatalf("sha256 hex 64, got %q", h1)
	}
	h2, _ := ParseResetToken("  " + raw + "  ")
	if h1 != h2 {
		t.Fatal("trim canónico")
	}
	for name, bad := range map[string]string{
		"vacío": "", "espacios": "   ", "no-b64": "!!!no-base64!!!",
		"corto": "YWJj", "largo": raw + "A", "otp-8d": "12345678",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseResetToken(bad); err == nil {
				t.Fatal("debía fallar formato")
			}
		})
	}
}

func TestPasswordResetRecord_Alive(t *testing.T) {
	now := time.Now().UTC()
	if PwdResetTTL != 15*time.Minute {
		t.Fatalf("TTL 15min, got %v", PwdResetTTL)
	}
	base := &PasswordResetRecord{ExpiresAt: now.Add(PwdResetTTL)}
	if !base.Alive(now) {
		t.Fatal("vivo")
	}
	cases := []struct {
		name string
		mut  func(*PasswordResetRecord)
	}{
		{"expirado", func(r *PasswordResetRecord) { r.ExpiresAt = now.Add(-time.Second) }},
		{"consumido", func(r *PasswordResetRecord) { r.Consumed = true }},
		{"superseded", func(r *PasswordResetRecord) { r.Superseded = true }},
		{"3 intentos", func(r *PasswordResetRecord) { r.Attempts = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &PasswordResetRecord{ExpiresAt: now.Add(PwdResetTTL)}
			tc.mut(r)
			if r.Alive(now) {
				t.Fatal("debía estar inactivo")
			}
		})
	}
	r2 := &PasswordResetRecord{ExpiresAt: now.Add(PwdResetTTL), Attempts: 2}
	if !r2.Alive(now) {
		t.Fatal("2 intentos aún vivo")
	}
	var nilRec *PasswordResetRecord
	if nilRec.Alive(now) {
		t.Fatal("nil no vivo")
	}
}

func TestPwdResetConsts(t *testing.T) {
	if PwdResetTokenBytes != 32 || PwdResetMaxAttempts != 3 {
		t.Fatal("32B/3")
	}
	if PwdResetCooldown != 60*time.Second || PwdResetMaxDay != 5 {
		t.Fatal("60s/5-día")
	}
}
