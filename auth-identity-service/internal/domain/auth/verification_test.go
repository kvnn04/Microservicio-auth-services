package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func validTokenPlain() string {
	b := make([]byte, VerifyTokenBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestParseTokenInput(t *testing.T) {
	good := validTokenPlain()
	h, err := ParseTokenInput("  "+good+"  ")
	if err != nil || h == "" {
		t.Fatalf("token válido rechazado: %v", err)
	}
	// 31B debe rechazar.
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 31))
	if _, err := ParseTokenInput(short); !errors.Is(err, ErrValidation) {
		t.Fatalf("31B debe ser ErrValidation, got %v", err)
	}
	// No base64.
	if _, err := ParseTokenInput("!!!no-base64!!!"); !errors.Is(err, ErrValidation) {
		t.Fatalf("no-b64 debe ser ErrValidation, got %v", err)
	}
	// Vacío.
	if _, err := ParseTokenInput("   "); !errors.Is(err, ErrValidation) {
		t.Fatalf("vacío debe ser ErrValidation, got %v", err)
	}
}

func TestParseOTPInput(t *testing.T) {
	if _, err := ParseOTPInput("87654321"); err != nil {
		t.Fatalf("OTP 8 dígitos rechazado: %v", err)
	}
	for _, bad := range []string{"1234567", "123456789", "abcdefgh", "1234 567", ""} {
		if _, err := ParseOTPInput(bad); !errors.Is(err, ErrValidation) {
			t.Fatalf("%q debe ser ErrValidation, got %v", bad, err)
		}
	}
}

func TestVerificationRecordIsAlive(t *testing.T) {
	now := time.Now().UTC()
	alive := &VerificationRecord{UserID: "u1", TokenHash: "h", ExpiresAt: now.Add(TTL2()), Attempts: 0}
	if !alive.IsAlive(now) || !alive.CanAttempt(now) {
		t.Fatal("debe estar vivo")
	}
	for _, tc := range []struct {
		name string
		mut  func(*VerificationRecord)
	}{
		{"expirado", func(v *VerificationRecord) { v.ExpiresAt = now.Add(-time.Minute) }},
		{"consumido", func(v *VerificationRecord) { v.Consumed = true }},
		{"superseded", func(v *VerificationRecord) { v.Superseded = true }},
		{"quemado", func(v *VerificationRecord) { v.Attempts = VerifyMaxAttempts }},
	} {
		v := &VerificationRecord{UserID: "u1", TokenHash: "h", ExpiresAt: now.Add(time.Minute)}
		tc.mut(v)
		if v.IsAlive(now) {
			t.Fatalf("%s debe ser !IsAlive", tc.name)
		}
	}
	var nilRec *VerificationRecord
	if nilRec.IsAlive(now) {
		t.Fatal("nil debe ser !IsAlive")
	}
}

func TTL2() time.Duration { return VerifyTTL }
