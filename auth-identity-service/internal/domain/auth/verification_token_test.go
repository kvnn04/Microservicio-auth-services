package auth

import (
	"testing"
	"time"
)

func TestVerificationTokenLifecycle(t *testing.T) {
	now := time.Now().UTC()
	tok := NewVerificationToken("user-1", "hash123", now)
	if tok.MaxAttempts != VerificationMaxAttempts {
		t.Fatalf("max = %d", tok.MaxAttempts)
	}
	if tok.IsExpired(now) {
		t.Fatal("no debe estar expirado al crear")
	}
	if err := tok.CanAttempt(now); err != nil {
		t.Fatalf("debe permitir: %v", err)
	}
	if err := tok.CanAttempt(now.Add(VerificationTTL + time.Second)); err != ErrTokenExpired {
		t.Fatalf("got %v", err)
	}
	tok.Consumed = true
	if err := tok.CanAttempt(now); err != ErrTokenConsumed {
		t.Fatalf("got %v", err)
	}
	tok.Consumed = false
	tok.Attempts = VerificationMaxAttempts
	if err := tok.CanAttempt(now); err != ErrTokenMaxAttempts {
		t.Fatalf("got %v", err)
	}
}
