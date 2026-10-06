package shared

import (
	"errors"
	"testing"
)

func TestValidateConsentInput(t *testing.T) {
	tests := []struct {
		name     string
		accepted bool
		tv, pv   string
		wantErr  error
	}{
		{"ok", true, "v2026.10", "v2026.10", nil},
		{"no aceptado", false, "v2026.10", "v2026.10", ErrTermsRequired},
		{"formato malo terms", true, "2026.10", "v2026.10", ErrInvalidFormat},
		{"formato malo privacy", true, "v2026.10", "latest", ErrInvalidFormat},
		{"vacías", true, "", "", ErrInvalidFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConsentInput(tt.accepted, tt.tv, tt.pv)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("inesperado: %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLegalDocumentFormat(t *testing.T) {
	d := LegalDocument{DocType: DocTerms, Version: "v2026.10"}
	if err := d.ValidateFormat(); err != nil {
		t.Fatal(err)
	}
	if err := (LegalDocument{DocType: "cookies", Version: "v2026.10"}).ValidateFormat(); err == nil {
		t.Fatal("cookies vetado")
	}
	if err := (LegalDocument{DocType: DocPrivacy, Version: "v10"}).ValidateFormat(); err == nil {
		t.Fatal("formato debe fallar")
	}
}

func TestNewConsentRecord(t *testing.T) {
	r, err := NewConsentRecord("u1", DocTerms, "v2026.10", "iph", "uah", "classic", "req-1")
	if err != nil || r.DocType != DocTerms {
		t.Fatalf("err=%v r=%+v", err, r)
	}
	// UNIQUE conceptual: mismo user/doc/version se resuelve con ON CONFLICT.
	if _, err := NewConsentRecord("", DocTerms, "v2026.10", "iph", "uah", "classic", "req-1"); err == nil {
		t.Fatal("sin userID debe fallar")
	}
	if _, err := NewConsentRecord("u1", DocTerms, "bad", "iph", "uah", "classic", "req-1"); err == nil {
		t.Fatal("versión mala debe fallar")
	}
}

func TestTermsOutdatedError(t *testing.T) {
	e := &TermsOutdatedError{ActiveTerms: "v2026.10", ActivePrivacy: "v2026.10"}
	if !errors.Is(e, ErrTermsOutdated) {
		t.Fatal("debe envolver ErrTermsOutdated")
	}
}
