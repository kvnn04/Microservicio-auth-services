package user

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantNorm string
		wantOrig string
		wantErr  bool
	}{
		{name: "trim y lowercase", raw: "  Test@Example.COM ", wantNorm: "test@example.com", wantOrig: "Test@Example.COM"},
		{name: "plus tag preservado", raw: "User+tag@Example.com", wantNorm: "user+tag@example.com", wantOrig: "User+tag@Example.com"},
		{name: "puntos locales preservados", raw: "First.Last@Example.com", wantNorm: "first.last@example.com", wantOrig: "First.Last@Example.com"},
		{name: "formato invalido sin arroba", raw: "no-es-email", wantErr: true},
		{name: "formato invalido sin tld", raw: "a@b.c", wantErr: true},
		{name: "emoji rechazado", raw: "user😀@example.com", wantErr: true},
		{name: "control rechazado", raw: "user\x00@example.com", wantErr: true},
		{name: "newline rechazado", raw: "user\n@example.com", wantErr: true},
		{name: "vacio", raw: "   ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm, orig, err := Normalize(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("esperaba error para %q", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if norm != tt.wantNorm {
				t.Fatalf("normalized = %q, want %q", norm, tt.wantNorm)
			}
			if orig != tt.wantOrig {
				t.Fatalf("original = %q, want %q", orig, tt.wantOrig)
			}
		})
	}
	// >254
	local := ""
	for i := 0; i < 250; i++ {
		local += "a"
	}
	if _, _, err := Normalize(local + "@example.com"); err == nil {
		t.Fatal("esperaba error >254")
	}
}

func TestDomainOf(t *testing.T) {
	if got := DomainOf("test@example.com"); got != "example.com" {
		t.Fatalf("got %q", got)
	}
	if got := DomainOf("sin-arroba"); got != "" {
		t.Fatalf("got %q", got)
	}
}
