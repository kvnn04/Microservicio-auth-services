package security

import (
	"context"
	"testing"

	"auth-identity-service/internal/domain/auth"
)

func TestBackupHasherRoundtrip(t *testing.T) {
	ctx := context.Background()
	pepper := []byte("pepper-32bytes-1234567890123456")
	h := NewBackupCodeIssuer(pepper, nil)
	plain, hash, err := h.Generate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 10 {
		t.Fatalf("canónico 10ch: %q", plain)
	}
	if got := auth.Display(plain); len(got) != 11 || got[4] != '-' {
		t.Fatalf("display: %q", got)
	}
	canonical, err := auth.Canonicalize(plain)
	if err != nil {
		t.Fatal(err)
	}
	if h.Hash(canonical) != hash {
		t.Fatal("hash determinista")
	}
	if !h.Verify(ctx, canonical, hash) {
		t.Fatal("verify actual")
	}
	if h.Verify(ctx, "ZZZZ-ZZZZZZ", hash) {
		t.Fatal("distinto no verifica")
	}
}

func TestBackupHasherRotacion(t *testing.T) {
	ctx := context.Background()
	oldPepper := []byte("old-pepper-32bytes-1234567890123")
	newPepper := []byte("new-pepper-32bytes-1234567890123")
	oldHash := NewBackupCodeIssuer(oldPepper, nil).Hash("AAAAAAAAAA")
	// Tras rotar: el viejo verifica vía prev.
	rotated := NewBackupCodeIssuer(newPepper, oldPepper)
	if !rotated.Verify(ctx, "AAAAAAAAAA", oldHash) {
		t.Fatal("prev debe verificar")
	}
	// Sin prev configurado: el viejo ya no verifica.
	fresh := NewBackupCodeIssuer(newPepper, nil)
	if fresh.Verify(ctx, "AAAAAAAAAA", oldHash) {
		t.Fatal("sin prev no debe verificar")
	}
	// Hash nuevo difiere del viejo.
	if rotated.Hash("AAAAAAAAAA") == oldHash {
		t.Fatal("rotación debe cambiar hash")
	}
}
