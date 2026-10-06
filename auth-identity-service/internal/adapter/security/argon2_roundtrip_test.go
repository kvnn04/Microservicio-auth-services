package security

import (
	"context"
	"testing"
)

func TestArgon2Roundtrip(t *testing.T) {
	h := NewArgon2Hasher(nil)
	ctx := context.Background()
	enc, err := h.Hash(ctx, "Str0ng!Passw0rd-2026")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.Verify(ctx, "Str0ng!Passw0rd-2026", enc)
	if err != nil || !ok {
		t.Fatalf("verify válido: ok=%v err=%v hash=%s", ok, err, enc)
	}
	ok, _ = h.Verify(ctx, "Wrong!Passw0rd-2026", enc)
	if ok {
		t.Fatal("password mala debe fallar")
	}
}
