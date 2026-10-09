package security

import (
	"context"
	"strings"
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

// F-22: params por ambiente + pisos + compat con hashes viejos.
func TestArgon2CustomParams(t *testing.T) {
	ctx := context.Background()
	h := NewArgon2HasherWithParams(nil, Argon2Params{Memory: 8192, Iterations: 1, Parallelism: 1})
	enc, err := h.Hash(ctx, "Str0ng!Passw0rd-2026")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"$argon2id$v=19$", "m=8192,t=1,p=1$"} {
		if !strings.Contains(enc, want) {
			t.Fatalf("PHC debe llevar params custom: %s", enc)
		}
	}
	if ok, err := h.Verify(ctx, "Str0ng!Passw0rd-2026", enc); err != nil || !ok {
		t.Fatalf("verify custom: %v %v", ok, err)
	}
	// Hash OWASP viejo verifica con hasher custom (params viajan en PHC).
	old := NewArgon2Hasher(nil)
	oldEnc, _ := old.Hash(ctx, "Str0ng!Passw0rd-2026")
	if ok, err := h.Verify(ctx, "Str0ng!Passw0rd-2026", oldEnc); err != nil || !ok {
		t.Fatalf("compat hacia atrás: %v %v", ok, err)
	}
	// Pisos: valores ridículos se elevan, nunca debilitan en silencio.
	floored := NewArgon2HasherWithParams(nil, Argon2Params{Memory: 1, Iterations: 0, Parallelism: 0})
	if floored.params.Memory != minMemory || floored.params.Iterations != minIterations || floored.params.Parallelism != minParallelism {
		t.Fatalf("sin pisos: %+v", floored.params)
	}
}
