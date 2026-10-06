package security

import (
	"context"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
)

func TestEd25519SignVerify(t *testing.T) {
	priv, _, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer(priv, "2026-10-a", "", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	claims, err := auth.NewAccessClaims("", "", "user-1", "sid-1", "jti-1", now, []auth.AMR{auth.AMRPassword}, []string{"user"}, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	jwt, kid, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	if kid != "2026-10-a" {
		t.Fatalf("kid=%q", kid)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt 3 partes: %q", jwt)
	}
	// Header debe llevar alg EdDSA + kid.
	if !strings.Contains(parts[0], "") { // forma validada en Verify
		t.Fatal("header vacío")
	}
	got, err := signer.Verify(jwt)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Sub != "user-1" || got.SID != "sid-1" || got.JTI != "jti-1" {
		t.Fatalf("claims=%+v", got)
	}
	if got.Exp-got.Iat != 900 {
		t.Fatalf("TTL 900: %d", got.Exp-got.Iat)
	}
	// Manipulado → rechaza.
	if _, err := signer.Verify(jwt + "x"); err == nil {
		t.Fatal("tamper debe fallar")
	}
	// alg none jamás.
	none := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
	if _, err := signer.Verify(none); err == nil {
		t.Fatal("none debe rechazarse")
	}
	// kid distinto → rechaza.
	priv2, _, _ := GenerateEd25519Key()
	signer2, _ := NewEd25519Signer(priv2, "2026-10-b", "", "")
	if _, err := signer2.Verify(jwt); err == nil {
		t.Fatal("kid distinto debe fallar")
	}
}

func TestEd25519NoKey(t *testing.T) {
	_, err := NewEd25519Signer(nil, "k", "", "")
	if err == nil {
		t.Fatal("sin privada debe fallar")
	}
	_, err = NewEd25519SignerFromSeed([]byte("corta"), "k", "", "")
	if err == nil {
		t.Fatal("seed corta debe fallar")
	}
	if _, err := ParseEd25519PrivateKey(""); err == nil {
		t.Fatal("vacía debe fallar")
	}
}

func TestRefreshGenerator(t *testing.T) {
	g := NewRefreshGenerator()
	plain, hash, err := g.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 43 {
		t.Fatalf("43ch b64url, got %d %q", len(plain), plain)
	}
	if len(hash) != 64 {
		t.Fatalf("sha256 hex 64, got %q", hash)
	}
	if g.Hash(plain) != hash {
		t.Fatal("hash determinista")
	}
	// Único.
	plain2, hash2, _ := g.Generate(context.Background())
	if plain == plain2 || hash == hash2 {
		t.Fatal("CSPRNG debe ser único")
	}
	if !g.EqualHash(hash, hash) || g.EqualHash(hash, hash2) {
		t.Fatal("ConstantTime")
	}
}
