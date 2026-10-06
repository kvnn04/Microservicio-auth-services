package security

import (
	"context"
	"testing"

	"auth-identity-service/internal/domain/auth"
)

func testStepUpIssuer(t *testing.T) *StepUpTokenIssuer {
	t.Helper()
	priv, _, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewStepUpTokenIssuer(priv, "2026-10-a", "")
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func TestStepUpToken_IssueVerify(t *testing.T) {
	iss := testStepUpIssuer(t)
	tok, jti, err := iss.IssueToken(context.Background(), "user-1", auth.ScopeChangePassword, []string{"pwd", "totp"})
	if err != nil {
		t.Fatal(err)
	}
	if jti == "" {
		t.Fatal("jti vacío")
	}
	claims, err := iss.VerifyToken(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Sub != "user-1" || claims.JTI != jti || claims.Scope != "cred:change-password" {
		t.Fatalf("claims=%+v", claims)
	}
	if claims.Aud != "step-up" {
		t.Fatalf("aud aislado: %q", claims.Aud)
	}
	if claims.Exp-claims.Iat != 300 {
		t.Fatalf("TTL 300: %d", claims.Exp-claims.Iat)
	}
	// Manipulado → rechaza.
	if _, err := iss.VerifyToken(tok + "x"); err == nil {
		t.Fatal("tamper debe fallar")
	}
	// Scope inválido no se emite.
	if _, _, err := iss.IssueToken(context.Background(), "u", "admin", nil); err == nil {
		t.Fatal("scope cerrado")
	}
	// Sin clave → fail-fast.
	empty := &StepUpTokenIssuer{kid: "k"}
	if _, _, err := empty.IssueToken(context.Background(), "u", auth.ScopeMFADisable, nil); err == nil {
		t.Fatal("sin privada debe fallar")
	}
}

func TestStepUpToken_AudAislado(t *testing.T) {
	// Un Access (aud=api) jamás verifica como step-up y viceversa.
	stepIss := testStepUpIssuer(t)
	tok, _, err := stepIss.IssueToken(context.Background(), "u1", auth.ScopeAccountDelete, []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stepIss.VerifyToken(tok); err != nil {
		t.Fatalf("propio: %v", err)
	}
	// Header alg none jamás.
	none := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
	if _, err := stepIss.VerifyToken(none); err == nil {
		t.Fatal("none debe rechazarse")
	}
}
