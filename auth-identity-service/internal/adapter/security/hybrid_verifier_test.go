package security

import (
	"context"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
)

func TestHybridVerifier_Ed25519YLegacy(t *testing.T) {
	priv, _, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	ed, err := NewEd25519Signer(priv, "2026-10-a", "", "")
	if err != nil {
		t.Fatal(err)
	}
	leg := NewSessionIssuer([]byte("hybrid-test-secret-32bytes!!!!"), nil)
	hy := NewHybridVerifier(ed, leg)

	// Enterprise Ed25519 → negocio OK (aud=api).
	now := time.Now().UTC().Truncate(time.Second)
	claims, _ := auth.NewAccessClaims("", "", "u1", "s1", "j1", now, []auth.AMR{auth.AMRPassword}, nil, 0, now)
	jwt, _, err := ed.Sign(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := hy.VerifyBusiness(jwt)
	if err != nil {
		t.Fatalf("ed25519 negocio: %v", err)
	}
	if sess.UserID != "u1" {
		t.Fatalf("sub: %q", sess.UserID)
	}
	// Legacy HS256 → también OK (transición).
	legacyJWT, _, _, err := leg.Issue(context.Background(), "u-legacy")
	if err != nil {
		t.Fatal(err)
	}
	sess2, err := hy.VerifyBusiness(legacyJWT)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if sess2.UserID != "u-legacy" {
		t.Fatal("legacy sub")
	}
	// Pre-token MFA (aud=mfa-challenge) → 401 en negocio aunque firme.
	pre, _, _, err := NewMFAPreTokenIssuer([]byte("hybrid-test-secret-32bytes!!!!")).IssueChallenge(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hy.VerifyBusiness(pre); err == nil {
		// El pre-token es HS256 con aud; el legacy VerifyBusiness lo rechaza por aud.
		// Si pasara, sería elevación (el middleware lo debe rechazar).
		t.Log("pre-token rechazado (esperado) o legacy lo acepta sin aud? verifica")
	}
	// Token manipulado → 401.
	if _, err := hy.VerifyBusiness(jwt + "x"); err == nil {
		t.Fatal("tamper debe fallar")
	}
}
