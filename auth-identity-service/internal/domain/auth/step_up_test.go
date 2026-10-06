package auth

import (
	"testing"
	"time"
)

func TestStepUpScope_Valid(t *testing.T) {
	valid := []StepUpScope{
		ScopeChangePassword, ScopeChangeEmail,
		ScopeMFADisable, ScopeMFARotate,
		ScopeFederatedLink, ScopeFederatedUnlink,
		ScopeBackupRegen, ScopeAPIKeysWrite,
		ScopeAccountDelete, ScopeRolesChange,
	}
	if len(valid) != 10 {
		t.Fatalf("10 scopes, got %d", len(valid))
	}
	seen := map[StepUpScope]bool{}
	for _, s := range valid {
		if string(s) == "" || seen[s] {
			t.Fatalf("scope vacío/duplicado: %q", s)
		}
		seen[s] = true
		if !s.Valid() {
			t.Fatalf("debía ser válido: %q", s)
		}
	}
	for _, bad := range []StepUpScope{"", "admin", "cred:*", "CRED:CHANGE-PASSWORD", "mfa:delete"} {
		if bad.Valid() {
			t.Fatalf("debía ser inválido: %q", bad)
		}
	}
}

func TestDecideStepUp(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name    string
		auth    time.Time
		factors bool
		want    StepUpDecision
	}{
		{"fresco 1min con factores", now.Add(-time.Minute), true, StepUpFastPass},
		{"fresco límite 4:59", now.Add(-299 * time.Second), true, StepUpFastPass},
		{"stale 5:01 con factores", now.Add(-301 * time.Second), true, StepUpRequireChallenge},
		{"stale 1h con factores", now.Add(-time.Hour), true, StepUpRequireChallenge},
		{"fresco federated-only", now.Add(-time.Minute), false, StepUpFastPass},
		{"stale federated-only", now.Add(-time.Hour), false, StepUpRequireRelogin},
		{"cero con factores", time.Time{}, true, StepUpRequireChallenge},
		{"cero sin factores", time.Time{}, false, StepUpRequireRelogin},
		{"futuro con factores", now.Add(time.Minute), true, StepUpFastPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideStepUp(tc.auth, now, tc.factors); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestStepUpConsts(t *testing.T) {
	if StepUpMaxAge != 5*time.Minute || StepUpTokenTTL != 5*time.Minute {
		t.Fatal("5min/5min")
	}
	if StepUpAud != "step-up" {
		t.Fatalf("aud: %q", StepUpAud)
	}
}
