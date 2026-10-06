package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

type fakeLegal struct {
	terms, privacy shared.LegalDocument
	err            error
	calls          int
}

func newFakeLegal() *fakeLegal {
	return &fakeLegal{
		terms:   shared.LegalDocument{DocType: shared.DocTerms, Version: "v2026.10", IsActive: true},
		privacy: shared.LegalDocument{DocType: shared.DocPrivacy, Version: "v2026.10", IsActive: true},
	}
}

func (f *fakeLegal) GetActive(_ context.Context) (shared.LegalDocument, shared.LegalDocument, error) {
	f.calls++
	return f.terms, f.privacy, f.err
}

type fakeConsentMetrics struct {
	recorded map[string]int
	rejected map[string]int
	outdated map[string]int
}

func newFakeConsentMetrics() *fakeConsentMetrics {
	return &fakeConsentMetrics{recorded: map[string]int{}, rejected: map[string]int{}, outdated: map[string]int{}}
}
func (m *fakeConsentMetrics) IncConsentRecorded(d, s string) { m.recorded[d+"/"+s]++ }
func (m *fakeConsentMetrics) IncConsentRejected(r string)     { m.rejected[r]++ }
func (m *fakeConsentMetrics) IncConsentOutdated(d string)     { m.outdated[d]++ }

func legalSvc(repo *mockRepo, legal *fakeLegal) (*RegisterUserService, *mockMetrics, *fakeConsentMetrics) {
	metrics := newMockMetrics()
	cm := newFakeConsentMetrics()
	s := NewRegisterUserService(repo, &mockHasher{hash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"},
		&mockBreach{}, mockIssuer{}, &mockOutbox{}, newMockIdem(), mockAudit{}, metrics, NoopTracer{})
	s.Sleep = func(time.Duration) {}
	s.Legal = legal
	s.Consents = cm
	return s, metrics, cm
}

func legalInput() RegisterUserInput {
	return RegisterUserInput{
		EmailRaw: "Test@Example.com ", Password: "Str0ng!Passw0rd-2026",
		TermsAccepted: true, TermsVersion: "v2026.10", PrivacyVersion: "v2026.10",
		RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "test",
	}
}

func TestLegalRejectPreProbe(t *testing.T) {
	// Sin terms → 400 sin tocar Probe (repo vacío = habría creado) ni hash.
	repo := newMockRepo()
	s, _, cm := legalSvc(repo, newFakeLegal())
	in := legalInput()
	in.TermsAccepted = false
	if _, err := s.Execute(context.Background(), in); err == nil {
		t.Fatal("esperaba error")
	}
	if len(repo.created) != 0 {
		t.Fatal("rechazo no debe crear usuario (pre-Probe)")
	}
	if cm.rejected["missing"] != 1 {
		t.Fatalf("métrica missing: %v", cm.rejected)
	}
}

func TestLegalOutdatedTraeActivas(t *testing.T) {
	repo := newMockRepo()
	s, _, cm := legalSvc(repo, newFakeLegal())
	in := legalInput()
	in.TermsVersion = "v2026.09"
	_, err := s.Execute(context.Background(), in)
	var oe *shared.TermsOutdatedError
	if !errors.As(err, &oe) {
		t.Fatalf("esperaba TermsOutdatedError, got %v", err)
	}
	if oe.ActiveTerms != "v2026.10" || oe.ActivePrivacy != "v2026.10" {
		t.Fatalf("meta activas: %+v", oe)
	}
	if len(repo.created) != 0 {
		t.Fatal("outdated no debe crear")
	}
	if cm.rejected["outdated"] != 1 || cm.outdated["terms"] != 1 {
		t.Fatalf("métricas: %v %v", cm.rejected, cm.outdated)
	}
}

func TestLegalVigenteCreaLedger(t *testing.T) {
	repo := newMockRepo()
	s, _, cm := legalSvc(repo, newFakeLegal())
	out, err := s.Execute(context.Background(), legalInput())
	if err != nil || out.Status != "pending_verification" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if cm.recorded["terms/classic"] != 1 || cm.recorded["privacy/classic"] != 1 {
		t.Fatalf("ledger métricas: %v", cm.recorded)
	}
}

func TestLegalInfraFailClosed(t *testing.T) {
	repo := newMockRepo()
	legal := newFakeLegal()
	legal.err = errors.New("db down")
	s, _, _ := legalSvc(repo, legal)
	if _, err := s.Execute(context.Background(), legalInput()); err == nil {
		t.Fatal("PG legal down debe ser 500 (fail-closed)")
	}
	if len(repo.created) != 0 {
		t.Fatal("fail-closed: 0 filas")
	}
	_ = user.ProbeUnique
}
