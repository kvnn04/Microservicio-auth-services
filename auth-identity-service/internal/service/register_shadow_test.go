package service

import (
	"context"
	"testing"
	"time"

	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

type mockThrottle struct {
	allow bool
	calls int
}

func (m *mockThrottle) AllowOwnerNotify(_ context.Context, _ string) (bool, error) {
	m.calls++
	return m.allow, nil
}

func shadowSvc(throttle *mockThrottle) (*RegisterUserService, *mockOutbox, *mockMetrics) {
	repo := newMockRepo()
	repo.byEmail["test@example.com"] = &user.User{ID: uuid.NewString(), EmailNormalized: "test@example.com", Status: user.StatusActive}
	outbox := &mockOutbox{}
	metrics := newMockMetrics()
	s := NewRegisterUserService(repo, &mockHasher{hash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"},
		&mockBreach{}, mockIssuer{}, outbox, newMockIdem(), mockAudit{}, metrics, NoopTracer{})
	s.Sleep = func(time.Duration) {}
	s.Throttle = throttle
	return s, outbox, metrics
}

func TestShadowVsUniqueMismoOutput(t *testing.T) {
	th := &mockThrottle{allow: true}
	s, outbox, metrics := shadowSvc(th)
	in := validInput()
	shadowOut, err := s.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("shadow: %v", err)
	}
	// Único con otro servicio limpio.
	s2, _ := testSvc(newMockRepo(), nil)
	in2 := validInput()
	in2.EmailRaw = "nuevo-unico@example.com"
	in2.RequestID = uuid.NewString()
	uniqueOut, err := s2.Execute(context.Background(), in2)
	if err != nil {
		t.Fatalf("unique: %v", err)
	}
	if shadowOut.Status != uniqueOut.Status || shadowOut.IsShadowDuplicate == uniqueOut.IsShadowDuplicate {
		t.Fatalf("outputs distinguibles: shadow=%+v unique=%+v", shadowOut, uniqueOut)
	}
	if len(outbox.enqueued) != 1 {
		t.Fatalf("shadow debe encolar 1 notify, got %d", len(outbox.enqueued))
	}
	if metrics.probes[string(user.ProbeShadowDuplicate)] != 1 || metrics.notify[false] != 1 {
		t.Fatalf("métricas: %+v notify=%v", metrics.probes, metrics.notify)
	}
}

func TestShadowThrottledSoloAudit(t *testing.T) {
	th := &mockThrottle{allow: false}
	s, outbox, metrics := shadowSvc(th)
	if _, err := s.Execute(context.Background(), validInput()); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(outbox.enqueued) != 0 {
		t.Fatal("throttled no debe encolar email")
	}
	if metrics.probes[string(user.ProbeThrottledNotify)] != 1 || metrics.notify[true] != 1 {
		t.Fatalf("métricas: %+v notify=%v", metrics.probes, metrics.notify)
	}
	if th.calls != 1 {
		t.Fatal("throttle debe consultarse 1 vez")
	}
}

func TestProbeAndNotify(t *testing.T) {
	if ProbeAndNotify(false, false) != user.ProbeUnique {
		t.Fatal("unique")
	}
	if ProbeAndNotify(true, true) != user.ProbeShadowDuplicate {
		t.Fatal("shadow")
	}
	if ProbeAndNotify(true, false) != user.ProbeThrottledNotify {
		t.Fatal("throttled")
	}
	if GenericRegisterStatus != "pending_verification" || GenericResendStatus != "if_exists_verification_sent" {
		t.Fatal("outputs genéricos")
	}
}
