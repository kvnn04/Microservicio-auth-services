package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

type mockRepo struct {
	byEmail map[string]*user.User
	created []*user.User
	outbox  [][]user.OutboxPayload
	onCreate func(u *user.User) error
}

func newMockRepo() *mockRepo { return &mockRepo{byEmail: map[string]*user.User{}} }

func (m *mockRepo) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := m.byEmail[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (m *mockRepo) FindByID(_ context.Context, id string) (*user.User, error) {
	for _, u := range m.byEmail {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, user.ErrNotFound
}
func (m *mockRepo) CreateWithOutbox(_ context.Context, u *user.User, outbox []user.OutboxPayload, _ string, _ string) error {
	return m.create(u, outbox)
}
func (m *mockRepo) CreateWithConsents(_ context.Context, u *user.User, outbox []user.OutboxPayload, _ string, _ user.RegistrationContext) error {
	return m.create(u, outbox)
}
func (m *mockRepo) create(u *user.User, outbox []user.OutboxPayload) error {
	if m.onCreate != nil {
		if err := m.onCreate(u); err != nil {
			return err
		}
	}
	if _, exists := m.byEmail[u.EmailNormalized]; exists {
		return user.ErrDuplicateShadow
	}
	m.byEmail[u.EmailNormalized] = u
	m.created = append(m.created, u)
	m.outbox = append(m.outbox, outbox)
	return nil
}

type mockHasher struct{ hash string }

func (m *mockHasher) Hash(_ context.Context, _ string) (string, error) {
	return m.hash, nil
}
func (m *mockHasher) Verify(_ context.Context, _, _ string) (bool, error) { return true, nil }

type mockBreach struct {
	compromised bool
	err         error
}

func (m *mockBreach) IsCompromised(_ context.Context, _ string) (bool, error) {
	return m.compromised, m.err
}

type mockIssuer struct{}

func (mockIssuer) Generate() (string, string, error) { return "plain-token", "hash123", nil }
func (mockIssuer) HashToken(p string) string         { return "hash:" + p }

type mockOutbox struct{ enqueued [][]user.OutboxPayload }

func (m *mockOutbox) Enqueue(_ context.Context, e []user.OutboxPayload) error {
	m.enqueued = append(m.enqueued, e)
	return nil
}

type mockIdem struct{ store map[string]string }

func newMockIdem() *mockIdem { return &mockIdem{store: map[string]string{}} }
func (m *mockIdem) Get(_ context.Context, k string) (string, bool, error) {
	v, ok := m.store[k]
	return v, ok, nil
}
func (m *mockIdem) Put(_ context.Context, k, v string, _ time.Duration) error {
	m.store[k] = v
	return nil
}

type mockAudit struct{}

func (mockAudit) Log(_ context.Context, _ string, _ map[string]string) error { return nil }

type mockMetrics struct {
	counts   map[string]int
	fallback int
	probes   map[string]int
	notify   map[bool]int
	blocked  int
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{counts: map[string]int{}, probes: map[string]int{}, notify: map[bool]int{}}
}
func (m *mockMetrics) IncRegistration(s string)              { m.counts[s]++ }
func (m *mockMetrics) ObserveRegistrationDuration(_ float64) {}
func (m *mockMetrics) IncHibpFallback()                      { m.fallback++ }
func (m *mockMetrics) IncUniquenessProbe(o string)           { m.probes[o]++ }
func (m *mockMetrics) IncNotifyOwner(t bool)                  { m.notify[t]++ }
func (m *mockMetrics) IncIPBlocked()                          { m.blocked++ }

func testSvc(repo *mockRepo, breach *mockBreach) (*RegisterUserService, *mockMetrics) {
	if breach == nil {
		breach = &mockBreach{}
	}
	metrics := newMockMetrics()
	s := NewRegisterUserService(repo, &mockHasher{hash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"},
		breach, mockIssuer{}, &mockOutbox{}, newMockIdem(), mockAudit{}, metrics, NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s, metrics
}

func validInput() RegisterUserInput {
	return RegisterUserInput{
		EmailRaw: "Test@Example.com ", Password: "Str0ng!Passw0rd-2026",
		TermsAccepted: true, TermsVersion: "v2026.10", PrivacyVersion: "v2026.10",
		RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "test",
	}
}

func TestRegisterSuccess(t *testing.T) {
	repo := newMockRepo()
	s, metrics := testSvc(repo, nil)
	out, err := s.Execute(context.Background(), validInput())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Status != "pending_verification" || out.IsShadowDuplicate {
		t.Fatalf("out: %+v", out)
	}
	if len(repo.created) != 1 || len(repo.outbox[0]) != 3 {
		t.Fatalf("created=%d outbox=%v", len(repo.created), repo.outbox)
	}
	if metrics.counts["success"] != 1 {
		t.Fatalf("metrics: %v", metrics.counts)
	}
}

func TestRegisterDuplicateShadowSameOutput(t *testing.T) {
	repo := newMockRepo()
	s, _ := testSvc(repo, nil)
	repo.byEmail["test@example.com"] = &user.User{ID: uuid.NewString(), EmailNormalized: "test@example.com", Status: user.StatusActive}
	out, err := s.Execute(context.Background(), validInput())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !out.IsShadowDuplicate || out.Status != "pending_verification" {
		t.Fatalf("out: %+v", out)
	}
	if len(repo.created) != 0 {
		t.Fatal("shadow no debe crear")
	}
}

func TestRegisterRaceUniqueViolationBecomesShadow(t *testing.T) {
	repo := newMockRepo()
	s, _ := testSvc(repo, nil)
	repo.onCreate = func(u *user.User) error { return user.ErrDuplicateShadow }
	out, err := s.Execute(context.Background(), validInput())
	if err != nil || !out.IsShadowDuplicate {
		t.Fatalf("err=%v out=%+v", err, out)
	}
}

func TestRegisterHibpTimeoutFallback(t *testing.T) {
	repo := newMockRepo()
	s, metrics := testSvc(repo, &mockBreach{err: errors.New("timeout")})
	out, err := s.Execute(context.Background(), validInput())
	if err != nil || !out.HibpFallback || metrics.fallback != 1 {
		t.Fatalf("err=%v out=%+v metrics=%v", err, out, metrics.fallback)
	}
	s2, _ := testSvc(newMockRepo(), &mockBreach{err: errors.New("timeout")})
	s2.localDeny = map[string]struct{}{"Str0ng!Passw0rd-2026": {}}
	if _, err := s2.Execute(context.Background(), validInput()); err == nil {
		t.Fatal("esperaba ValidationError")
	}
}

func TestRegisterIdempotentReplay(t *testing.T) {
	repo := newMockRepo()
	s, _ := testSvc(repo, nil)
	in := validInput()
	if _, err := s.Execute(context.Background(), in); err != nil {
		t.Fatalf("1st: %v", err)
	}
	n := len(repo.created)
	out, err := s.Execute(context.Background(), in)
	if err != nil || !out.IsIdempotentReplay || len(repo.created) != n {
		t.Fatalf("replay: err=%v out=%+v", err, out)
	}
}
