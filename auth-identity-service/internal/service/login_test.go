package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

type fakeTracker struct {
	limitsErr error
	locked    map[string]bool
	fails     map[string]int
	lockCalls []string
}

func newFakeTracker() *fakeTracker {
	return &fakeTracker{locked: map[string]bool{}, fails: map[string]int{}}
}

func (f *fakeTracker) CheckLimits(_ context.Context, _, _ string) error { return f.limitsErr }
func (f *fakeTracker) IsLocked(_ context.Context, key string) (bool, error) {
	return f.locked[key], nil
}
func (f *fakeTracker) RecordFail(_ context.Context, key string) (bool, bool, error) {
	f.lockCalls = append(f.lockCalls, key)
	f.fails[key]++
	if f.fails[key] >= 5 {
		f.locked[key] = true
		return true, true, nil
	}
	return false, false, nil
}
func (f *fakeTracker) ResetOnSuccess(_ context.Context, key string) error {
	delete(f.fails, key)
	delete(f.locked, key)
	return nil
}

type loginSessions struct{ n int }

func (f *loginSessions) Issue(_ context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	f.n++
	return auth.IssuedPair{
		AccessJWT: "at-" + req.UserID, RefreshPlain: "rt-" + req.UserID,
		SID: "sid-" + req.UserID, JTI: "jti", Family: "fam", KID: "2026-10-a",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

type loginMFA struct{ n int }

func (f *loginMFA) IssueChallenge(_ context.Context, uid string) (string, string, int, error) {
	f.n++
	return "mfa-" + uid, "ch-" + uid, 300, nil
}

func loginSvc(repo *mockRepo, tracker *fakeTracker) (*LoginService, *loginSessions, *loginMFA) {
	if tracker == nil {
		tracker = newFakeTracker()
	}
	sess := &loginSessions{}
	mfa := &loginMFA{}
	s := NewLoginService(repo, &mockHasher{hash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"},
		tracker, sess, mfa, nil, &mockOutbox{}, newMockIdem(), mockAudit{}, newMockLoginMetrics(), NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s, sess, mfa
}

type mockLoginMetrics struct{ counts map[string]int }

func newMockLoginMetrics() *mockLoginMetrics { return &mockLoginMetrics{counts: map[string]int{}} }
func (m *mockLoginMetrics) IncLogin(r string)              { m.counts["login/"+r]++ }
func (m *mockLoginMetrics) ObserveLoginDuration(float64)   {}
func (m *mockLoginMetrics) IncLoginFailure(r string)       { m.counts["fail/"+r]++ }
func (m *mockLoginMetrics) IncLoginLock()                  { m.counts["lock"]++ }
func (m *mockLoginMetrics) IncLoginLockEmail(t bool) {
	if t {
		m.counts["lockmail-throttled"]++
	} else {
		m.counts["lockmail"]++
	}
}

func loginInput(email, pw string) LoginInput {
	return LoginInput{EmailRaw: email, Password: pw, RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "t"}
}

func seedLoginUser(repo *mockRepo, email, id string, active, mfa bool) {
	st := user.StatusPendingVerification
	if active {
		st = user.StatusActive
	}
	repo.byEmail[email] = &user.User{
		ID: id, EmailNormalized: email, Status: st,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash", MFAEnabled: mfa,
	}
}

func TestLoginSuccess(t *testing.T) {
	repo := newMockRepo()
	seedLoginUser(repo, "u@example.com", "uid-1", true, false)
	s, sess, _ := loginSvc(repo, nil)
	out, err := s.Execute(context.Background(), loginInput("u@example.com", "Str0ng!Passw0rd-2026"))
	if err != nil || out.Status != "active" || out.Session == nil {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if sess.n != 1 {
		t.Fatal("debe emitir 1 sesión")
	}
}

func TestLoginMFAChallenge(t *testing.T) {
	repo := newMockRepo()
	seedLoginUser(repo, "m@example.com", "uid-2", true, true)
	s, sess, mfa := loginSvc(repo, nil)
	out, err := s.Execute(context.Background(), loginInput("m@example.com", "Str0ng!Passw0rd-2026"))
	if err != nil || out.Status != "mfa_required" || out.Challenge == nil || out.Session != nil {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if sess.n != 0 || mfa.n != 1 {
		t.Fatal("solo challenge, sin sesión")
	}
	if len(out.Challenge.Methods) != 1 || out.Challenge.ExpiresIn != 300 {
		t.Fatalf("challenge: %+v", out.Challenge)
	}
}

func TestLoginCuatroMalosMismoError(t *testing.T) {
	repo := newMockRepo()
	seedLoginUser(repo, "u@example.com", "uid-1", true, false)
	// PENDING con buena + federated-only se modelan con hashes/estados.
	repo.byEmail["pending@example.com"] = &user.User{ID: "uid-p", EmailNormalized: "pending@example.com", Status: user.StatusPendingVerification, PasswordHash: "$argon2id$h"}
	repo.byEmail["fed@example.com"] = &user.User{ID: "uid-f", EmailNormalized: "fed@example.com", Status: user.StatusActive, PasswordAlgo: "federated"}
	s, _, _ := loginSvc(repo, nil)
	cases := []LoginInput{
		loginInput("nadie@example.com", "Str0ng!Passw0rd-2026"),
		loginInput("pending@example.com", "Str0ng!Passw0rd-2026"),
		loginInput("fed@example.com", "Str0ng!Passw0rd-2026"),
	}
	for i, in := range cases {
		if _, err := s.Execute(context.Background(), in); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("caso %d: %v", i, err)
		}
	}
	// Mala password (hasher que falla) → mismo error opaco.
	badRepo := newMockRepo()
	seedLoginUser(badRepo, "u@example.com", "uid-1", true, false)
	badSvc := NewLoginService(badRepo, badHasher{}, newFakeTracker(), &loginSessions{}, &loginMFA{}, nil,
		&mockOutbox{}, newMockIdem(), mockAudit{}, newMockLoginMetrics(), NoopTracer{})
	badSvc.Sleep = func(time.Duration) {}
	if _, err := badSvc.Execute(context.Background(), loginInput("u@example.com", "wrong")); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("mala password: %v", err)
	}
	_ = user.StatusLocked
}

type badHasher struct{}

func (badHasher) Hash(_ context.Context, _ string) (string, error) { return "h", nil }
func (badHasher) Verify(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}

func TestLoginLockSigueInvalid(t *testing.T) {
	repo := newMockRepo()
	seedLoginUser(repo, "u@example.com", "uid-1", true, false)
	tr := newFakeTracker()
	tr.locked["uid-1"] = true
	s, _, _ := loginSvc(repo, tr)
	if _, err := s.Execute(context.Background(), loginInput("u@example.com", "Str0ng!Passw0rd-2026")); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("lock debe seguir 401 opaco: %v", err)
	}
}

func TestLoginReplayNoDuplicaFails(t *testing.T) {
	repo := newMockRepo()
	tr := newFakeTracker()
	s, _, _ := loginSvc(repo, tr)
	in := loginInput("nadie@example.com", "Str0ng!Passw0rd-2026")
	if _, err := s.Execute(context.Background(), in); err == nil {
		t.Fatal("1º debe ser 401")
	}
	n := len(tr.lockCalls)
	if _, err := s.Execute(context.Background(), in); err == nil {
		t.Fatal("replay debe ser 401")
	}
	if len(tr.lockCalls) != n {
		t.Fatal("replay no debe duplicar fails")
	}
}

func TestLoginRateLimited(t *testing.T) {
	repo := newMockRepo()
	tr := newFakeTracker()
	tr.limitsErr = auth.ErrRateLimited
	s, _, _ := loginSvc(repo, tr)
	if _, err := s.Execute(context.Background(), loginInput("u@example.com", "x")); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("rate: %v", err)
	}
}
