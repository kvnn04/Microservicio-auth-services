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

// FakeIdP programa respuestas (firma OK/mala, nonce, verified).
type fakeIdP struct {
	authURL  auth.AuthURL
	verifier string
	tokens   auth.TokenSet
	claims   auth.OIDClaims
	xErr     error
	vErr     error
}

func (f *fakeIdP) BuildAuthorizeURL(_ context.Context, _ auth.AuthorizeReq) (auth.AuthURL, string, error) {
	return f.authURL, f.verifier, nil
}
func (f *fakeIdP) ExchangeCode(_ context.Context, _ user.Provider, _, _, _ string) (auth.TokenSet, error) {
	if f.xErr != nil {
		return auth.TokenSet{}, f.xErr
	}
	return f.tokens, nil
}
func (f *fakeIdP) VerifyIDToken(_ context.Context, _ user.Provider, _, _ string) (auth.OIDClaims, error) {
	if f.vErr != nil {
		return auth.OIDClaims{}, f.vErr
	}
	return f.claims, nil
}

type fakeFedRepo struct {
	bySub    map[string]*user.User
	byEmail  map[string]*user.User
	created  int
	onCreate func() error
}

func newFakeFedRepo() *fakeFedRepo {
	return &fakeFedRepo{bySub: map[string]*user.User{}, byEmail: map[string]*user.User{}}
}

func (f *fakeFedRepo) FindByProviderSub(_ context.Context, _ user.Provider, sub string) (*user.FederatedIdentity, *user.User, error) {
	if u, ok := f.bySub[sub]; ok {
		return &user.FederatedIdentity{Provider: user.ProviderGoogle, Sub: sub, UserID: u.ID}, u, nil
	}
	return nil, nil, user.ErrNotFound
}
func (f *fakeFedRepo) FindUserByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := f.byEmail[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (f *fakeFedRepo) CreateUserWithFederation(_ context.Context, u *user.User, fi *user.FederatedIdentity, _ []user.OutboxPayload, _ user.MailPayload, _ user.RegistrationContext) error {
	if f.onCreate != nil {
		if err := f.onCreate(); err != nil {
			return err
		}
	}
	if _, ok := f.byEmail[u.EmailNormalized]; ok {
		return user.ErrEmailCollision
	}
	f.byEmail[u.EmailNormalized] = u
	f.bySub[fi.Sub] = u
	f.created++
	return nil
}

type fakeStateStore struct {
	states map[string]auth.FederatedState
}

func newFakeStateStore() *fakeStateStore {
	return &fakeStateStore{states: map[string]auth.FederatedState{}}
}
func (f *fakeStateStore) SaveState(_ context.Context, state string, st auth.FederatedState) error {
	f.states[state] = st
	return nil
}
func (f *fakeStateStore) ConsumeState(_ context.Context, state string) (auth.FederatedState, error) {
	st, ok := f.states[state]
	if !ok {
		return auth.FederatedState{}, user.ErrNotFound
	}
	delete(f.states, state)
	return st, nil
}

type fakeSessions struct{}

func (fakeSessions) Issue(_ context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	return auth.IssuedPair{
		AccessJWT: "access-" + req.UserID, RefreshPlain: "refresh-" + req.UserID,
		SID: "sid-" + req.UserID, JTI: "jti", Family: "fam", KID: "2026-10-a",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

type fedMetrics struct{ counts map[string]int }

func newFedMetrics() *fedMetrics                        { return &fedMetrics{counts: map[string]int{}} }
func (m *fedMetrics) IncFederated(p, r string)          { m.counts[p+"/"+r]++ }
func (m *fedMetrics) ObserveFederatedDuration(float64)  {}
func (m *fedMetrics) ObserveIDPLatency(string, float64) {}
func (m *fedMetrics) IncCollision(p string)             { m.counts["coll/"+p]++ }

func fedSvc(idp *fakeIdP, repo *fakeFedRepo) (*RegisterFederatedService, *fedMetrics) {
	m := newFedMetrics()
	s := NewRegisterFederatedService(idp, repo, newFakeStateStore(),
		nil, mockPairIssuer2{}, fakeSessions{}, &mockOutbox{}, &mockThrottle{allow: true},
		newMockIdem(), mockAudit{}, m, NoopTracer{}, "v2026.10", false)
	return s, m
}

type mockPairIssuer2 struct{}

func (mockPairIssuer2) GeneratePair() (string, string, string, string, error) {
	return "tp", "th", "12345678", "oh", nil
}

func fedBoolP(b bool) *bool { return &b }

func cbIn(code, state string) CallbackInput {
	return CallbackInput{Provider: "google", Code: code, State: state, RequestID: uuid.NewString()}
}

func TestFederatedVerifiedActive(t *testing.T) {
	idp := &fakeIdP{
		tokens: auth.TokenSet{IDToken: "idtok"},
		claims: auth.OIDClaims{Sub: "google123", Email: "Nuevo@Example.com ", EmailVerified: fedBoolP(true), Nonce: "n"},
	}
	repo := newFakeFedRepo()
	s, m := fedSvc(idp, repo)
	// Pre-carga estado consumible.
	_ = s.States.SaveState(context.Background(), "st1", auth.FederatedState{Nonce: "n", Verifier: "v"})
	out, err := s.Callback(context.Background(), cbIn("code1", "st1"))
	if err != nil || out.Status != "active" || out.Session == nil {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if repo.created != 1 || m.counts["google/active"] != 1 {
		t.Fatalf("created=%d metrics=%v", repo.created, m.counts)
	}
}

func TestFederatedNoVerifiedPending(t *testing.T) {
	idp := &fakeIdP{
		tokens: auth.TokenSet{IDToken: "idtok"},
		claims: auth.OIDClaims{Sub: "g2", Email: "a@b.co", EmailVerified: fedBoolP(false), Nonce: "n"},
	}
	repo := newFakeFedRepo()
	s, m := fedSvc(idp, repo)
	_ = s.States.SaveState(context.Background(), "st2", auth.FederatedState{Nonce: "n", Verifier: "v"})
	out, err := s.Callback(context.Background(), cbIn("code2", "st2"))
	if err != nil || out.Status != "pending_verification" || out.Session != nil {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if m.counts["google/pending"] != 1 {
		t.Fatalf("metrics=%v", m.counts)
	}
}

func TestFederatedCollision409(t *testing.T) {
	idp := &fakeIdP{
		tokens: auth.TokenSet{IDToken: "idtok"},
		claims: auth.OIDClaims{Sub: "otro-sub", Email: "existe@example.com", EmailVerified: fedBoolP(true), Nonce: "n"},
	}
	repo := newFakeFedRepo()
	repo.byEmail["existe@example.com"] = &user.User{ID: uuid.NewString(), EmailNormalized: "existe@example.com", Status: user.StatusActive}
	s, m := fedSvc(idp, repo)
	_ = s.States.SaveState(context.Background(), "st3", auth.FederatedState{Nonce: "n", Verifier: "v"})
	_, err := s.Callback(context.Background(), cbIn("code3", "st3"))
	if !errors.Is(err, auth.ErrLinkRequired) {
		t.Fatalf("esperaba ErrLinkRequired, got %v", err)
	}
	if repo.created != 0 || m.counts["coll/google"] != 1 {
		t.Fatalf("no debe crear; metrics=%v", m.counts)
	}
}

func TestFederatedReplayState400(t *testing.T) {
	idp := &fakeIdP{}
	s, _ := fedSvc(idp, newFakeFedRepo())
	_, err := s.Callback(context.Background(), cbIn("code", "inexistente"))
	if !errors.Is(err, auth.ErrInvalidState) {
		t.Fatalf("replay debe ser ErrInvalidState, got %v", err)
	}
}

func TestFederatedCancelAndProvider(t *testing.T) {
	idp := &fakeIdP{}
	s, _ := fedSvc(idp, newFakeFedRepo())
	_, err := s.Callback(context.Background(), CallbackInput{Provider: "google", IdpError: "access_denied", RequestID: uuid.NewString()})
	if !errors.Is(err, auth.ErrFederatedCancelled) {
		t.Fatalf("cancel: %v", err)
	}
	_, err = s.Callback(context.Background(), CallbackInput{Provider: "facebook", RequestID: uuid.NewString()})
	if !errors.Is(err, auth.ErrProviderNotSupported) {
		t.Fatalf("provider: %v", err)
	}
	_, err = s.Callback(context.Background(), CallbackInput{Provider: "google", HasBearer: true, RequestID: uuid.NewString()})
	if !errors.Is(err, auth.ErrUseLinkFlow) {
		t.Fatalf("bearer: %v", err)
	}
}

func TestFederatedIDPUnavailable(t *testing.T) {
	idp := &fakeIdP{xErr: auth.ErrIDPUnavailable}
	s, _ := fedSvc(idp, newFakeFedRepo())
	_ = s.States.SaveState(context.Background(), "st4", auth.FederatedState{Nonce: "n", Verifier: "v"})
	_, err := s.Callback(context.Background(), cbIn("code", "st4"))
	if !errors.Is(err, auth.ErrIDPUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestFederatedHitLogin(t *testing.T) {
	idp := &fakeIdP{
		tokens: auth.TokenSet{IDToken: "idtok"},
		claims: auth.OIDClaims{Sub: "g9", Email: "x@y.co", EmailVerified: fedBoolP(true), Nonce: "n"},
	}
	repo := newFakeFedRepo()
	repo.bySub["g9"] = &user.User{ID: "u9", EmailNormalized: "x@y.co", Status: user.StatusActive}
	s, _ := fedSvc(idp, repo)
	_ = s.States.SaveState(context.Background(), "st5", auth.FederatedState{Nonce: "n", Verifier: "v"})
	out, err := s.Callback(context.Background(), cbIn("code", "st5"))
	if err != nil || out.Status != "active" || out.Session == nil {
		t.Fatalf("login: %v %+v", err, out)
	}
}
