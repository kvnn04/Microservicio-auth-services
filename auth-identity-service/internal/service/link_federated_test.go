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

type linkTestIdP struct {
	authURL  auth.AuthURL
	verifier string
	claims   auth.OIDClaims
	xErr     error
	vErr     error
}

func (f *linkTestIdP) BuildAuthorizeURL(_ context.Context, _ auth.AuthorizeReq) (auth.AuthURL, string, error) {
	return f.authURL, f.verifier, nil
}
func (f *linkTestIdP) ExchangeCode(_ context.Context, _ user.Provider, _, _, _ string) (auth.TokenSet, error) {
	if f.xErr != nil {
		return auth.TokenSet{}, f.xErr
	}
	return auth.TokenSet{IDToken: "idtok"}, nil
}
func (f *linkTestIdP) VerifyIDToken(_ context.Context, _ user.Provider, _, _ string) (auth.OIDClaims, error) {
	if f.vErr != nil {
		return auth.OIDClaims{}, f.vErr
	}
	return f.claims, nil
}

type linkTestState struct{ st user.LinkState }

func (s *linkTestState) SaveLinkState(_ context.Context, _ string, st user.LinkState) error {
	s.st = st
	return nil
}
func (s *linkTestState) ConsumeLinkState(_ context.Context, _ string) (user.LinkState, error) {
	return s.st, nil
}

type linkTestMetrics struct{ counts map[string]int }

func newLinkTestMetrics() *linkTestMetrics { return &linkTestMetrics{counts: map[string]int{}} }
func (m *linkTestMetrics) IncLink(p, o, r string)  { m.counts[p+"/"+o+"/"+r]++ }
func (m *linkTestMetrics) IncLastFactorBlocked()   { m.counts["lastfactor"]++ }
func (m *linkTestMetrics) IncLinkStateFailure(r string) { m.counts["state/"+r]++ }

func freshUser(id string) AuthUser {
	return AuthUser{ID: id, AuthTime: time.Now().UTC().Add(-time.Minute)}
}

func linkSvc() (*LinkService, *fakeLinkStore, *linkTestState, *mockRepo) {
	store := newFakeLinkStore()
	st := &linkTestState{}
	idp := &linkTestIdP{authURL: auth.AuthURL{URL: "https://idp/auth", State: "s", Nonce: "n"}, verifier: "v"}
	repo := newMockRepo()
	s := NewLinkService(idp, store, st, repo, &mockHasher{}, &mockOutbox{}, nil,
		newMockIdem(), mockAudit{}, newLinkTestMetrics(), NoopTracer{}, "http://x/link/callback", 5, 5*time.Minute)
	return s, store, st, repo
}

func seedActive(repo *mockRepo, email, id string, withPassword bool) {
	u := &user.User{ID: id, EmailNormalized: email, Status: user.StatusActive}
	if withPassword {
		u.PasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"
	}
	repo.byEmail[email] = u
}

func TestLinkInitiateStale401(t *testing.T) {
	s, _, _, _ := linkSvc()
	_, err := s.Initiate(context.Background(), LinkInitiateInput{
		User: AuthUser{ID: "u", AuthTime: time.Now().UTC().Add(-30 * time.Minute)},
		Provider: "google", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, user.ErrStepUpRequired) {
		t.Fatalf("stale debe ser StepUp, got %v", err)
	}
	// PENDING no linkea aunque esté fresco.
	uid := uuid.NewString()
	s.Users.(*mockRepo).byEmail["p@e.co"] = &user.User{ID: uid, EmailNormalized: "p@e.co", Status: user.StatusPendingVerification}
	_, err = s.Initiate(context.Background(), LinkInitiateInput{
		User: freshUser(uid), Provider: "google", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, auth.ErrAccountUnavailable) {
		t.Fatalf("pending debe ser 403, got %v", err)
	}
}

func TestLinkCallbackOK(t *testing.T) {
	s, _, st, repo := linkSvc()
	uid := uuid.NewString()
	seedActive(repo, "cb@example.com", uid, false)
	st.st = user.LinkState{UserID: uid, Nonce: "n", Verifier: "v"}
	s.IdPs.(*linkTestIdP).claims = auth.OIDClaims{Sub: "G1", Email: "a@b.co", EmailVerified: &[]bool{true}[0], Nonce: "n"}
	out, err := s.Callback(context.Background(), LinkCallbackInput{
		User: freshUser(uid), Provider: "google", Code: "c", State: "s", RequestID: uuid.NewString(),
	})
	if err != nil || out.Status != "linked" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
}

func TestLinkCallbackMismatch400(t *testing.T) {
	s, _, st, repo := linkSvc()
	caller := uuid.NewString()
	seedActive(repo, "caller@example.com", caller, false)
	st.st = user.LinkState{UserID: "otro", Nonce: "n", Verifier: "v"}
	_, err := s.Callback(context.Background(), LinkCallbackInput{
		User: freshUser(caller), Provider: "google", Code: "c", State: "s", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, auth.ErrInvalidState) {
		t.Fatalf("mismatch debe ser InvalidState, got %v", err)
	}
}

func TestLinkSelfAlreadyAndForeign409(t *testing.T) {
	s, store, st, repo := linkSvc()
	uid := uuid.NewString()
	seedActive(repo, "a@example.com", uid, false)
	st.st = user.LinkState{UserID: uid, Nonce: "n", Verifier: "v"}
	store.bySub["G9"] = &user.User{ID: uid}
	s.IdPs.(*linkTestIdP).claims = auth.OIDClaims{Sub: "G9", Email: "a@b.co", Nonce: "n"}
	out, err := s.Callback(context.Background(), LinkCallbackInput{
		User: freshUser(uid), Provider: "google", Code: "c", State: "s", RequestID: uuid.NewString(),
	})
	if err != nil || out.Status != "already_linked" {
		t.Fatalf("self: %v %+v", err, out)
	}
	// Ajeno.
	uidB := uuid.NewString()
	seedActive(repo, "b@example.com", uidB, false)
	st.st = user.LinkState{UserID: uidB, Nonce: "n", Verifier: "v"}
	_, err = s.Callback(context.Background(), LinkCallbackInput{
		User: freshUser(uidB), Provider: "google", Code: "c2", State: "s2", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, user.ErrCollisionForeign) {
		t.Fatalf("ajeno debe ser colisión, got %v", err)
	}
}

func TestUnlinkLastFactor400(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	repo.byEmail["solo@example.com"] = &user.User{ID: uid, EmailNormalized: "solo@example.com", Status: user.StatusActive}
	store := newFakeLinkStore()
	store.links[uid] = []user.FederatedIdentity{{Provider: user.ProviderGoogle, Sub: "G1"}}
	s := NewUnlinkService(store, repo, &mockHasher{}, newMockIdem(), mockAudit{}, newLinkTestMetrics(), NoopTracer{}, 5*time.Minute)
	_, err := s.Unlink(context.Background(), UnlinkInput{
		User: freshUser(uid), Provider: "google", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, user.ErrLastAuthFactor) {
		t.Fatalf("último factor: %v", err)
	}
}

func TestUnlinkOKAndListMasked(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	repo.byEmail["u@example.com"] = &user.User{
		ID: uid, EmailNormalized: "u@example.com", Status: user.StatusActive,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash",
	}
	store := newFakeLinkStore()
	store.links[uid] = []user.FederatedIdentity{{
		Provider: user.ProviderGoogle, Sub: "G1", EmailAtLink: "u@example.com",
	}}
	store.byUserProv[uid+":google"] = &user.FederatedIdentity{Provider: user.ProviderGoogle, Sub: "G1"}
	store.hasPassword[uid] = true
	s := NewUnlinkService(store, repo, &mockHasher{hash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"},
		newMockIdem(), mockAudit{}, newLinkTestMetrics(), NoopTracer{}, 5*time.Minute)
	pre, err := s.List(context.Background(), uid, "")
	if err != nil || len(pre) != 1 {
		t.Fatalf("list: %v %v", err, pre)
	}
	if pre[0].EmailMasked != "u***@example.com" || len(pre[0].SubHash) != 8 {
		t.Fatalf("enmascarado: %+v", pre[0])
	}
	if pre[0].Provider != "google" {
		t.Fatalf("provider: %+v", pre[0])
	}
	out, err := s.Unlink(context.Background(), UnlinkInput{
		User: freshUser(uid), Provider: "google", CurrentPassword: "Str0ng!Passw0rd-2026", RequestID: uuid.NewString(),
	})
	if err != nil || out.Status != "unlinked" {
		t.Fatalf("unlink: %v %+v", err, out)
	}
	items, err := s.List(context.Background(), uid, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("tras unlink lista vacía: %v", items)
	}
}
