package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
)

// --- Fakes CU-AUTH-04 ---

type fakeSigner struct {
	kid string
	err error
}

func (f *fakeSigner) Sign(_ context.Context, claims auth.AccessClaims) (string, string, error) {
	if f.err != nil {
		return "", "", f.err
	}
	if f.kid == "" {
		f.kid = "2026-10-a"
	}
	// JWT fake determinista (el adapter real firma Ed25519; aquí solo forma).
	return "header." + claims.Sub + "." + claims.JTI, f.kid, nil
}
func (f *fakeSigner) ActiveKID() string {
	if f.kid == "" {
		return "2026-10-a"
	}
	return f.kid
}

type fakeRefreshGen struct {
	plain string
	hash  string
	err   error
	n     int
}

func (f *fakeRefreshGen) Generate(_ context.Context) (string, string, error) {
	if f.err != nil {
		return "", "", f.err
	}
	f.n++
	if f.plain != "" {
		return f.plain, f.hash, nil
	}
	// 43ch determinista por intento (evita colisiones en tests).
	p := "refresh-plain-43ch-test-vector-000000000" + string(rune('a'+f.n%26))
	h := "hash-" + p
	return p, h, nil
}
func (f *fakeRefreshGen) Hash(plain string) string { return "hash-" + plain }

type fakeSessionStore struct {
	sessions map[string]auth.Session
	families map[string]auth.RefreshFamily
	hashes   map[string]auth.RefreshHash
	count    map[string]int // user -> sesiones
	fail     error
	conflictOnce bool
	evicted  string
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		sessions: map[string]auth.Session{},
		families: map[string]auth.RefreshFamily{},
		hashes:   map[string]auth.RefreshHash{},
		count:    map[string]int{},
	}
}

func (f *fakeSessionStore) Create(_ context.Context, sess auth.Session, fam auth.RefreshFamily, h auth.RefreshHash, evt user.OutboxPayload, _ *user.OutboxPayload) (string, error) {
	if f.fail != nil {
		return "", f.fail
	}
	if f.conflictOnce {
		f.conflictOnce = false
		return "", auth.ErrSessionConflict
	}
	if _, ok := f.sessions[sess.SID]; ok {
		return "", auth.ErrSessionConflict
	}
	if _, ok := f.hashes[h.Hash]; ok {
		return "", auth.ErrSessionConflict
	}
	f.sessions[sess.SID] = sess
	f.families[fam.Family] = fam
	f.hashes[h.Hash] = h
	f.count[sess.UserID]++
	// LRU-20: si excede, evicta una (simulada).
	if f.count[sess.UserID] > auth.MaxSessionsPerUser {
		f.evicted = "evicted-sid"
		return f.evicted, nil
	}
	return "", nil
}

type fakeSessionCache struct {
	saved int
	fail  error
}

func (f *fakeSessionCache) Save(_ context.Context, _ auth.Session, _ auth.RefreshFamily, _ string) error {
	f.saved++
	return f.fail
}

type fakeIssueUsers struct {
	users map[string]*user.User
	err   error
}

func (f *fakeIssueUsers) FindByEmailNormalized(_ context.Context, _ string) (*user.User, error) {
	return nil, user.ErrNotFound
}
func (f *fakeIssueUsers) FindByID(_ context.Context, id string) (*user.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (f *fakeIssueUsers) CreateWithOutbox(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ string, _ *user.VerificationMail) error {
	return nil
}
func (f *fakeIssueUsers) CreateWithConsents(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext, _ *user.VerificationMail) error {
	return nil
}

type fakeIssueMetrics struct {
	issued   map[string]int
	evicted  int
	fallback int
	infra    map[string]int
	durs     int
}

func newFakeIssueMetrics() *fakeIssueMetrics {
	return &fakeIssueMetrics{issued: map[string]int{}, infra: map[string]int{}}
}
func (m *fakeIssueMetrics) IncIssued(method, amr string) { m.issued[method+"/"+amr]++ }
func (m *fakeIssueMetrics) ObserveIssueDuration(float64) { m.durs++ }
func (m *fakeIssueMetrics) IncEvicted(string)            { m.evicted++ }
func (m *fakeIssueMetrics) IncRedisFallback()            { m.fallback++ }
func (m *fakeIssueMetrics) IncInfraError(op string)      { m.infra[op]++ }

func issueTestSvc(store *fakeSessionStore, cache *fakeSessionCache, users map[string]*user.User) (*IssueService, *fakeIssueMetrics) {
	m := newFakeIssueMetrics()
	s := NewIssueService(&fakeSigner{}, &fakeRefreshGen{}, store, cache,
		&fakeIssueUsers{users: users}, NoopAudit{}, m, NoopTracer{}, "", "")
	s.Now = func() time.Time { return time.Now().UTC() }
	return s, m
}

func issueReq(uid string, method string, amr []auth.AMR) auth.SessionRequest {
	return auth.SessionRequest{
		UserID: uid, Method: method, AMR: amr,
		AuthTime: time.Now().UTC().Add(-time.Second),
		Device:   auth.Device{IPHash: "ip", UAHash: "ua"},
		Roles:    []string{"user"}, RolesVer: 1,
	}
}

func TestIssue_HappyPaths(t *testing.T) {
	cases := []struct {
		name   string
		method string
		amr    []auth.AMR
	}{
		{"password", "password", []auth.AMR{auth.AMRPassword}},
		{"mfa totp", "password", []auth.AMR{auth.AMRPassword, auth.AMRTOTP}},
		{"mfa backup", "password", []auth.AMR{auth.AMRPassword, auth.AMRBackup}},
		{"federated", "federated_google", []auth.AMR{auth.AMRFederatedGoogle}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uid := "user-" + tc.name
			// Sin Users (confía en llamador) + con Users ACTIVE.
			for _, withUsers := range []bool{false, true} {
				store := newFakeSessionStore()
				cache := &fakeSessionCache{}
				var users map[string]*user.User
				var svc *IssueService
				var m *fakeIssueMetrics
				if withUsers {
					users = map[string]*user.User{uid: {ID: uid, Status: user.StatusActive}}
					svc, m = issueTestSvc(store, cache, users)
				} else {
					svc, m = issueTestSvc(store, cache, nil)
					svc.Users = nil
				}
				pair, err := svc.Issue(context.Background(), issueReq(uid, tc.method, tc.amr))
				if err != nil {
					t.Fatalf("withUsers=%v: %v", withUsers, err)
				}
				if pair.AccessJWT == "" || pair.RefreshPlain == "" {
					t.Fatal("par vacío")
				}
				if pair.SID == pair.JTI || pair.SID == pair.Family {
					t.Fatal("sid/jti/family deben ser distintos")
				}
				if pair.KID == "" {
					t.Fatal("kid vacío")
				}
				if len(store.sessions) != 1 || len(store.families) != 1 || len(store.hashes) != 1 {
					t.Fatalf("PG debe tener 1 fila c/u: %+v", store)
				}
				if cache.saved != 1 {
					t.Fatal("Redis write-through")
				}
				if m.durs != 1 {
					t.Fatal("duración observada")
				}
				// Doble Issue = 2 sid (no idempotente por RequestID).
				pair2, err := svc.Issue(context.Background(), issueReq(uid, tc.method, tc.amr))
				if err != nil {
					t.Fatal(err)
				}
				if pair2.SID == pair.SID {
					t.Fatal("cada login crea sid nuevo")
				}
			}
		})
	}
}

func TestIssue_Validation(t *testing.T) {
	svc, _ := issueTestSvc(newFakeSessionStore(), &fakeSessionCache{}, nil)
	svc.Users = nil
	now := time.Now().UTC()
	dev := auth.Device{IPHash: "ip", UAHash: "ua"}
	cases := []struct {
		name string
		req  auth.SessionRequest
	}{
		{"sin user", auth.SessionRequest{Method: "password", AMR: []auth.AMR{auth.AMRPassword}, AuthTime: now, Device: dev}},
		{"method raro", auth.SessionRequest{UserID: "u", Method: "x", AMR: []auth.AMR{auth.AMRPassword}, AuthTime: now, Device: dev}},
		{"amr vacio", auth.SessionRequest{UserID: "u", Method: "password", AuthTime: now, Device: dev}},
		{"device vacio", auth.SessionRequest{UserID: "u", Method: "password", AMR: []auth.AMR{auth.AMRPassword}, AuthTime: now}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Issue(context.Background(), tc.req); !errors.Is(err, auth.ErrInvalidSessionRequest) {
				t.Fatalf("esperaba validation, got %v", err)
			}
		})
	}
	// No-ACTIVE vía Users.
	uid := "u-locked"
	svc2, _ := issueTestSvc(newFakeSessionStore(), &fakeSessionCache{}, map[string]*user.User{
		uid: {ID: uid, Status: user.StatusLocked},
	})
	if _, err := svc2.Issue(context.Background(), issueReq(uid, "password", []auth.AMR{auth.AMRPassword})); !errors.Is(err, auth.ErrInvalidSessionRequest) {
		t.Fatalf("locked debe ser validation, got %v", err)
	}
}

func TestIssue_InfraDegradada(t *testing.T) {
	uid := "u1"
	// PG down → 500 sin entregar (0 filas).
	storeFail := newFakeSessionStore()
	storeFail.fail = errors.New("pg down")
	svc, _ := issueTestSvc(storeFail, &fakeSessionCache{}, nil)
	svc.Users = nil
	if _, err := svc.Issue(context.Background(), issueReq(uid, "password", []auth.AMR{auth.AMRPassword})); err == nil {
		t.Fatal("PG down debe fallar")
	}
	if len(storeFail.sessions) != 0 {
		t.Fatal("0 filas si Tx falla (sin huérfanos)")
	}
	// Redis down → 200 vía PG + fallback.
	store := newFakeSessionStore()
	cacheFail := &fakeSessionCache{fail: errors.New("redis down")}
	svc2, m2 := issueTestSvc(store, cacheFail, nil)
	svc2.Users = nil
	pair, err := svc2.Issue(context.Background(), issueReq(uid, "password", []auth.AMR{auth.AMRPassword}))
	if err != nil || pair.AccessJWT == "" {
		t.Fatalf("Redis-down entrega igual: %v", err)
	}
	if m2.fallback != 1 {
		t.Fatal("fallback metric")
	}
	// Sin clave → ErrNoKey (500 arranque fallido).
	svc3, _ := issueTestSvc(newFakeSessionStore(), &fakeSessionCache{}, nil)
	svc3.Users = nil
	svc3.Signer = &fakeSigner{err: auth.ErrNoKey}
	if _, err := svc3.Issue(context.Background(), issueReq(uid, "password", []auth.AMR{auth.AMRPassword})); !errors.Is(err, auth.ErrNoKey) {
		t.Fatalf("sin clave ErrNoKey, got %v", err)
	}
	// Conflicto → reintenta 1 vez y entrega.
	storeC := newFakeSessionStore()
	storeC.conflictOnce = true
	svc4, _ := issueTestSvc(storeC, &fakeSessionCache{}, nil)
	svc4.Users = nil
	if _, err := svc4.Issue(context.Background(), issueReq(uid, "password", []auth.AMR{auth.AMRPassword})); err != nil {
		t.Fatalf("conflicto reintenta: %v", err)
	}
}
