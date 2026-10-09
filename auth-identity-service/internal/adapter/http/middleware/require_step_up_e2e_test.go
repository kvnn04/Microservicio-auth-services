package middleware

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/adapter/security"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"
)

// --- Fakes E2E CU-AUTH-06 (servicio real, cripto real, jti en memoria) ---

type e2eStepUsers struct {
	users map[string]*user.User
}

func (f *e2eStepUsers) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	for _, u := range f.users {
		if u.EmailNormalized == e {
			return u, nil
		}
	}
	return nil, user.ErrNotFound
}
func (f *e2eStepUsers) FindByID(_ context.Context, id string) (*user.User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (f *e2eStepUsers) CreateWithOutbox(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ string, _ *user.VerificationMail) error {
	return nil
}
func (f *e2eStepUsers) CreateWithConsents(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext, _ *user.VerificationMail) error {
	return nil
}

type e2eHasher struct{ ok bool }

func (h *e2eHasher) Hash(_ context.Context, _ string) (string, error) { return "h", nil }
func (h *e2eHasher) Verify(_ context.Context, _, _ string) (bool, error) {
	return h.ok, nil
}

type e2eJTIs struct {
	live map[string][2]string
}

func (f *e2eJTIs) Save(_ context.Context, jti, sub, scope string) error {
	f.live[jti] = [2]string{sub, scope}
	return nil
}
func (f *e2eJTIs) Consume(_ context.Context, jti string) (string, string, bool, error) {
	v, ok := f.live[jti]
	if !ok {
		return "", "", false, nil
	}
	delete(f.live, jti)
	return v[0], v[1], true, nil
}

type e2eIdem struct{ m map[string]string }

func (f *e2eIdem) Get(_ context.Context, k string) (string, bool, error) {
	v, ok := f.m[k]
	return v, ok, nil
}
func (f *e2eIdem) Put(_ context.Context, k, v string, _ time.Duration) error {
	f.m[k] = v
	return nil
}

type e2eOutbox struct {
	n int
}

func (f *e2eOutbox) Enqueue(_ context.Context, _ []user.OutboxPayload) error {
	f.n++
	return nil
}

func realStepUpService(users map[string]*user.User) (*service.StepUpService, ed25519.PrivateKey) {
	priv, _, _ := security.GenerateEd25519Key()
	iss, _ := security.NewStepUpTokenIssuer(priv, "2026-10-a", "")
	svc := service.NewStepUpService(&e2eStepUsers{users: users}, &e2eHasher{ok: true},
		nil, nil, nil, nil, nil, nil, nil, iss, &e2eJTIs{live: map[string][2]string{}},
		&e2eOutbox{}, &e2eIdem{m: map[string]string{}}, nil, nil, nil)
	svc.Sleep = func(time.Duration) {}
	return svc, priv
}

func stepUpGuardReq(uid string, age time.Duration, token string) *http.Request {
	req := httptest.NewRequest("POST", "/op", nil)
	ctx := context.WithValue(req.Context(), authUserKey, uid)
	ctx = context.WithValue(ctx, authTimeKey, time.Now().UTC().Add(-age))
	if token != "" {
		req.Header.Set("X-Step-Up-Token", token)
	}
	return req.WithContext(ctx)
}

// Escenario 1+2 del spec §7 a nivel guard: stale→401→challenge→token→op→replay 401.
func TestRequireStepUp_RealServiceE2E(t *testing.T) {
	uid := "user-e2e-1"
	users := map[string]*user.User{uid: {
		ID: uid, EmailNormalized: "e2e@example.com", PasswordHash: "h",
		Status: user.StatusActive,
	}}
	svc, _ := realStepUpService(users)

	// 1. Stale sin token → 401 STEP_UP_REQUIRED con meta scope.
	rr := httptest.NewRecorder()
	RequireStepUp(auth.ScopeChangePassword, svc, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	).ServeHTTP(rr, stepUpGuardReq(uid, time.Hour, ""))
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("required: %d %s", rr.Code, rr.Body.String())
	}

	// 2. Challenge con password (servicio real, cripto real).
	out, err := svc.Challenge(context.Background(), service.StepUpChallengeInput{
		User:  service.AuthUser{ID: uid, AuthTime: time.Now().UTC().Add(-time.Hour)},
		Scope: string(auth.ScopeChangePassword), Password: "ok",
		RequestID: "req-e2e-1",
	})
	if err != nil || out.Token == "" {
		t.Fatalf("challenge: %v %+v", err, out)
	}

	// 3. Op con token → 200 (quema el jti).
	rr2 := httptest.NewRecorder()
	RequireStepUp(auth.ScopeChangePassword, svc, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	).ServeHTTP(rr2, stepUpGuardReq(uid, time.Hour, out.Token))
	if rr2.Code != http.StatusOK {
		t.Fatalf("op con token: %d %s", rr2.Code, rr2.Body.String())
	}

	// 4. Replay mismo token → 401 STEP_UP_REUSED.
	rr3 := httptest.NewRecorder()
	RequireStepUp(auth.ScopeChangePassword, svc, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	).ServeHTTP(rr3, stepUpGuardReq(uid, time.Hour, out.Token))
	if rr3.Code != http.StatusUnauthorized || !strings.Contains(rr3.Body.String(), "STEP_UP_REUSED") {
		t.Fatalf("reused: %d %s", rr3.Code, rr3.Body.String())
	}

	// 5. Token en otra op → 401 INVALID_STEP_UP.
	out2, err := svc.Challenge(context.Background(), service.StepUpChallengeInput{
		User:  service.AuthUser{ID: uid, AuthTime: time.Now().UTC().Add(-time.Hour)},
		Scope: string(auth.ScopeChangeEmail), Password: "ok",
		RequestID: "req-e2e-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	rr4 := httptest.NewRecorder()
	RequireStepUp(auth.ScopeChangePassword, svc, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	).ServeHTTP(rr4, stepUpGuardReq(uid, time.Hour, out2.Token))
	if rr4.Code != http.StatusUnauthorized || !strings.Contains(rr4.Body.String(), "INVALID_STEP_UP") {
		t.Fatalf("cross-scope: %d %s", rr4.Code, rr4.Body.String())
	}

	// 6. Fresco sin token → 200 fast-pass.
	rr5 := httptest.NewRecorder()
	RequireStepUp(auth.ScopeChangePassword, svc, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	).ServeHTTP(rr5, stepUpGuardReq(uid, time.Minute, ""))
	if rr5.Code != http.StatusOK {
		t.Fatalf("fast-pass: %d", rr5.Code)
	}
}

var _ shared.IdempotencyStore = (*e2eIdem)(nil)
