package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

// --- Fakes HTTP CU-CRED-01 ---

type pwdHTTPStore struct {
	uid      string
	eligible bool
	hint     bool
	quota    bool
	issued   int
	hints    int
	rec      *auth.PasswordResetRecord
	findErr  error
	lastRisk string
	consumed bool
}

func (f *pwdHTTPStore) EligibleForReset(_ context.Context, _ string) (string, bool, bool, error) {
	return f.uid, f.eligible, f.hint, nil
}
func (f *pwdHTTPStore) QuotaCheck(_ context.Context, _ string) (bool, time.Duration, error) {
	return f.quota, 0, nil
}
func (f *pwdHTTPStore) Issue(_ context.Context, rec *auth.PasswordResetRecord) error {
	f.issued++
	f.rec = rec
	return nil
}
func (f *pwdHTTPStore) IssueHint(_ context.Context, _, _ string) error {
	f.hints++
	return nil
}
func (f *pwdHTTPStore) FindAlive(_ context.Context, _ string) (*auth.PasswordResetRecord, *user.User, error) {
	if f.findErr != nil {
		return nil, nil, f.findErr
	}
	if f.rec == nil || !f.rec.Alive(time.Now().UTC()) {
		return nil, nil, auth.ErrPwdResetInvalid
	}
	return f.rec, &user.User{ID: f.uid, EmailNormalized: "u@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash", Status: user.StatusActive}, nil
}
func (f *pwdHTTPStore) ConsumeTx(_ context.Context, uid, _ string, _, risk, _, _, _ string) error {
	f.lastRisk = risk
	f.consumed = true
	return nil
}
func (f *pwdHTTPStore) IncrementAttempts(_ context.Context, _ string) (bool, error) {
	return false, nil
}

type pwdPairIssuer struct{}

func (pwdPairIssuer) GeneratePair() (string, string, string, string, error) {
	tp := strings.Repeat("A", 43)
	th, _ := auth.ParseResetToken(tp)
	return tp, th, "", "", nil
}

type pwdHasher struct{ ok bool }

func (h *pwdHasher) Hash(_ context.Context, _ string) (string, error) { return "new-hash", nil }
func (h *pwdHasher) Verify(_ context.Context, _, _ string) (bool, error) {
	return h.ok, nil
}

type pwdHTTPMetrics struct{}

func (pwdHTTPMetrics) IncReset(string, string)               {}
func (pwdHTTPMetrics) ObserveResetDuration(string, float64)  {}
func (pwdHTTPMetrics) IncHibpFallback()                      {}
func (pwdHTTPMetrics) IncMismatch(string)                    {}
func (pwdHTTPMetrics) IncResetFallback(string)               {}

func pwdStartHTTP(store *pwdHTTPStore) *service.PasswordResetStartService {
	s := service.NewPasswordResetStartService(store, pwdPairIssuer{},
		&stubIdem{m: map[string]string{}}, stubAudit{}, pwdHTTPMetrics{}, service.NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s
}

func pwdConfirmHTTP(store *pwdHTTPStore, reused bool) *service.PasswordResetConfirmService {
	s := service.NewPasswordResetConfirmService(store, &pwdHasher{ok: reused}, nil,
		&stubIdem{m: map[string]string{}}, stubAudit{}, pwdHTTPMetrics{}, service.NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s
}

func doPwdStart(t *testing.T, svc *service.PasswordResetStartService, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset/start", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	PwdResetStartHandler(svc, nil).ServeHTTP(rr, req)
	return rr
}

func TestPwdResetStartHTTP202Identicos(t *testing.T) {
	stores := map[string]*pwdHTTPStore{
		"elegible":  {uid: uuid.NewString(), eligible: true, quota: true},
		"pending":   {uid: uuid.NewString(), quota: true},
		"federated": {uid: uuid.NewString(), hint: true, quota: true},
		"inexistente": {quota: true},
	}
	bodies := map[string]string{}
	for name, st := range stores {
		rr := doPwdStart(t, pwdStartHTTP(st), `{"email":"`+name+`@example.com"}`)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("%s: %d", name, rr.Code)
		}
		bodies[name] = strings.TrimSpace(rr.Body.String())
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("no-store: %q", cc)
		}
	}
	base := bodies["elegible"]
	for name, b := range bodies {
		if b != base {
			t.Fatalf("202 distinguible %s:\n%s\n%s", name, base, b)
		}
	}
	if stores["elegible"].issued != 1 || stores["federated"].hints != 1 {
		t.Fatal("1 link + 1 hint, resto 0 correos")
	}
}

func TestPwdResetStartHTTP400Malforma(t *testing.T) {
	rr := doPwdStart(t, pwdStartHTTP(&pwdHTTPStore{quota: true}), `{"email":"no-es-email"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("400, got %d", rr.Code)
	}
}

func doPwdConfirm(t *testing.T, svc *service.PasswordResetConfirmService, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if method == "GET" {
		req = httptest.NewRequest("GET", target, nil)
	} else {
		req = httptest.NewRequest("POST", target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	PwdResetConfirmHandler(svc, nil).ServeHTTP(rr, req)
	return rr
}

func pwdActiveRec(uid string) *auth.PasswordResetRecord {
	th, _ := auth.ParseResetToken(strings.Repeat("A", 43))
	return &auth.PasswordResetRecord{
		UserID: uid, TokenHash: th,
		ExpiresAt: time.Now().UTC().Add(auth.PwdResetTTL),
		Ctx:       auth.NewPlessContext("1.2.3.4", "Mozilla/5.0"),
	}
}

func TestPwdResetConfirmHTTP200(t *testing.T) {
	uid := uuid.NewString()
	store := &pwdHTTPStore{uid: uid, quota: true, rec: pwdActiveRec(uid)}
	rr := doPwdConfirm(t, pwdConfirmHTTP(store, false), "POST", "/confirm",
		`{"token":"`+strings.Repeat("A", 43)+`","new_password":"Nu3va!Valida-2026"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("200, got %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "password_changed") {
		t.Fatalf("body: %s", rr.Body.String())
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Fatal("sin auto-login: sin cookies")
	}
	if !store.consumed {
		t.Fatal("token consumido")
	}
}

func TestPwdResetConfirmHTTPPolicyYReused(t *testing.T) {
	uid := uuid.NewString()
	// Débil → POLICY con detalle, token intacto.
	st1 := &pwdHTTPStore{uid: uid, quota: true, rec: pwdActiveRec(uid)}
	rr := doPwdConfirm(t, pwdConfirmHTTP(st1, false), "POST", "/confirm",
		`{"token":"`+strings.Repeat("A", 43)+`","new_password":"corta"}`)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "PASSWORD_POLICY_FAILED") {
		t.Fatalf("policy: %d %s", rr.Code, rr.Body.String())
	}
	if st1.consumed {
		t.Fatal("policy-fail no quema")
	}
	// Igual a actual → REUSED.
	st2 := &pwdHTTPStore{uid: uid, quota: true, rec: pwdActiveRec(uid)}
	rr2 := doPwdConfirm(t, pwdConfirmHTTP(st2, true), "POST", "/confirm",
		`{"token":"`+strings.Repeat("A", 43)+`","new_password":"Nu3va!Valida-2026"}`)
	if rr2.Code != http.StatusBadRequest || !strings.Contains(rr2.Body.String(), "PASSWORD_REUSED") {
		t.Fatalf("reused: %d %s", rr2.Code, rr2.Body.String())
	}
}

func TestPwdResetConfirmHTTP400Identicos(t *testing.T) {
	bodies := map[string]string{}
	for name, tc := range map[string]struct {
		store *pwdHTTPStore
		body  string
	}{
		"miss":      {&pwdHTTPStore{findErr: auth.ErrPwdResetInvalid}, `{"token":"` + strings.Repeat("B", 43) + `","new_password":"Nu3va!Valida-2026"}`},
		"expirado":  {&pwdHTTPStore{rec: &auth.PasswordResetRecord{ExpiresAt: time.Now().UTC().Add(-time.Minute)}}, `{"token":"` + strings.Repeat("A", 43) + `","new_password":"Nu3va!Valida-2026"}`},
		"consumido": {&pwdHTTPStore{rec: func() *auth.PasswordResetRecord { r := pwdActiveRec("u"); r.Consumed = true; return r }()}, `{"token":"` + strings.Repeat("A", 43) + `","new_password":"Nu3va!Valida-2026"}`},
		"aleatorio": {&pwdHTTPStore{findErr: auth.ErrPwdResetInvalid}, `{"token":"` + strings.Repeat("C", 43) + `","new_password":"Nu3va!Valida-2026"}`},
	} {
		rr := doPwdConfirm(t, pwdConfirmHTTP(tc.store, false), "POST", "/confirm", tc.body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, rr.Code)
		}
		bodies[name] = strings.TrimSpace(rr.Body.String())
	}
	base := bodies["miss"]
	for name, b := range bodies {
		if b != base {
			t.Fatalf("400 distinguible %s:\n%s\n%s", name, base, b)
		}
		if strings.Contains(b, "user_id") {
			t.Fatalf("fuga en %s", name)
		}
	}
}

func TestPwdResetConfirmHTTPGetForm(t *testing.T) {
	store := &pwdHTTPStore{}
	rr := doPwdConfirm(t, pwdConfirmHTTP(store, false), "GET", "/reset?token="+strings.Repeat("A", 43), "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "reset_form") {
		t.Fatalf("GET form: %d %s", rr.Code, rr.Body.String())
	}
	if store.consumed {
		t.Fatal("GET nunca consume")
	}
	rr2 := doPwdConfirm(t, pwdConfirmHTTP(store, false), "GET", "/reset?token=corto", "")
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("GET malformado 400: %d", rr2.Code)
	}
}

func TestPwdResetConfirmHTTPHighRisk200(t *testing.T) {
	uid := uuid.NewString()
	rec := pwdActiveRec(uid)
	rec.Ctx = auth.NewPlessContext("192.168.1.10", "Mozilla/5.0 Chrome/120")
	store := &pwdHTTPStore{uid: uid, quota: true, rec: rec}
	req := httptest.NewRequest("POST", "/confirm",
		bytes.NewBufferString(`{"token":"`+strings.Repeat("A", 43)+`","new_password":"Nu3va!Valida-2026"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	req.Header.Set("User-Agent", "okhttp/4.12")
	req.RemoteAddr = "10.20.30.40:1234"
	rr := httptest.NewRecorder()
	PwdResetConfirmHandler(pwdConfirmHTTP(store, false), nil).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("high-risk igual 200: %d %s", rr.Code, rr.Body.String())
	}
	if store.lastRisk != "high" {
		t.Fatalf("risk high: %q", store.lastRisk)
	}
}
