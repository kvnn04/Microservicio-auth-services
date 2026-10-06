package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

// --- Fakes HTTP CU-AUTH-05 ---

type plessHTTPStore struct {
	uid      string
	mfa      bool
	eligible bool
	quota    bool
	issued   int
	rec      *auth.PasswordlessRecord
	findErr  error
	lastRisk string
	consumed bool
}

func (f *plessHTTPStore) Eligible(_ context.Context, _ string) (string, bool, bool, error) {
	return f.uid, f.mfa, f.eligible, nil
}
func (f *plessHTTPStore) QuotaCheck(_ context.Context, _ string) (bool, time.Duration, error) {
	return f.quota, 0, nil
}
func (f *plessHTTPStore) Issue(_ context.Context, rec *auth.PasswordlessRecord) error {
	f.issued++
	f.rec = rec
	return nil
}
func (f *plessHTTPStore) FindAlive(_ context.Context, _ string) (*auth.PasswordlessRecord, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.rec == nil || !f.rec.Alive(time.Now().UTC()) {
		return nil, auth.ErrPlessInvalid
	}
	return f.rec, nil
}
func (f *plessHTTPStore) ConsumeTx(_ context.Context, uid, _ string, _, risk, _, _ string) (*auth.PlessConsumeResult, error) {
	f.lastRisk = risk
	f.consumed = true
	return &auth.PlessConsumeResult{UserID: uid, MFAEnabled: f.mfa}, nil
}
func (f *plessHTTPStore) IncrementAttempts(_ context.Context, _ string) (bool, error) {
	return false, nil
}

type plessPairIssuer struct{}

func (plessPairIssuer) GeneratePair() (string, string, string, string, error) {
	tp := strings.Repeat("A", 43)
	th, _ := auth.ParsePlessToken(tp)
	oh, _ := auth.ParsePlessOTP("87654321")
	return tp, th, "87654321", oh, nil
}

type plessMFAIssuer struct{}

func (plessMFAIssuer) IssueChallenge(_ context.Context, uid string) (string, string, int, error) {
	return "mfa-" + uid, "ch-" + uid, 300, nil
}

type plessHTTPMetrics struct{}

func (plessHTTPMetrics) IncPless(string, string)                {}
func (plessHTTPMetrics) ObservePlessDuration(string, float64)   {}
func (plessHTTPMetrics) IncMismatch(string)                    {}
func (plessHTTPMetrics) IncPlessFallback(string)               {}

func plessStartHTTP(store *plessHTTPStore) *service.PasswordlessStartService {
	s := service.NewPasswordlessStartService(store, plessPairIssuer{},
		&hIdem{m: map[string]string{}}, hAudit{}, plessHTTPMetrics{}, service.NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s
}

func plessVerifyHTTP(store *plessHTTPStore) *service.PasswordlessVerifyService {
	s := service.NewPasswordlessVerifyService(store, mfaHTTPSessions{}, plessMFAIssuer{},
		newMFAHTTPChal(), &hIdem{m: map[string]string{}}, hAudit{}, plessHTTPMetrics{}, service.NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s
}

func doPlessStart(t *testing.T, svc *service.PasswordlessStartService, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwordless/start", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	PlessStartHandler(svc, nil).ServeHTTP(rr, req)
	return rr
}

func TestPlessStartHTTP202Identicos(t *testing.T) {
	eligible := &plessHTTPStore{uid: uuid.NewString(), eligible: true, quota: true}
	rr1 := doPlessStart(t, plessStartHTTP(eligible), `{"email":"u@example.com"}`)
	noelig := &plessHTTPStore{uid: "", eligible: false, quota: true}
	rr2 := doPlessStart(t, plessStartHTTP(noelig), `{"email":"nadie@example.com"}`)
	if rr1.Code != http.StatusAccepted || rr2.Code != http.StatusAccepted {
		t.Fatalf("202 siempre: %d %d", rr1.Code, rr2.Code)
	}
	if strings.TrimSpace(rr1.Body.String()) != strings.TrimSpace(rr2.Body.String()) {
		t.Fatalf("cuerpos idénticos:\n%s\n%s", rr1.Body.String(), rr2.Body.String())
	}
	if eligible.issued != 1 || noelig.issued != 0 {
		t.Fatal("solo elegible emite (Mailhog 1)")
	}
	if cc := rr1.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("no-store: %q", cc)
	}
}

func TestPlessStartHTTP400Malforma(t *testing.T) {
	rr := doPlessStart(t, plessStartHTTP(&plessHTTPStore{quota: true}), `{"email":"no-es-email"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("400, got %d %s", rr.Code, rr.Body.String())
	}
}

func doPlessVerify(t *testing.T, svc *service.PasswordlessVerifyService, method, target, body string) *httptest.ResponseRecorder {
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
	PlessVerifyHandler(svc, nil, false).ServeHTTP(rr, req)
	return rr
}

func plessActiveRec(uid string) *auth.PasswordlessRecord {
	th, _ := auth.ParsePlessToken(strings.Repeat("A", 43))
	oh, _ := auth.ParsePlessOTP("87654321")
	return &auth.PasswordlessRecord{
		UserID: uid, TokenHash: th, OTPHash: oh,
		ExpiresAt: time.Now().UTC().Add(auth.PlessTTL),
		Ctx:       auth.NewPlessContext("1.2.3.4", "Mozilla/5.0"),
	}
}

func TestPlessVerifyHTTP200Hibrido(t *testing.T) {
	uid := uuid.NewString()
	store := &plessHTTPStore{uid: uid, eligible: true, quota: true, rec: plessActiveRec(uid)}
	rr := doPlessVerify(t, plessVerifyHTTP(store), "POST", "/verify",
		`{"token":"`+strings.Repeat("A", 43)+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("200, got %d %s", rr.Code, rr.Body.String())
	}
	foundRefresh := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "refresh_token" && c.HttpOnly && c.Path == "/api/v1/auth/refresh" {
			foundRefresh = true
		}
		if c.Name == "access_token" {
			t.Fatal("Access nunca en cookie")
		}
	}
	if !foundRefresh {
		t.Fatal("falta refresh cookie acotada")
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	data, _ := body["data"].(map[string]any)
	if data["access_token"] == nil || data["sid"] == nil {
		t.Fatalf("body: %v", body)
	}
}

func TestPlessVerifyHTTP202MFA(t *testing.T) {
	uid := uuid.NewString()
	store := &plessHTTPStore{uid: uid, mfa: true, eligible: true, quota: true, rec: plessActiveRec(uid)}
	rr := doPlessVerify(t, plessVerifyHTTP(store), "POST", "/verify", `{"code":"87654321"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("202, got %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "mfa_token") {
		t.Fatalf("pre-token: %s", rr.Body.String())
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Fatal("202 sin cookies de sesión")
	}
}

func TestPlessVerifyHTTP400Identicos(t *testing.T) {
	bodies := map[string]string{}
	for name, tc := range map[string]struct {
		store *plessHTTPStore
		body  string
	}{
		"miss":      {&plessHTTPStore{findErr: auth.ErrPlessInvalid}, `{"token":"` + strings.Repeat("B", 43) + `"}`},
		"expirado":  {&plessHTTPStore{rec: &auth.PasswordlessRecord{ExpiresAt: time.Now().UTC().Add(-time.Minute)}}, `{"token":"` + strings.Repeat("A", 43) + `"}`},
		"consumido": {&plessHTTPStore{rec: func() *auth.PasswordlessRecord { r := plessActiveRec("u"); r.Consumed = true; return r }()}, `{"code":"87654321"}`},
		"aleatorio": {&plessHTTPStore{findErr: auth.ErrPlessInvalid}, `{"code":"00000000"}`},
	} {
		rr := doPlessVerify(t, plessVerifyHTTP(tc.store), "POST", "/verify", tc.body)
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
		if strings.Contains(b, "user_id") || strings.Contains(b, "@") {
			t.Fatalf("fuga PII en %s", name)
		}
	}
}

func TestPlessVerifyHTTPGetAlias(t *testing.T) {
	uid := uuid.NewString()
	store := &plessHTTPStore{uid: uid, eligible: true, quota: true, rec: plessActiveRec(uid)}
	rr := doPlessVerify(t, plessVerifyHTTP(store), "GET", "/passwordless?token="+strings.Repeat("A", 43), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET alias 200, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestPlessVerifyHTTPHighRisk200(t *testing.T) {
	uid := uuid.NewString()
	rec := plessActiveRec(uid)
	rec.Ctx = auth.NewPlessContext("192.168.1.10", "Mozilla/5.0 Chrome/120")
	store := &plessHTTPStore{uid: uid, eligible: true, quota: true, rec: rec}
	req := httptest.NewRequest("POST", "/verify", bytes.NewBufferString(`{"token":"`+strings.Repeat("A", 43)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	req.Header.Set("User-Agent", "okhttp/4.12")
	req.RemoteAddr = "10.20.30.40:1234"
	rr := httptest.NewRecorder()
	PlessVerifyHandler(plessVerifyHTTP(store), nil, false).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("high-risk igual 200, got %d %s", rr.Code, rr.Body.String())
	}
	if store.lastRisk != "high" {
		t.Fatalf("risk high, got %q", store.lastRisk)
	}
}
