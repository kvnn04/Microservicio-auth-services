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

// Reutiliza mocks de verify_email_test.go (mismo paquete service? no: handlers).
// Mocks locales mínimos para HTTP.

type hStore struct {
	rec       *auth.VerificationRecord
	findErr   error
	consume   *auth.ConsumedUser
	consumeErr error
	activated map[string]string
	quota     bool
}

func (m *hStore) FindAlive(_ context.Context, _ string) (*auth.VerificationRecord, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	return m.rec, nil
}
func (m *hStore) ConsumeAtomically(_ context.Context, uid, hash, method string) (*auth.ConsumedUser, error) {
	if m.consumeErr != nil {
		return nil, m.consumeErr
	}
	if m.consume != nil {
		return m.consume, nil
	}
	return &auth.ConsumedUser{UserID: uid, Method: method}, nil
}
func (m *hStore) Register(_ context.Context, _ *auth.VerificationRecord) error { return nil }
func (m *hStore) IncrementAttempts(_ context.Context, _ string) (int, bool, error) {
	return 2, false, nil
}
func (m *hStore) ResendQuotaCheck(_ context.Context, _ string) (bool, time.Duration, error) {
	return m.quota, 0, nil
}
func (m *hStore) WasActivatedBy(_ context.Context, hash string) (string, bool, error) {
	uid, ok := m.activated[hash]
	return uid, ok, nil
}

type hIdem struct{ m map[string]string }

func (s *hIdem) Get(_ context.Context, k string) (string, bool, error) {
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *hIdem) Put(_ context.Context, k, v string, _ time.Duration) error {
	s.m[k] = v
	return nil
}

type hAudit struct{}

func (hAudit) Log(_ context.Context, _ string, _ map[string]string) error { return nil }

type hMetrics struct{}

func (hMetrics) IncVerification(string, string)       {}
func (hMetrics) ObserveVerificationDuration(float64) {}
func (hMetrics) IncResend(string)                    {}
func (hMetrics) IncAttemptsBurned()                  {}
func (hMetrics) IncRedisFallback(string)             {}
func (hMetrics) IncFederated(string, string)          {}
func (hMetrics) ObserveFederatedDuration(float64)     {}
func (hMetrics) ObserveIDPLatency(string, float64)    {}
func (hMetrics) IncCollision(string)                 {}

func verifySvcForHTTP(rec *auth.VerificationRecord, findErr error) *service.VerifyEmailService {
	st := &hStore{rec: rec, findErr: findErr, activated: map[string]string{}, quota: true}
	s := service.NewVerifyEmailService(st, nil, &hIdem{m: map[string]string{}}, hAudit{}, hMetrics{}, service.NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s
}

func doVerify(t *testing.T, svc *service.VerifyEmailService, method, target, body string) *httptest.ResponseRecorder {
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
	VerifyHandler(svc, nil).ServeHTTP(rr, req)
	return rr
}

func TestVerifyHTTP200Link(t *testing.T) {
	plain := strings.Repeat("A", 43) // 32B
	h, _ := auth.ParseTokenInput(plain)
	rec := &auth.VerificationRecord{UserID: "u1", TokenHash: h, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	svc := verifySvcForHTTP(rec, nil)
	rr := doVerify(t, svc, "POST", "/api/v1/auth/verify-email",
		`{"token":"`+plain+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&out)
	if out["success"] != true {
		t.Fatalf("body=%v", out)
	}
	// GET alias.
	rr = doVerify(t, svc, "GET", "/api/v1/auth/verify-email?token="+plain, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifyHTTP400Indistinguibles(t *testing.T) {
	svc := verifySvcForHTTP(nil, auth.ErrInvalidOrExpired)
	tokB := strings.Repeat("B", 43)
	tokC := strings.Repeat("C", 43)
	bodies := map[string]string{}
	for name, tc := range map[string]struct{ method, target, body string }{
		"aleatorio": {"POST", "/api/v1/auth/verify-email", `{"token":"` + tokB + `"}`},
		"expirado":  {"POST", "/api/v1/auth/verify-email", `{"code":"11111111"}`},
		"consumido": {"GET", "/api/v1/auth/verify-email?token=" + tokC, ""},
	} {
		rr := doVerify(t, svc, tc.method, tc.target, tc.body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: code=%d", name, rr.Code)
		}
		var out map[string]any
		_ = json.NewDecoder(rr.Body).Decode(&out)
		b, _ := json.Marshal(out["error"])
		bodies[name] = string(b)
	}
	if bodies["aleatorio"] != bodies["expirado"] || bodies["expirado"] != bodies["consumido"] {
		t.Fatalf("bodies distinguibles: %v", bodies)
	}
}

func TestVerifyHTTP400Formato(t *testing.T) {
	svc := verifySvcForHTTP(nil, nil)
	rr := doVerify(t, svc, "POST", "/api/v1/auth/verify-email", `{"token":"corto","code":"12345678"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("ambos presentes debe ser 400, got %d", rr.Code)
	}
	rr = doVerify(t, svc, "POST", "/api/v1/auth/verify-email", `{"code":"123"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("OTP corto debe ser 400, got %d", rr.Code)
	}
}

func TestVerifyHTTP413(t *testing.T) {
	svc := verifySvcForHTTP(nil, nil)
	big := `{"token":"` + string(make([]byte, 5000)) + `"}`
	rr := doVerify(t, svc, "POST", "/api/v1/auth/verify-email", big)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code=%d want 413", rr.Code)
	}
}
