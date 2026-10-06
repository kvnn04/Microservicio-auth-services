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
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

type loginStubRepo struct {
	users map[string]*user.User
}

func (s *loginStubRepo) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := s.users[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (s *loginStubRepo) FindByID(_ context.Context, _ string) (*user.User, error) {
	return nil, user.ErrNotFound
}
func (s *loginStubRepo) CreateWithOutbox(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ string) error {
	return nil
}
func (s *loginStubRepo) CreateWithConsents(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext) error {
	return nil
}

type loginStubTracker struct{}

func (loginStubTracker) CheckLimits(_ context.Context, _, _ string) error { return nil }
func (loginStubTracker) IsLocked(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (loginStubTracker) RecordFail(_ context.Context, _ string) (bool, bool, error) {
	return false, false, nil
}
func (loginStubTracker) ResetOnSuccess(_ context.Context, _ string) error { return nil }

type loginStubSessions struct{}

func (loginStubSessions) Issue(_ context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	return auth.IssuedPair{
		AccessJWT: "at", RefreshPlain: "rt-43ch-test-vector-0000000000000000000",
		SID: "sid-test", JTI: "jti", Family: "fam", KID: "2026-10-a",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

type loginStubMFA struct{}

func (loginStubMFA) IssueChallenge(_ context.Context, _ string) (string, string, int, error) {
	return "mfa-token", "ch-1", 300, nil
}

func loginSvcHTTP(users map[string]*user.User) *service.LoginService {
	s := service.NewLoginService(&loginStubRepo{users: users}, stubHasher{}, loginStubTracker{},
		loginStubSessions{}, loginStubMFA{}, nil, stubOutbox{}, &stubIdem{m: map[string]string{}},
		stubAudit{}, service.NoopLoginMetrics{}, service.NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s
}

func doLogin(t *testing.T, svc *service.LoginService, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	LoginHandler(svc, false).ServeHTTP(rr, req)
	return rr
}

func activeLoginUser(mfa bool) *user.User {
	return &user.User{ID: uuid.NewString(), EmailNormalized: "u@example.com", Status: user.StatusActive,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash", MFAEnabled: mfa}
}

func TestLoginHTTP200(t *testing.T) {
	svc := loginSvcHTTP(map[string]*user.User{"u@example.com": activeLoginUser(false)})
	rr := doLogin(t, svc, `{"email":"u@example.com","password":"x"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache %q", cc)
	}
	// CU-AUTH-04 híbrida web: Refresh en cookie acotada + Access en body (nunca en cookie/URL).
	var foundRefresh bool
	var refreshPath string
	var refreshHttpOnly bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "refresh_token" && c.HttpOnly {
			foundRefresh = true
			refreshPath = c.Path
			refreshHttpOnly = c.HttpOnly
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("SameSite Lax, got %v", c.SameSite)
			}
		}
		if c.Name == "access_token" {
			t.Fatal("Access NUNCA en cookie (memoria JS)")
		}
	}
	if !foundRefresh || !refreshHttpOnly {
		t.Fatal("falta refresh_token HttpOnly")
	}
	if refreshPath != "/api/v1/auth/refresh" {
		t.Fatalf("Path acotado, got %q", refreshPath)
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	data, _ := body["data"].(map[string]any)
	if data == nil || data["access_token"] == nil || data["sid"] == nil {
		t.Fatalf("body debe traer access_token+sid: %v", body)
	}
	if exp, _ := data["expires_in"].(float64); exp != 900 {
		t.Fatalf("expires_in 900, got %v", data["expires_in"])
	}
}

func TestLoginHTTP202MFA(t *testing.T) {
	svc := loginSvcHTTP(map[string]*user.User{"u@example.com": activeLoginUser(true)})
	rr := doLogin(t, svc, `{"email":"u@example.com","password":"x"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&out)
	data := out["data"].(map[string]any)
	if data["status"] != "mfa_required" || data["mfa_token"] == nil {
		t.Fatalf("body=%v", out)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Fatal("202 sin cookies de sesión")
	}
}

func TestLoginHTTP401Identicos(t *testing.T) {
	pending := activeLoginUser(false)
	pending.Status = user.StatusPendingVerification
	fed := activeLoginUser(false)
	fed.PasswordHash = ""
	svc := loginSvcHTTP(map[string]*user.User{
		"u@example.com":       activeLoginUser(false),
		"pending@example.com": pending,
		"fed@example.com":     fed,
	})
	bodies := map[string]string{}
	cases := map[string]string{
		"inexistente": `{"email":"nadie@example.com","password":"x"}`,
		"pending":     `{"email":"pending@example.com","password":"x"}`,
		"federado":    `{"email":"fed@example.com","password":"x"}`,
	}
	for name, body := range cases {
		rr := doLogin(t, svc, body)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s: code=%d", name, rr.Code)
		}
		bodies[name] = strings.TrimSpace(rr.Body.String())
	}
	if bodies["inexistente"] != bodies["pending"] || bodies["pending"] != bodies["federado"] {
		t.Fatalf("401 distinguibles: %v", bodies)
	}
	for _, banned := range []string{"USER_NOT_FOUND", "WRONG_PASSWORD", "NOT_VERIFIED", "LOCKED", "403", "404", "409", "423"} {
		for name, b := range bodies {
			_ = name
			if strings.Contains(b, banned) {
				t.Fatalf("fuga %q", banned)
			}
		}
	}
	_ = auth.ErrInvalidCredentials
}
