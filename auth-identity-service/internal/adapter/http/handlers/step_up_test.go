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

	"auth-identity-service/internal/adapter/http/middleware"
	"auth-identity-service/internal/adapter/security"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

// --- Fakes HTTP CU-AUTH-06 ---

type stepUpHTTPUsers struct {
	users map[string]*user.User
}

func (s *stepUpHTTPUsers) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := s.users[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (s *stepUpHTTPUsers) FindByID(_ context.Context, id string) (*user.User, error) {
	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, user.ErrNotFound
}
func (s *stepUpHTTPUsers) CreateWithOutbox(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ string, _ *user.VerificationMail) error {
	return nil
}
func (s *stepUpHTTPUsers) CreateWithConsents(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext, _ *user.VerificationMail) error {
	return nil
}

type stepUpHTTPIssuer struct {
	n int
}

func (f *stepUpHTTPIssuer) IssueToken(_ context.Context, uid string, scope auth.StepUpScope, amr []string) (string, string, error) {
	f.n++
	_ = amr
	return "stup-token-" + string(scope), "jti-http-1", nil
}
func (f *stepUpHTTPIssuer) VerifyToken(string) (auth.StepUpClaims, error) {
	return auth.StepUpClaims{}, nil
}

type stepUpHTTPJTIs struct {
	saved map[string][2]string
}

func (f *stepUpHTTPJTIs) Save(_ context.Context, jti, sub, scope string) error {
	if f.saved == nil {
		f.saved = map[string][2]string{}
	}
	f.saved[jti] = [2]string{sub, scope}
	return nil
}
func (f *stepUpHTTPJTIs) Consume(_ context.Context, jti string) (string, string, bool, error) {
	v, ok := f.saved[jti]
	if !ok {
		return "", "", false, nil
	}
	delete(f.saved, jti)
	return v[0], v[1], true, nil
}

type stepUpHTTPMetrics struct{}

func (stepUpHTTPMetrics) IncStepUp(string, string)              {}
func (stepUpHTTPMetrics) ObserveStepUpDuration(string, float64) {}
func (stepUpHTTPMetrics) IncReuseBlocked()                      {}

func stepUpSvcForHTTP(users map[string]*user.User, hasher auth.PasswordHasher) (*service.StepUpService, *stepUpHTTPJTIs) {
	jtis := &stepUpHTTPJTIs{}
	if hasher == nil {
		hasher = stubHasher{}
	}
	s := service.NewStepUpService(&stepUpHTTPUsers{users: users}, hasher, nil,
		nil, nil, nil, nil, nil, nil,
		&stepUpHTTPIssuer{}, jtis, stubOutbox{},
		&stubIdem{m: map[string]string{}}, stubAudit{}, stepUpHTTPMetrics{}, service.NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s, jtis
}

func stepUpUser(uid, email string, mfa bool, withPassword bool) *user.User {
	pw := ""
	if withPassword {
		pw = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"
	}
	return &user.User{ID: uid, EmailNormalized: email, EmailOriginal: email,
		PasswordHash: pw, Status: user.StatusActive, MFAEnabled: mfa}
}

func doStepUpChallenge(t *testing.T, svc *service.StepUpService, uid, body string) *httptest.ResponseRecorder {
	t.Helper()
	// Bearer legacy válido (el middleware real usa HybridVerifier; la firma
	// acepta cualquier verificador con VerifyBusiness).
	iss := security.NewSessionIssuer([]byte("test-stepup-secret-32bytes!!!"), nil)
	at, _, _, err := iss.Issue(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/step-up/challenge", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	req.Header.Set("Authorization", "Bearer "+at)
	rr := httptest.NewRecorder()
	middleware.RequireAuth(iss)(StepUpChallengeHandler(svc, nil)).ServeHTTP(rr, req)
	return rr
}

func TestStepUpChallengeHTTP200(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"u@example.com": stepUpUser(uid, "u@example.com", false, true)}
	svc, jtis := stepUpSvcForHTTP(users, nil)
	rr := doStepUpChallenge(t, svc, uid, `{"scope":"cred:change-password","password":"ok"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("200, got %d %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	data, _ := body["data"].(map[string]any)
	if data["step_up_token"] == nil || data["scope"] != "cred:change-password" || data["expires_in"] != float64(300) {
		t.Fatalf("body: %v", body)
	}
	if len(jtis.saved) != 1 {
		t.Fatal("jti single-use registrado")
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("no-store: %q", cc)
	}
}

func TestStepUpChallengeHTTP401Opaco(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"u@example.com": stepUpUser(uid, "u@example.com", false, true)}
	badHasher := &stepUpBadHasher{}
	svc, _ := stepUpSvcForHTTP(users, badHasher)
	rr := doStepUpChallenge(t, svc, uid, `{"scope":"cred:change-password","password":"mala"}`)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("401, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "INVALID_STEP_UP") {
		t.Fatalf("código: %s", rr.Body.String())
	}
}

func TestStepUpChallengeHTTP400Scope(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"u@example.com": stepUpUser(uid, "u@example.com", false, true)}
	svc, _ := stepUpSvcForHTTP(users, nil)
	rr := doStepUpChallenge(t, svc, uid, `{"scope":"admin","password":"x"}`)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "UNKNOWN_SCOPE") {
		t.Fatalf("400 scope: %d %s", rr.Code, rr.Body.String())
	}
}

func TestStepUpChallengeHTTP401Relogin(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"f@example.com": stepUpUser(uid, "f@example.com", false, false)}
	svc, _ := stepUpSvcForHTTP(users, nil)
	rr := doStepUpChallenge(t, svc, uid, `{"scope":"federated:unlink"}`)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "STEP_UP_REQUIRES_RELOGIN") {
		t.Fatalf("relogin: %d %s", rr.Code, rr.Body.String())
	}
}

func TestStepUpChallengeHTTP401SinBearer(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"u@example.com": stepUpUser(uid, "u@example.com", false, true)}
	svc, _ := stepUpSvcForHTTP(users, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/step-up/challenge",
		bytes.NewBufferString(`{"scope":"mfa:disable","password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	StepUpChallengeHandler(svc, nil).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("sin Bearer 401: %d", rr.Code)
	}
}

// stepUpBadHasher rechaza siempre (401 opaco).
type stepUpBadHasher struct{}

func (stepUpBadHasher) Hash(_ context.Context, _ string) (string, error) { return "h", nil }
func (stepUpBadHasher) Verify(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
