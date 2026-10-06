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

	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

// TestShadowEqualityBytes: unique vs shadow deben ser byte-idénticos.
// Veto contractual: jamás 409/422 ni campos available/exists/taken.
func TestShadowEqualityBytes(t *testing.T) {
	unique := newSvc(map[string]*user.User{})
	shadow := newSvc(map[string]*user.User{
		"test@example.com": {ID: uuid.NewString(), EmailNormalized: "test@example.com", Status: user.StatusActive},
	})
	bodyOf := func(svc *service.RegisterUserService, email, pw string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register",
			bytes.NewBufferString(`{"email":"`+email+`","password":"`+pw+`","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-ID", uuid.NewString())
		rr := httptest.NewRecorder()
		RegisterHandler(svc).ServeHTTP(rr, req)
		return rr.Code, strings.TrimSpace(rr.Body.String())
	}
	c1, b1 := bodyOf(unique, "nuevo-xyz@example.com", "Str0ng!Passw0rd-2026")
	c2, b2 := bodyOf(shadow, "Test@Example.com ", "0tra!Passw0rd-2026")
	if c1 != http.StatusCreated || c2 != http.StatusCreated {
		t.Fatalf("codes %d vs %d", c1, c2)
	}
	if b1 != b2 {
		t.Fatalf("bodies distinguibles:\n%s\n%s", b1, b2)
	}
	for _, banned := range []string{"409", "422", "available", "exists", "taken", "already", "duplicate", "user_id"} {
		if strings.Contains(strings.ToLower(b2), banned) {
			t.Fatalf("fuga %q en body shadow", banned)
		}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(b2), &out); err != nil {
		t.Fatal(err)
	}
	if _, hasData := out["data"]; !hasData {
		t.Fatal("falta data.status")
	}
}

// Resend genérico: inexistente, ACTIVE y PENDING → mismo 202.
type resendRepo struct {
	users map[string]*user.User
}

type pairIssuer struct{}

func (pairIssuer) GeneratePair() (string, string, string, string, error) {
	return "plain", "th", "12345678", "oh", nil
}

func (s *resendRepo) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := s.users[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (s *resendRepo) FindByID(_ context.Context, _ string) (*user.User, error) {
	return nil, user.ErrNotFound
}
func (s *resendRepo) CreateWithOutbox(_ context.Context, u *user.User, _ []user.OutboxPayload, _ string, _ string) error {
	return nil
}
func (s *resendRepo) CreateWithConsents(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext) error {
	return nil
}

func TestResendGenerico(t *testing.T) {
	repo := &resendRepo{users: map[string]*user.User{
		"active@example.com":  {ID: uuid.NewString(), EmailNormalized: "active@example.com", Status: user.StatusActive},
		"pending@example.com": {ID: uuid.NewString(), EmailNormalized: "pending@example.com", Status: user.StatusPendingVerification},
	}}
	store := &hStore{activated: map[string]string{}, quota: true}
	newSvc := func() *service.ResendService {
		s := service.NewResendService(repo, store, pairIssuer{}, &stubIdem{m: map[string]string{}}, stubAudit{}, hMetrics{}, service.NoopTracer{})
		return s
	}
	bodies := map[string]string{}
	for name, email := range map[string]string{
		"inexistente": "nadie@example.com",
		"active":      "active@example.com",
		"pending":     "pending@example.com",
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification",
			bytes.NewBufferString(`{"email":"`+email+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-ID", uuid.NewString())
		rr := httptest.NewRecorder()
		ResendHandler(newSvc(), nil).ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("%s: code=%d body=%s", name, rr.Code, rr.Body.String())
		}
		bodies[name] = strings.TrimSpace(rr.Body.String())
	}
	if bodies["inexistente"] != bodies["active"] || bodies["active"] != bodies["pending"] {
		t.Fatalf("resend distinguible: %v", bodies)
	}
	_ = time.Now
}
