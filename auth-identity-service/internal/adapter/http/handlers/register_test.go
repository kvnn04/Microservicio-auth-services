package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

type stubRepo struct {
	users map[string]*user.User
}

func (s *stubRepo) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := s.users[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (s *stubRepo) FindByID(_ context.Context, _ string) (*user.User, error) {
	return nil, user.ErrNotFound
}
func (s *stubRepo) CreateWithOutbox(_ context.Context, u *user.User, _ []user.OutboxPayload, _ string, _ string) error {
	if _, ok := s.users[u.EmailNormalized]; ok {
		return user.ErrDuplicateShadow
	}
	s.users[u.EmailNormalized] = u
	return nil
}
func (s *stubRepo) CreateWithConsents(_ context.Context, u *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext) error {
	return s.CreateWithOutbox(context.Background(), u, nil, "", "")
}

type stubHasher struct{}

func (stubHasher) Hash(_ context.Context, _ string) (string, error) {
	return "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash", nil
}
func (stubHasher) Verify(_ context.Context, _, _ string) (bool, error) { return true, nil }

type stubBreach struct{}

func (stubBreach) IsCompromised(_ context.Context, _ string) (bool, error) { return false, nil }

type stubIssuer struct{}

func (stubIssuer) Generate() (string, string, error) { return "plain", "tokhash", nil }
func (stubIssuer) HashToken(p string) string         { return p }

type stubOutbox struct{}

func (stubOutbox) Enqueue(_ context.Context, _ []user.OutboxPayload) error { return nil }

type stubIdem struct{ m map[string]string }

func (s *stubIdem) Get(_ context.Context, k string) (string, bool, error) {
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *stubIdem) Put(_ context.Context, k, v string, _ time.Duration) error {
	s.m[k] = v
	return nil
}

type stubAudit struct{}

func (stubAudit) Log(_ context.Context, _ string, _ map[string]string) error { return nil }

func newSvc(users map[string]*user.User) *service.RegisterUserService {
	s := service.NewRegisterUserService(
		&stubRepo{users: users}, stubHasher{}, stubBreach{}, stubIssuer{},
		stubOutbox{}, &stubIdem{m: map[string]string{}}, stubAudit{},
		service.NoopMetrics{}, service.NoopTracer{},
	)
	s.Sleep = func(time.Duration) {}
	return s
}

func doPost(t *testing.T, svc *service.RegisterUserService, body string, reqID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if reqID != "" {
		req.Header.Set("X-Request-ID", reqID)
	}
	rr := httptest.NewRecorder()
	RegisterHandler(svc).ServeHTTP(rr, req)
	return rr
}

func TestRegisterHTTP201Success(t *testing.T) {
	svc := newSvc(map[string]*user.User{})
	rr := doPost(t, svc, `{"email":"Test@Example.com","password":"Str0ng!Passw0rd-2026","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}`, uuid.NewString())
	if rr.Code != http.StatusCreated {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q", cc)
	}
}

func TestRegisterHTTP201ShadowIdentico(t *testing.T) {
	existing := map[string]*user.User{
		"test@example.com": {ID: uuid.NewString(), EmailNormalized: "test@example.com", Status: user.StatusActive},
	}
	svc := newSvc(existing)
	rr1 := doPost(t, newSvc(map[string]*user.User{}),
		`{"email":"nuevo@example.com","password":"Str0ng!Passw0rd-2026","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}`, uuid.NewString())
	rr2 := doPost(t, svc,
		`{"email":"Test@Example.com","password":"0tra!Passw0rd-2026","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}`, uuid.NewString())
	if rr1.Code != rr2.Code || rr1.Body.String() != rr2.Body.String() {
		t.Fatalf("shadow debe ser idéntico:\n%s\n%s", rr1.Body.String(), rr2.Body.String())
	}
}

func TestRegisterHTTP400(t *testing.T) {
	svc := newSvc(map[string]*user.User{})
	rr := doPost(t, svc, `{"email":"no-es-email","password":"123"}`, uuid.NewString())
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRegisterHTTP413(t *testing.T) {
	svc := newSvc(map[string]*user.User{})
	big := `{"email":"a@b.co","password":"` + string(make([]byte, 33*1024)) + `"}`
	rr := doPost(t, svc, big, uuid.NewString())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code=%d want 413 body=%s", rr.Code, rr.Body.String()[:200])
	}
}
