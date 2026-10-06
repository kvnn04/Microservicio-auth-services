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

// --- Fakes HTTP CU-CRED-03 ---

type emailHTTPStore struct {
	uid      string
	taken    map[string]string // newNorm → ownerID
	quota    bool
	issued   int
	rec      *user.EmailChangeRecord
	findErr  error
	consumed bool
}

func (f *emailHTTPStore) QuotaCheck(_ context.Context, _ string) (bool, time.Duration, error) {
	return f.quota, 0, nil
}
func (f *emailHTTPStore) Taken(_ context.Context, newNorm, requesterID string) (bool, error) {
	if owner, ok := f.taken[newNorm]; ok && owner != requesterID {
		return true, nil
	}
	return false, nil
}
func (f *emailHTTPStore) Issue(_ context.Context, rec *user.EmailChangeRecord) error {
	f.issued++
	f.rec = rec
	return nil
}
func (f *emailHTTPStore) FindAlive(_ context.Context, _ string) (*user.EmailChangeRecord, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.rec == nil || !f.rec.Alive(time.Now().UTC()) {
		return nil, user.ErrEmailChangeInvalid
	}
	return f.rec, nil
}
func (f *emailHTTPStore) ConfirmTx(_ context.Context, _ string) (string, string, error) {
	f.consumed = true
	return f.uid, f.rec.NewNormalized, nil
}
func (f *emailHTTPStore) IncrementAttempts(_ context.Context, _ string) (bool, error) {
	return false, nil
}

type emailHTTPUsers struct {
	users map[string]*user.User
}

func (s *emailHTTPUsers) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := s.users[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (s *emailHTTPUsers) FindByID(_ context.Context, id string) (*user.User, error) {
	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, user.ErrNotFound
}
func (s *emailHTTPUsers) CreateWithOutbox(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ string) error {
	return nil
}
func (s *emailHTTPUsers) CreateWithConsents(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext) error {
	return nil
}

type emailHTTPMetrics struct{}

func (emailHTTPMetrics) IncEmailChange(string, string)             {}
func (emailHTTPMetrics) ObserveEmailChangeDuration(string, float64) {}
func (emailHTTPMetrics) IncEmailChangeFallback(string)             {}

type emailHTTPStepUp struct {
	mode string
	err  error
}

func (f *emailHTTPStepUp) Check(_ context.Context, _ string, _ time.Time, _ auth.StepUpScope, _ string) (string, error) {
	return f.mode, f.err
}

// stubPairIssuer genera par link+OTP (solo se usa el link).
type stubPairIssuer struct{}

func (stubPairIssuer) GeneratePair() (string, string, string, string, error) {
	tp := strings.Repeat("A", 43)
	th, _ := user.ParseEmailChangeToken(tp)
	return tp, th, "87654321", "otp-hash", nil
}

func emailStartSvc(users map[string]*user.User, store *emailHTTPStore, stepUp *emailHTTPStepUp) *service.EmailChangeStartService {
	return service.NewEmailChangeStartService(&emailHTTPUsers{users: users}, store,
		stepUp, stubPairIssuer{},
		&stubIdem{m: map[string]string{}}, stubAudit{}, emailHTTPMetrics{}, service.NoopTracer{})
}

func emailUser(uid, email string) *user.User {
	return &user.User{ID: uid, EmailNormalized: email, EmailOriginal: email,
		PasswordHash: "h", Status: user.StatusActive}
}

func doEmailStart(t *testing.T, svc *service.EmailChangeStartService, uid, body string) *httptest.ResponseRecorder {
	t.Helper()
	iss := security.NewSessionIssuer([]byte("test-email-change-secret-32b!"), nil)
	at, _, _, err := iss.Issue(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/email/change/start", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	req.Header.Set("Authorization", "Bearer "+at)
	rr := httptest.NewRecorder()
	middleware.RequireAuth(iss)(EmailChangeStartHandler(svc, nil)).ServeHTTP(rr, req)
	return rr
}

func TestEmailChangeStartHTTP202(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"viejo@example.com": emailUser(uid, "viejo@example.com")}
	store := &emailHTTPStore{uid: uid, quota: true, taken: map[string]string{}}
	svc := emailStartSvc(users, store, &emailHTTPStepUp{})
	rr := doEmailStart(t, svc, uid, `{"new_email":"Nuevo@Example.com "}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("202, got %d %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	data, _ := body["data"].(map[string]any)
	if data["status"] != "confirmation_sent" || data["new_email_masked"] != "n***@example.com" {
		t.Fatalf("body: %v", body)
	}
	if store.issued != 1 {
		t.Fatal("doble-mail encolado (issue 1)")
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("no-store: %q", cc)
	}
}

func TestEmailChangeStartHTTP401409400(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"viejo@example.com": emailUser(uid, "viejo@example.com")}
	// Stale sin token → 401.
	svc := emailStartSvc(users,
		&emailHTTPStore{uid: uid, quota: true, taken: map[string]string{}},
		&emailHTTPStepUp{err: auth.ErrStepUpRequired})
	rr := doEmailStart(t, svc, uid, `{"new_email":"nuevo@example.com"}`)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("stale 401: %d %s", rr.Code, rr.Body.String())
	}
	// Tomado → 409.
	other := uuid.NewString()
	users["ocupado@example.com"] = emailUser(other, "ocupado@example.com")
	store := &emailHTTPStore{uid: uid, quota: true, taken: map[string]string{"ocupado@example.com": other}}
	svc2 := emailStartSvc(users, store, &emailHTTPStepUp{})
	rr2 := doEmailStart(t, svc2, uid, `{"new_email":"ocupado@example.com"}`)
	if rr2.Code != http.StatusConflict || !strings.Contains(rr2.Body.String(), "EMAIL_TAKEN") {
		t.Fatalf("taken 409: %d %s", rr2.Code, rr2.Body.String())
	}
	if store.issued != 0 {
		t.Fatal("tomado no emite")
	}
	// Igual → 400 SAME_EMAIL.
	rr3 := doEmailStart(t, svc2, uid, `{"new_email":"viejo@example.com"}`)
	if rr3.Code != http.StatusBadRequest || !strings.Contains(rr3.Body.String(), "SAME_EMAIL") {
		t.Fatalf("same 400: %d %s", rr3.Code, rr3.Body.String())
	}
}

func emailConfirmSvc(store *emailHTTPStore) *service.EmailChangeConfirmService {
	s := service.NewEmailChangeConfirmService(store,
		&stubIdem{m: map[string]string{}}, stubAudit{}, emailHTTPMetrics{}, service.NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s
}

func emailActiveRec(uid, newEmail string) *user.EmailChangeRecord {
	th, _ := user.ParseEmailChangeToken(strings.Repeat("A", 43))
	return &user.EmailChangeRecord{
		RequesterID: uid, TokenHash: th, NewNormalized: newEmail, NewOriginal: newEmail,
		ExpiresAt: time.Now().UTC().Add(user.EmailChangeTTL),
	}
}

func doEmailConfirm(t *testing.T, svc *service.EmailChangeConfirmService, verifier interface {
	VerifyBusiness(string) (*security.VerifiedSession, error)
}, method, target, body, bearer string,
) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if method == "GET" {
		req = httptest.NewRequest("GET", target, nil)
	} else {
		req = httptest.NewRequest("POST", target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Request-ID", uuid.NewString())
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	EmailChangeConfirmHandler(svc, verifier).ServeHTTP(rr, req)
	return rr
}

func emailBearer(t *testing.T, iss *security.SessionIssuer, uid string) string {
	t.Helper()
	at, _, _, err := iss.Issue(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestEmailChangeConfirmHTTP200(t *testing.T) {
	uid := uuid.NewString()
	iss := security.NewSessionIssuer([]byte("test-email-change-secret-32b!"), nil)
	store := &emailHTTPStore{uid: uid, rec: emailActiveRec(uid, "nuevo@example.com")}
	svc := emailConfirmSvc(store)
	rr := doEmailConfirm(t, svc, iss, "POST", "/confirm",
		`{"token":"`+strings.Repeat("A", 43)+`"}`, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("200, got %d %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	data, _ := body["data"].(map[string]any)
	if data["status"] != "email_changed" || data["new_email_masked"] != "n***@example.com" {
		t.Fatalf("body: %v", body)
	}
	if !store.consumed || len(rr.Result().Cookies()) != 0 {
		t.Fatal("consumido y sin auto-login (sin cookies)")
	}
}

func TestEmailChangeConfirmHTTP400Identicos(t *testing.T) {
	iss := security.NewSessionIssuer([]byte("test-email-change-secret-32b!"), nil)
	bodies := map[string]string{}
	for name, tc := range map[string]struct {
		store *emailHTTPStore
		body  string
	}{
		"miss":      {&emailHTTPStore{findErr: user.ErrEmailChangeInvalid}, `{"token":"` + strings.Repeat("B", 43) + `"}`},
		"expirado":  {&emailHTTPStore{rec: &user.EmailChangeRecord{ExpiresAt: time.Now().UTC().Add(-time.Minute)}}, `{"token":"` + strings.Repeat("A", 43) + `"}`},
		"consumido": {&emailHTTPStore{rec: func() *user.EmailChangeRecord { r := emailActiveRec("u", "nuevo@example.com"); r.Consumed = true; return r }()}, `{"token":"` + strings.Repeat("A", 43) + `"}`},
		"aleatorio": {&emailHTTPStore{findErr: user.ErrEmailChangeInvalid}, `{"token":"` + strings.Repeat("C", 43) + `"}`},
	} {
		svc := emailConfirmSvc(tc.store)
		rr := doEmailConfirm(t, svc, iss, "POST", "/confirm", tc.body, "")
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
	}
}

func TestEmailChangeConfirmHTTPBearerYGet(t *testing.T) {
	uid := uuid.NewString()
	iss := security.NewSessionIssuer([]byte("test-email-change-secret-32b!"), nil)
	// Bearer ajeno → 400 opaco.
	store := &emailHTTPStore{uid: uid, rec: emailActiveRec(uid, "nuevo@example.com")}
	svc := emailConfirmSvc(store)
	rr := doEmailConfirm(t, svc, iss, "POST", "/confirm",
		`{"token":"`+strings.Repeat("A", 43)+`"}`, emailBearer(t, iss, "otro"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("ajeno 400: %d", rr.Code)
	}
	// Bearer propio → 200.
	store2 := &emailHTTPStore{uid: uid, rec: emailActiveRec(uid, "nuevo@example.com")}
	svc2 := emailConfirmSvc(store2)
	rr2 := doEmailConfirm(t, svc2, iss, "POST", "/confirm",
		`{"token":"`+strings.Repeat("A", 43)+`"}`, emailBearer(t, iss, uid))
	if rr2.Code != http.StatusOK {
		t.Fatalf("propio 200: %d %s", rr2.Code, rr2.Body.String())
	}
	// GET form: formato OK → 200 sin consumir; malformado → 400.
	store3 := &emailHTTPStore{uid: uid, rec: emailActiveRec(uid, "nuevo@example.com")}
	svc3 := emailConfirmSvc(store3)
	rr3 := doEmailConfirm(t, svc3, iss, "GET", "/change?token="+strings.Repeat("A", 43), "", "")
	if rr3.Code != http.StatusOK {
		t.Fatalf("GET form: %d", rr3.Code)
	}
	if store3.consumed {
		t.Fatal("GET nunca consume")
	}
	rr4 := doEmailConfirm(t, svc3, iss, "GET", "/change?token=corto", "", "")
	if rr4.Code != http.StatusBadRequest {
		t.Fatalf("GET malformado: %d", rr4.Code)
	}
}

func TestEmailChangeStartHTTP429Throttled(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"viejo@example.com": emailUser(uid, "viejo@example.com")}
	store := &emailHTTPStore{uid: uid, quota: false, taken: map[string]string{}}
	svc := emailStartSvc(users, store, &emailHTTPStepUp{})
	rr := doEmailStart(t, svc, uid, `{"new_email":"nuevo@example.com"}`)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("429, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "EMAIL_SEND_THROTTLED") {
		t.Fatalf("código: %s", rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("falta Retry-After")
	}
	if store.issued != 0 {
		t.Fatal("throttled no emite")
	}
}
