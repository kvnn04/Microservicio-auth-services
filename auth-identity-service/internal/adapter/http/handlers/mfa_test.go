package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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

type mfaHTTPUsers struct {
	users map[string]*user.User
}

func (s *mfaHTTPUsers) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := s.users[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (s *mfaHTTPUsers) FindByID(_ context.Context, id string) (*user.User, error) {
	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, user.ErrNotFound
}
func (s *mfaHTTPUsers) CreateWithOutbox(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ string, _ *user.VerificationMail) error {
	return nil
}
func (s *mfaHTTPUsers) CreateWithConsents(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext, _ *user.VerificationMail) error {
	return nil
}

type mfaHTTPStore struct {
	staged map[string][]byte
	active map[string][]byte
}

func (s *mfaHTTPStore) Stage(_ context.Context, uid string, enc []byte) error {
	s.staged[uid] = enc
	return nil
}
func (s *mfaHTTPStore) Staged(_ context.Context, uid string) ([]byte, bool, error) {
	if enc, ok := s.staged[uid]; ok {
		return enc, false, nil
	}
	return nil, false, auth.ErrNoStaged
}
func (s *mfaHTTPStore) PromoteTx(_ context.Context, uid string) error { return nil }
func (s *mfaHTTPStore) GetActive(_ context.Context, uid string) ([]byte, error) {
	if enc, ok := s.active[uid]; ok {
		return enc, nil
	}
	return nil, user.ErrNotFound
}
func (s *mfaHTTPStore) DisableTx(_ context.Context, uid string) error { return nil }

type mfaHTTPPreToken struct {
	claims auth.PreTokenClaims
	err    error
}

func (f *mfaHTTPPreToken) ValidateChallenge(_ string) (auth.PreTokenClaims, error) {
	if f.err != nil {
		return auth.PreTokenClaims{}, f.err
	}
	return f.claims, nil
}

type mfaHTTPChal struct {
	live  map[string]string
	used  map[string]bool
	fails map[string]int
}

func newMFAHTTPChal() *mfaHTTPChal {
	return &mfaHTTPChal{live: map[string]string{}, used: map[string]bool{}, fails: map[string]int{}}
}
func (f *mfaHTTPChal) Register(_ context.Context, cid, uid string) error {
	f.live[cid] = uid
	return nil
}
func (f *mfaHTTPChal) Consume(_ context.Context, cid string) (string, error) {
	uid, ok := f.live[cid]
	if !ok {
		return "", user.ErrNotFound
	}
	delete(f.live, cid)
	return uid, nil
}
func (f *mfaHTTPChal) RecordFail(_ context.Context, cid string) (bool, error) {
	f.fails[cid]++
	if f.fails[cid] >= 5 {
		delete(f.live, cid)
		return true, nil
	}
	return false, nil
}
func (f *mfaHTTPChal) MarkReplay(_ context.Context, uid string, c int64) (bool, error) {
	k := uid + "/" + itoaHTTP(c)
	if f.used[k] {
		return false, nil
	}
	f.used[k] = true
	return true, nil
}
func (f *mfaHTTPChal) Uncheckable(_ context.Context) bool { return false }

func itoaHTTP(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var mfaTestSecret = []byte("test-secrets-key-32bytes!!!!!!!!")

type mfaHTTPSessions struct{}

func (mfaHTTPSessions) Issue(_ context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	return auth.IssuedPair{
		AccessJWT: "at-" + req.UserID, RefreshPlain: "rt-43ch-test-vector-0000000000000000000",
		SID: "sid-test", JTI: "jti", Family: "fam", KID: "2026-10-a",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

func mfaStack(users map[string]*user.User) (*service.MFAService, *security.SessionIssuer, *mfaHTTPChal) {
	iss := security.NewSessionIssuer([]byte("test-session-secret-32bytes!!"), nil)
	chal := newMFAHTTPChal()
	box, _ := security.NewSecretBox(mfaTestSecret)
	svc := service.NewMFAService(security.NewTOTPProvider(), box,
		&mfaHTTPStore{staged: map[string][]byte{}, active: map[string][]byte{}},
		chal, &mfaHTTPPreToken{}, nil, nil,
		&mfaHTTPUsers{users: users}, nil, mfaHTTPSessions{},
		nil, &stubIdem{m: map[string]string{}}, stubAudit{},
		service.NoopMFAMetrics{}, service.NoopTracer{}, "Example")
	svc.Sleep = func(time.Duration) {}
	return svc, iss, chal
}

func doAuthedMFA(t *testing.T, iss *security.SessionIssuer, uid string, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	at, _, _, err := iss.Issue(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func mfaChain(iss *security.SessionIssuer, h http.Handler, fresh bool) http.Handler {
	inner := h
	if fresh {
		// Fresh lee auth_time del ctx: auth corre primero (más externo).
		inner = middleware.RequireFreshAuth(5 * time.Minute)(inner)
	}
	inner = middleware.RequireAuth(iss)(inner)
	return middleware.Recover(middleware.RequestID(inner))
}

func activeMFAUser(uid, email string) *user.User {
	return &user.User{ID: uid, EmailNormalized: email, Status: user.StatusActive,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"}
}

func TestMFAHTTPSetupStale401(t *testing.T) {
	svc, iss, _ := mfaStack(map[string]*user.User{})
	// Bearer inválido → 401 sin tocar servicio.
	req := httptest.NewRequest("POST", "/mfa/totp/setup", nil)
	req.Header.Set("Authorization", "Bearer invalido")
	rr := httptest.NewRecorder()
	mfaChain(iss, MFASetupHandler(svc, nil), true).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rr.Code)
	}
	_ = svc
}

func TestMFAHTTPVerifyOKQuemaReplay(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"u@example.com": activeMFAUser(uid, "u@example.com")}
	svc, iss, chal := mfaStack(users)
	_ = iss
	// Pre-token real emitido por el issuer de login (misma secret de sesión).
	pretok, _, _, err := security.NewMFAPreTokenIssuer([]byte("test-session-secret-32bytes!!")).IssueChallenge(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	// Challenge vivo + secreto activo real (generado por provider).
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	totp := security.NewTOTPProvider()
	code, _ := totp.CodeAt(context.Background(), raw, auth.NewCounter(time.Now().UTC()))
	// Guarda secreto cifrado directo en el store del servicio.
	box, _ := security.NewSecretBox(mfaTestSecret)
	enc, _ := box.Encrypt(context.Background(), uid, raw)
	store := svc.Secrets.(*mfaHTTPStore)
	store.active[uid] = enc
	// Challenge registrado con el challenge_id del pretoken: extrae del payload.
	chID := challengeIDOf(t, pretok)
	chal.live[chID] = uid
	body, _ := json.Marshal(map[string]string{"mfa_token": pretok, "code": code})
	req := httptest.NewRequest("POST", "/mfa/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	// Validador real de pretoken.
	svc.PreToken = security.NewMFAPreTokenIssuer([]byte("test-session-secret-32bytes!!"))
	MFAVerifyHandler(svc, nil, false).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rr.Code, rr.Body.String())
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Fatal("faltan cookies de sesión")
	}
	// Replay mismo body → 401 (challenge consumido).
	req2 := httptest.NewRequest("POST", "/mfa/verify", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Request-ID", uuid.NewString())
	rr2 := httptest.NewRecorder()
	MFAVerifyHandler(svc, nil, false).ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized || !strings.Contains(rr2.Body.String(), "INVALID_MFA") {
		t.Fatalf("replay: %d %s", rr2.Code, rr2.Body.String())
	}
}

func challengeIDOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("token malo")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		ChallengeID string `json:"challenge_id"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.ChallengeID
}

func TestMFAHTTPDisableUltimo400(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"s@example.com": {
		ID: uid, EmailNormalized: "s@example.com", Status: user.StatusActive,
	}}
	svc, iss, _ := mfaStack(users)
	rr := doAuthedMFA(t, iss, uid,
		mfaChain(iss, MFADisableHandler(svc), true), "DELETE", "/mfa/totp", "")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "LAST_AUTH_FACTOR") {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
}
