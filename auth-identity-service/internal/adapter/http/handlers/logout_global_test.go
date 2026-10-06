package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

// --- Fakes HTTP CU-SES-02 ---

// logoutGlobalHTTPVerifier mapea token→claims (sid incluidos).
type logoutGlobalHTTPVerifier struct {
	claims map[string]auth.AccessClaims
}

func (f *logoutGlobalHTTPVerifier) Verify(tok string) (auth.AccessClaims, error) {
	if c, ok := f.claims[tok]; ok {
		return c, nil
	}
	return auth.AccessClaims{}, errors.New("bad signature")
}

// logoutGlobalHTTPRevoker mata TODAS las sids registradas del usuario.
type logoutGlobalHTTPRevoker struct {
	alive map[string]map[string]bool // user → sid → viva
	calls int
	fail  error
}

func newLogoutGlobalHTTPRevoker() *logoutGlobalHTTPRevoker {
	return &logoutGlobalHTTPRevoker{alive: map[string]map[string]bool{}}
}

func (f *logoutGlobalHTTPRevoker) add(user, sid string) {
	if f.alive[user] == nil {
		f.alive[user] = map[string]bool{}
	}
	f.alive[user][sid] = true
}

func (f *logoutGlobalHTTPRevoker) RevokeAll(_ context.Context, userID, _ string) (auth.GlobalRevokeResult, error) {
	f.calls++
	if f.fail != nil {
		return auth.GlobalRevokeResult{}, f.fail
	}
	n := 0
	for sid, live := range f.alive[userID] {
		if live {
			f.alive[userID][sid] = false
			n++
		}
	}
	return auth.GlobalRevokeResult{Sessions: n, Families: n, ValidAfter: time.Now().UTC()}, nil
}

func globalClaimsFor(sub, sid string) auth.AccessClaims {
	now := time.Now().UTC()
	return auth.AccessClaims{
		Iss: "https://auth.example.com", Aud: "api",
		Sub: sub, SID: sid, JTI: "jti-" + sid,
		Iat: now.Add(-time.Minute).Unix(), Exp: now.Add(10 * time.Minute).Unix(),
		AuthTime: now.Add(-time.Hour).Unix(),
	}
}

func globalSvcForHTTP(ver *logoutGlobalHTTPVerifier, rev *logoutGlobalHTTPRevoker, limiter auth.LogoutLimiter) *service.LogoutGlobalService {
	if limiter == nil {
		limiter = &logoutHTTPLimiter{}
	}
	return service.NewLogoutGlobalService(ver, rev, limiter,
		&logoutHTTPIdem{m: map[string]string{}}, logoutHTTPMetrics{}, service.NoopTracer{})
}

func doGlobal(t *testing.T, h http.HandlerFunc, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout-global", bytes.NewBufferString(""))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("X-Request-ID", uuid.NewString())
	req.RemoteAddr = "9.9.9.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestLogoutGlobalHTTP_Corte3_TodosMueren(t *testing.T) {
	ver := &logoutGlobalHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": globalClaimsFor("user-1", "sid-A"),
		"jwt-B": globalClaimsFor("user-1", "sid-B"),
		"jwt-C": globalClaimsFor("user-1", "sid-C"),
	}}
	rev := newLogoutGlobalHTTPRevoker()
	rev.add("user-1", "sid-A")
	rev.add("user-1", "sid-B")
	rev.add("user-1", "sid-C")
	h := LogoutGlobalHandler(globalSvcForHTTP(ver, rev, nil), false)

	rr := doGlobal(t, h, "jwt-A")
	if rr.Code != http.StatusOK {
		t.Fatalf("200, got %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Success bool `json:"success"`
		Data    struct {
			Status          string `json:"status"`
			SessionsRevoked int    `json:"sessions_revoked"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil ||
		out.Data.Status != "logged_out_global" || out.Data.SessionsRevoked != 3 {
		t.Fatalf("corte 3: %s err=%v", rr.Body.String(), err)
	}
	// Repeat con A (nueva RequestID) → 200 con 0.
	rr2 := doGlobal(t, h, "jwt-A")
	var out2 struct {
		Success bool `json:"success"`
		Data    struct {
			Status          string `json:"status"`
			SessionsRevoked int    `json:"sessions_revoked"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr2.Body.Bytes(), &out2)
	if rr2.Code != http.StatusOK || out2.Data.SessionsRevoked != 0 {
		t.Fatalf("repeat 0: %d %s", rr2.Code, rr2.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("no-store siempre")
	}
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "refresh_token" && c.Path == "/api/v1/auth/refresh" && c.MaxAge == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("Clear-Cookie MISMO Path")
	}
}

func TestLogoutGlobalHTTP_401s(t *testing.T) {
	ver := &logoutGlobalHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": globalClaimsFor("user-1", "sid-A"),
	}}
	h := LogoutGlobalHandler(globalSvcForHTTP(ver, newLogoutGlobalHTTPRevoker(), nil), false)
	if rr := doGlobal(t, h, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("sin Bearer 401, got %d", rr.Code)
	}
	if rr := doGlobal(t, h, "jwt-malo"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("malo 401, got %d", rr.Code)
	}
}

func TestLogoutGlobalHTTP_Flood429(t *testing.T) {
	ver := &logoutGlobalHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": globalClaimsFor("user-1", "sid-A"),
	}}
	rev := newLogoutGlobalHTTPRevoker()
	rev.add("user-1", "sid-A")
	lim := &countGlobalHTTPLimiter{limit: 5}
	h := LogoutGlobalHandler(globalSvcForHTTP(ver, rev, lim), false)
	var ok, limited int
	for i := 0; i < 7; i++ {
		rr := doGlobal(t, h, "jwt-A")
		switch rr.Code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
			if rr.Header().Get("Retry-After") == "" {
				t.Fatal("429 con Retry-After")
			}
		default:
			t.Fatalf("iter %d: %d", i, rr.Code)
		}
	}
	if ok != 5 || limited != 2 {
		t.Fatalf("5×200 + 2×429: ok=%d limited=%d", ok, limited)
	}
}

// countGlobalHTTPLimiter permite N usos por clave (flood horario).
type countGlobalHTTPLimiter struct {
	limit  int
	counts map[string]int
}

func (l *countGlobalHTTPLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	if l.counts == nil {
		l.counts = map[string]int{}
	}
	l.counts[key]++
	if l.counts[key] > l.limit {
		return false, time.Hour, nil
	}
	return true, 0, nil
}

func TestLogoutGlobalHTTP_PGDown500SinCookie(t *testing.T) {
	ver := &logoutGlobalHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": globalClaimsFor("user-1", "sid-A"),
	}}
	rev := newLogoutGlobalHTTPRevoker()
	rev.fail = auth.ErrSessionInfra
	h := LogoutGlobalHandler(globalSvcForHTTP(ver, rev, nil), false)
	rr := doGlobal(t, h, "jwt-A")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("500, got %d", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "refresh_token" {
			t.Fatal("500 SIN Clear-Cookie")
		}
	}
}
