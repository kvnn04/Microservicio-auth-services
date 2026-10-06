package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

// --- Fakes HTTP CU-SES-01 ---

type logoutHTTPVerifier struct {
	claims map[string]auth.AccessClaims
}

func (f *logoutHTTPVerifier) Verify(tok string) (auth.AccessClaims, error) {
	if c, ok := f.claims[tok]; ok {
		return c, nil
	}
	return auth.AccessClaims{}, errors.New("bad signature")
}

type logoutHTTPRevoker struct {
	revoked map[string]bool // sid → revoked
	hashToSID map[string]string
	calls   int
	fail    error
}

func newLogoutHTTPRevoker() *logoutHTTPRevoker {
	return &logoutHTTPRevoker{revoked: map[string]bool{}, hashToSID: map[string]string{}}
}

func (f *logoutHTTPRevoker) RevokeSID(_ context.Context, id auth.LogoutIdentity) (auth.RevokedSession, error) {
	f.calls++
	if f.fail != nil {
		return auth.RevokedSession{}, f.fail
	}
	if f.revoked[id.SID] {
		return auth.RevokedSession{
			Result:   auth.LogoutAlreadyLoggedOut,
			Identity: auth.LogoutIdentity{UserID: id.UserID, SID: id.SID, JTI: id.JTI, Family: "fam-" + id.SID, ExpiresAt: id.ExpiresAt},
		}, nil
	}
	f.revoked[id.SID] = true
	return auth.RevokedSession{
		Result:   auth.LogoutLoggedOut,
		Identity: auth.LogoutIdentity{UserID: id.UserID, SID: id.SID, JTI: id.JTI, Family: "fam-" + id.SID, ExpiresAt: id.ExpiresAt},
	}, nil
}

func (f *logoutHTTPRevoker) RevokeByRefreshHash(_ context.Context, h string) (auth.RevokedSession, error) {
	f.calls++
	if f.fail != nil {
		return auth.RevokedSession{}, f.fail
	}
	sid, ok := f.hashToSID[h]
	if !ok {
		return auth.RevokedSession{Result: auth.LogoutAlreadyLoggedOut}, nil
	}
	if f.revoked[sid] {
		return auth.RevokedSession{Result: auth.LogoutAlreadyLoggedOut}, nil
	}
	f.revoked[sid] = true
	now := time.Now().UTC()
	return auth.RevokedSession{
		Result:   auth.LogoutLoggedOut,
		Identity: auth.LogoutIdentity{UserID: "u-refresh", SID: sid, JTI: "jti-" + sid, Family: "fam-" + sid, ExpiresAt: now.Add(5 * time.Minute)},
	}, nil
}

type logoutHTTPLimiter struct{ deny bool }

func (l *logoutHTTPLimiter) Allow(_ context.Context, _ string, _ int, _ time.Duration) (bool, time.Duration, error) {
	if l.deny {
		return false, time.Second, nil
	}
	return true, 0, nil
}

type logoutHTTPIdem struct{ m map[string]string }

func (s *logoutHTTPIdem) Get(_ context.Context, k string) (string, bool, error) {
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *logoutHTTPIdem) Put(_ context.Context, k, v string, _ time.Duration) error {
	s.m[k] = v
	return nil
}

type logoutHTTPMetrics struct{}

func (logoutHTTPMetrics) IncLogout(string)             {}
func (logoutHTTPMetrics) ObserveLogoutDuration(float64) {}
func (logoutHTTPMetrics) SetDenylistSize(float64)        {}

// Métricas globales CU-SES-02 (mismo fake).
func (logoutHTTPMetrics) IncGlobal(string)            {}
func (logoutHTTPMetrics) ObserveGlobalDuration(float64) {}
func (logoutHTTPMetrics) ObserveSessionsRevoked(int)    {}

// Métricas de sesiones CU-SES-03 (mismo fake).
func (logoutHTTPMetrics) IncListed(string)                {}
func (logoutHTTPMetrics) ObserveListDuration(float64)     {}
func (logoutHTTPMetrics) IncRevokedOne(string)            {}
func (logoutHTTPMetrics) ObserveRevokeOneDuration(float64) {}

func logoutClaimsFor(sub, sid, jti string) auth.AccessClaims {
	now := time.Now().UTC()
	return auth.AccessClaims{
		Iss: "https://auth.example.com", Aud: "api",
		Sub: sub, SID: sid, JTI: jti,
		Iat: now.Add(-time.Minute).Unix(), Exp: now.Add(10 * time.Minute).Unix(),
		AuthTime: now.Add(-time.Hour).Unix(),
	}
}

func logoutSvcForHTTP(ver *logoutHTTPVerifier, rev *logoutHTTPRevoker, deny bool) *service.LogoutService {
	return service.NewLogoutService(ver, rev, &logoutHTTPLimiter{deny: deny},
		&logoutHTTPIdem{m: map[string]string{}}, logoutHTTPMetrics{}, service.NoopTracer{})
}

func doLogout(t *testing.T, h http.HandlerFunc, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Buffer
	if body == "" {
		reader = bytes.NewBufferString("")
	} else {
		reader = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", reader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("X-Request-ID", uuid.NewString())
	req.RemoteAddr = "9.9.9.9:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestLogoutHTTP_AB_AMuereBVive(t *testing.T) {
	ver := &logoutHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": logoutClaimsFor("user-1", "sid-A", "jti-A"),
		"jwt-B": logoutClaimsFor("user-1", "sid-B", "jti-B"),
	}}
	rev := newLogoutHTTPRevoker()
	h := LogoutHandler(logoutSvcForHTTP(ver, rev, false), false)

	rrA := doLogout(t, h, "jwt-A", "")
	if rrA.Code != http.StatusOK {
		t.Fatalf("A logout 200, got %d %s", rrA.Code, rrA.Body.String())
	}
	var outA struct {
		Success bool `json:"success"`
		Data    struct{ Status string `json:"status"` } `json:"data"`
	}
	if err := json.Unmarshal(rrA.Body.Bytes(), &outA); err != nil || outA.Data.Status != "logged_out" {
		t.Fatalf("A status logged_out: %s err=%v", rrA.Body.String(), err)
	}
	// B sigue viva: su logout también da logged_out (no already).
	rrB := doLogout(t, h, "jwt-B", "")
	if rrB.Code != http.StatusOK {
		t.Fatalf("B logout 200, got %d", rrB.Code)
	}
	var outB struct {
		Success bool `json:"success"`
		Data    struct{ Status string `json:"status"` } `json:"data"`
	}
	_ = json.Unmarshal(rrB.Body.Bytes(), &outB)
	if outB.Data.Status != "logged_out" {
		t.Fatalf("B debe ser logged_out (vive), got %q", outB.Data.Status)
	}
	// A repetido → already (idempotente 200).
	rrA2 := doLogout(t, h, "jwt-A", "")
	var outA2 struct {
		Success bool `json:"success"`
		Data    struct{ Status string `json:"status"` } `json:"data"`
	}
	_ = json.Unmarshal(rrA2.Body.Bytes(), &outA2)
	if outA2.Data.Status != "already_logged_out" {
		t.Fatalf("replay A already, got %q", outA2.Data.Status)
	}
	if rrA.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("no-store siempre")
	}
}

func TestLogoutHTTP_SinNada_401(t *testing.T) {
	ver := &logoutHTTPVerifier{claims: map[string]auth.AccessClaims{}}
	h := LogoutHandler(logoutSvcForHTTP(ver, newLogoutHTTPRevoker(), false), false)
	rr := doLogout(t, h, "", "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("401, got %d %s", rr.Code, rr.Body.String())
	}
	// Sin Bearer pero con JSON inválido → también 401 (body se ignora).
	rr2 := doLogout(t, h, "", "{no-json")
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("body inválido ignorado → 401, got %d", rr2.Code)
	}
}

func TestLogoutHTTP_RefreshAlt(t *testing.T) {
	ver := &logoutHTTPVerifier{claims: map[string]auth.AccessClaims{}}
	rev := newLogoutHTTPRevoker()
	// hash de 64 'a' → sid-R.
	rev.hashToSID[strings.Repeat("a", 64)] = "sid-R"
	h := LogoutHandler(logoutSvcForHTTP(ver, rev, false), false)
	plain := strings.Repeat("A", 43) // forma válida; el servicio lo hashea...
	// Para el fake necesitamos el hash exacto que el servicio calcula:
	// usamos directamente el hash registrado vía body con plain que hashee a 64 'a'? No.
	// En su lugar, registramos el hash real: el servicio hashea el plain con SHA-256.
	// Calculamos aquí el hash del plain y lo registramos.
	rev.hashToSID[logoutTestHash(plain)] = "sid-R"
	rr := doLogout(t, h, "", `{"refresh_token":"`+plain+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh-alt 200, got %d %s", rr.Code, rr.Body.String())
	}
}

func logoutTestHash(plain string) string {
	// Duplica service.logoutRefreshHash (SHA-256 hex) sin importar service.
	// Implementación local para el test HTTP.
	h := sha256hexLogout(plain)
	return h
}

func sha256hexLogout(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestLogoutHTTP_ClearCookie_PathMatch(t *testing.T) {
	ver := &logoutHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": logoutClaimsFor("user-1", "sid-A", "jti-A"),
	}}
	h := LogoutHandler(logoutSvcForHTTP(ver, newLogoutHTTPRevoker(), false), false)
	rr := doLogout(t, h, "jwt-A", "")
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "refresh_token" {
			found = true
			if c.Path != "/api/v1/auth/refresh" {
				t.Fatalf("Path MISMO que Issue: %q", c.Path)
			}
			if !c.HttpOnly || c.MaxAge != 0 {
				t.Fatalf("Clear-Cookie HttpOnly + MaxAge=0: %+v", c)
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("SameSite=Lax: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("falta Clear-Cookie refresh_token")
	}
}

func TestLogoutHTTP_PGDown_500_SinCookie(t *testing.T) {
	ver := &logoutHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": logoutClaimsFor("user-1", "sid-A", "jti-A"),
	}}
	rev := newLogoutHTTPRevoker()
	rev.fail = auth.ErrSessionInfra
	h := LogoutHandler(logoutSvcForHTTP(ver, rev, false), false)
	rr := doLogout(t, h, "jwt-A", "")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("PG down 500, got %d", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "refresh_token" {
			t.Fatal("500 SIN Clear-Cookie mentirosa")
		}
	}
}

func TestLogoutHTTP_Rate_429(t *testing.T) {
	ver := &logoutHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": logoutClaimsFor("user-1", "sid-A", "jti-A"),
	}}
	h := LogoutHandler(logoutSvcForHTTP(ver, newLogoutHTTPRevoker(), true), false)
	rr := doLogout(t, h, "jwt-A", "")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 con Retry-After")
	}
}
