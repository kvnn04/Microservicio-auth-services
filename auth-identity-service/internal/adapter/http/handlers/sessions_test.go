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

// --- Fakes HTTP CU-SES-03 ---

type sessionsHTTPVerifier struct {
	claims map[string]auth.AccessClaims
}

func (f *sessionsHTTPVerifier) Verify(tok string) (auth.AccessClaims, error) {
	if c, ok := f.claims[tok]; ok {
		return c, nil
	}
	return auth.AccessClaims{}, errors.New("bad signature")
}

type sessionsHTTPLister struct {
	alive    map[string]map[string]auth.SessionView // user → sid → view
	revokeErr error
	listErr   error
}

func newSessionsHTTPLister() *sessionsHTTPLister {
	return &sessionsHTTPLister{alive: map[string]map[string]auth.SessionView{}}
}

func (f *sessionsHTTPLister) List(_ context.Context, userID string) ([]auth.SessionView, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []auth.SessionView
	for _, v := range f.alive[userID] {
		out = append(out, v)
	}
	// Orden last_seen DESC (como PG).
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].LastSeen.After(out[i].LastSeen) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

func (f *sessionsHTTPLister) RevokeOne(_ context.Context, userID, _, target string) (auth.RevokedOne, error) {
	if f.revokeErr != nil {
		return auth.RevokedOne{}, f.revokeErr
	}
	m := f.alive[userID]
	v, ok := m[target]
	if !ok {
		return auth.RevokedOne{}, auth.ErrSessionNotFound
	}
	delete(m, target)
	return auth.RevokedOne{SID: target, DeviceLabel: v.DeviceLabel, IPMasked: v.IPMasked}, nil
}

func sessionsHTTPClaims(sub, sid string) auth.AccessClaims {
	now := time.Now().UTC()
	return auth.AccessClaims{
		Iss: "https://auth.example.com", Aud: "api",
		Sub: sub, SID: sid, JTI: "jti-" + sid,
		Iat: now.Add(-time.Minute).Unix(), Exp: now.Add(10 * time.Minute).Unix(),
		AuthTime: now.Add(-time.Hour).Unix(),
	}
}

func seedSessionsHTTP(f *sessionsHTTPLister, user string, sids ...string) {
	now := time.Now().UTC()
	for i, sid := range sids {
		if f.alive[user] == nil {
			f.alive[user] = map[string]auth.SessionView{}
		}
		f.alive[user][sid] = auth.SessionView{
			SID: sid, DeviceLabel: "Chrome · Windows", IPMasked: "203.0.113.xxx",
			CreatedAt: now, LastSeen: now.Add(-time.Duration(i) * time.Hour),
		}
	}
}

func listSvcForHTTP(ver *sessionsHTTPVerifier, lister *sessionsHTTPLister) (*service.ListSessionsService, *service.RevokeSessionService) {
	limiter := &logoutHTTPLimiter{}
	lsvc := service.NewListSessionsService(ver, lister, limiter, &sessionsHTTPAudit{}, logoutHTTPMetrics{}, service.NoopTracer{})
	rsvc := service.NewRevokeSessionService(ver, lister, limiter, logoutHTTPMetrics{}, service.NoopTracer{})
	return lsvc, rsvc
}

type sessionsHTTPAudit struct{}

func (sessionsHTTPAudit) Log(_ context.Context, _ string, _ map[string]string) error {
	return nil
}

func doSessionsList(t *testing.T, h http.HandlerFunc, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func doRevokeOne(t *testing.T, h http.HandlerFunc, bearer, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+target, nil)
	req.SetPathValue("sid", target)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestSessionsListHTTP_MaskedYCurrent(t *testing.T) {
	sidA, sidB, sidC := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ver := &sessionsHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": sessionsHTTPClaims("user-1", sidA),
	}}
	lister := newSessionsHTTPLister()
	seedSessionsHTTP(lister, "user-1", sidA, sidB, sidC)
	lsvc, _ := listSvcForHTTP(ver, lister)

	rr := doSessionsList(t, SessionsListHandler(lsvc), "jwt-A")
	if rr.Code != http.StatusOK {
		t.Fatalf("200, got %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Success bool `json:"success"`
		Data    struct {
			Total    int              `json:"total"`
			Sessions []map[string]any `json:"sessions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Data.Total != 3 {
		t.Fatalf("total 3: %s err=%v", rr.Body.String(), err)
	}
	current := 0
	for _, s := range out.Data.Sessions {
		// Prohibidos: cualquier rastro de secreto.
		for _, k := range []string{"jti", "family", "access_token", "refresh_token", "hash", "tokens"} {
			if _, ok := s[k]; ok {
				t.Fatalf("campo prohibido %q", k)
			}
		}
		if s["ip_masked"] == nil {
			t.Fatal("ip_masked presente")
		}
		if c, _ := s["current"].(bool); c {
			current++
			if s["sid"] != sidA {
				t.Fatalf("current solo A: %v", s["sid"])
			}
		}
	}
	if current != 1 {
		t.Fatalf("exactamente 1 current: %d", current)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("no-store")
	}
}

func TestSessionsListHTTP_401y500(t *testing.T) {
	ver := &sessionsHTTPVerifier{claims: map[string]auth.AccessClaims{}}
	lister := newSessionsHTTPLister()
	lsvc, _ := listSvcForHTTP(ver, lister)
	if rr := doSessionsList(t, SessionsListHandler(lsvc), ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("sin Bearer 401, got %d", rr.Code)
	}
	// PG down → 500, jamás 200 [] falso.
	lister.listErr = auth.ErrSessionInfra
	ver2 := &sessionsHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": sessionsHTTPClaims("user-1", "sid-A"),
	}}
	lsvc2, _ := listSvcForHTTP(ver2, lister)
	rr := doSessionsList(t, SessionsListHandler(lsvc2), "jwt-A")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("PG down 500, got %d", rr.Code)
	}
	if bytes.Contains(rr.Body.Bytes(), []byte(`"sessions":[]`)) {
		t.Fatal("nunca 200 [] falso")
	}
}

func TestRevokeOneHTTP_RemotaOkYRepeat404(t *testing.T) {
	sidA, sidB, sidC := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ver := &sessionsHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": sessionsHTTPClaims("user-1", sidA),
	}}
	lister := newSessionsHTTPLister()
	seedSessionsHTTP(lister, "user-1", sidA, sidB, sidC)
	_, rsvc := listSvcForHTTP(ver, lister)
	h := RevokeOneHandler(rsvc)

	rr := doRevokeOne(t, h, "jwt-A", sidC)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke C 200, got %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Success bool `json:"success"`
		Data    struct {
			Status string `json:"status"`
			SID    string `json:"sid"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Data.Status != "revoked" || out.Data.SID != sidC {
		t.Fatalf("payload: %s", rr.Body.String())
	}
	if _, ok := lister.alive["user-1"][sidC]; ok {
		t.Fatal("C muerta")
	}
	if len(lister.alive["user-1"]) != 2 {
		t.Fatal("A/B vivas")
	}
	// Repeat → 404 (miss indistinguible, §4.2).
	if rr2 := doRevokeOne(t, h, "jwt-A", sidC); rr2.Code != http.StatusNotFound {
		t.Fatalf("repeat 404, got %d", rr2.Code)
	}
}

func TestRevokeOneHTTP_400sY404Iguales(t *testing.T) {
	sidA, sidX := uuid.NewString(), uuid.NewString()
	ver := &sessionsHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": sessionsHTTPClaims("user-1", sidA),
	}}
	lister := newSessionsHTTPLister()
	seedSessionsHTTP(lister, "user-1", sidA)
	seedSessionsHTTP(lister, "user-2", sidX)
	_, rsvc := listSvcForHTTP(ver, lister)
	h := RevokeOneHandler(rsvc)

	// Actual → 400 USE_LOGOUT + A viva.
	rr := doRevokeOne(t, h, "jwt-A", sidA)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("actual 400, got %d", rr.Code)
	}
	var useLogout struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &useLogout)
	if useLogout.Error.Code != "USE_LOGOUT" {
		t.Fatalf("code USE_LOGOUT: %s", rr.Body.String())
	}
	if _, ok := lister.alive["user-1"][sidA]; !ok {
		t.Fatal("A viva tras USE_LOGOUT")
	}

	// Malformado → 400.
	if rr := doRevokeOne(t, h, "jwt-A", "no-uuid"); rr.Code != http.StatusBadRequest {
		t.Fatalf("malforma 400, got %d", rr.Code)
	}

	// Ajena vs inexistente: 404 idénticos (supuesto Q4).
	rrAlien := doRevokeOne(t, h, "jwt-A", sidX)
	rrGhost := doRevokeOne(t, h, "jwt-A", uuid.NewString())
	if rrAlien.Code != http.StatusNotFound || rrGhost.Code != http.StatusNotFound {
		t.Fatalf("404 ambos: %d %d", rrAlien.Code, rrGhost.Code)
	}
	if rrAlien.Body.String() != rrGhost.Body.String() {
		t.Fatalf("404 idénticos:\n%s\n%s", rrAlien.Body.String(), rrGhost.Body.String())
	}
	if _, ok := lister.alive["user-2"][sidX]; !ok {
		t.Fatal("ajena intacta")
	}
}

func TestRevokeOneHTTP_PGDown500(t *testing.T) {
	ver := &sessionsHTTPVerifier{claims: map[string]auth.AccessClaims{
		"jwt-A": sessionsHTTPClaims("user-1", "sid-A"),
	}}
	lister := newSessionsHTTPLister()
	lister.revokeErr = auth.ErrSessionInfra
	_, rsvc := listSvcForHTTP(ver, lister)
	if rr := doRevokeOne(t, RevokeOneHandler(rsvc), "jwt-A", uuid.NewString()); rr.Code != http.StatusInternalServerError {
		t.Fatalf("500, got %d", rr.Code)
	}
}
