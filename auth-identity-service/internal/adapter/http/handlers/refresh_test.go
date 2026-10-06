package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

func sha256hexRefresh(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// --- Fakes HTTP CU-SES-04 (servicio real, store fake con CAS) ---

type refreshHTTPStore struct {
	current string
	parent  string
	revoked bool
	expired bool
	casErr  error
	lookupInfra bool
	calls   int
	flaps   int64
}

func (f *refreshHTTPStore) Lookup(_ context.Context, h string) (auth.RotationLookup, error) {
	if f.lookupInfra {
		return auth.RotationLookup{}, auth.ErrSessionInfra
	}
	now := time.Now().UTC()
	st := auth.FamilyState{
		Family: "fam-h", UserID: "user-h", SID: "sid-h",
		CurrentHash: f.current, ParentHash: f.parent, Counter: 3,
		AbsoluteExp: now.Add(80 * 24 * time.Hour), Revoked: f.revoked,
		RotatedAt: now.Add(-time.Hour), DeviceHash: "dev-h",
		AuthTime: now.Add(-time.Hour), AMR: []string{"pwd"}, Roles: []string{"user"},
	}
	switch h {
	case f.current:
		if f.expired {
			st.AbsoluteExp = now.Add(-time.Hour)
		}
		return auth.RotationLookup{State: st, PresentedHash: h,
			SlidingExp: now.Add(time.Hour), IsCurrent: true}, nil
	case f.parent:
		if f.parent == "" {
			return auth.RotationLookup{}, auth.ErrRefreshNotFound
		}
		return auth.RotationLookup{State: st, PresentedHash: h,
			SlidingExp: now.Add(time.Hour), IsParent: true}, nil
	default:
		return auth.RotationLookup{}, auth.ErrRefreshNotFound
	}
}

func (f *refreshHTTPStore) RotateCAS(_ context.Context, in auth.RotateCASInput) (auth.RotatedPair, error) {
	f.calls++
	if f.casErr != nil {
		return auth.RotatedPair{}, f.casErr
	}
	if in.OldHash != f.current {
		return auth.RotatedPair{}, auth.ErrRefreshConcurrent
	}
	f.parent = f.current
	f.current = in.NewHash
	return in.NewPair, nil
}

func (f *refreshHTTPStore) ExpireFamily(_ context.Context, _ string) error { return nil }

func (f *refreshHTTPStore) IncrFlaps(_ context.Context, _ string) (int64, error) {
	f.flaps++
	return f.flaps, nil
}

func (f *refreshHTTPStore) ReuseGlobal(_ context.Context, _ auth.ReuseGlobalInput) (auth.GlobalRevokeResult, error) {
	return auth.GlobalRevokeResult{}, nil
}

type refreshHTTPSigner struct{}

func (refreshHTTPSigner) Sign(_ context.Context, c auth.AccessClaims) (string, string, error) {
	return "jwt:" + c.JTI, "k1", nil
}
func (refreshHTTPSigner) ActiveKID() string { return "k1" }

type refreshHTTPGen struct{ n int }

func (g *refreshHTTPGen) Generate(_ context.Context) (string, string, error) {
	g.n++
	plain := "R-nuevo-plano-de-43-caracteres-refresh-" + string(rune('a'+g.n))
	sum := sha256hexRefresh(plain)
	return plain, sum, nil
}
func (g *refreshHTTPGen) Hash(plain string) string { return sha256hexRefresh(plain) }

type refreshHTTPLimiter struct{ deny bool }

func (l *refreshHTTPLimiter) Allow(_ context.Context, _ string, _ int, _ time.Duration) (bool, time.Duration, error) {
	if l.deny {
		return false, time.Minute, nil
	}
	return true, 0, nil
}

type refreshHTTPMetrics struct {
	counts     map[string]int
	reuse      int
	concurrent int
}

func (m *refreshHTTPMetrics) IncRotation(r string)            { m.counts[r]++ }
func (m *refreshHTTPMetrics) ObserveRotationDuration(float64) {}
func (m *refreshHTTPMetrics) IncReuseDetected()               { m.reuse++ }
func (m *refreshHTTPMetrics) IncConcurrent()                  { m.concurrent++ }

func refreshSvcForHTTP(store *refreshHTTPStore, deny bool) *service.RotateService {
	return service.NewRotateService(store, refreshHTTPSigner{}, &refreshHTTPGen{},
		&refreshHTTPLimiter{deny: deny}, &refreshHTTPIdem{m: map[string]string{}},
		&refreshHTTPAudit{}, &refreshHTTPMetrics{counts: map[string]int{}}, service.NoopTracer{})
}

type refreshHTTPIdem struct{ m map[string]string }

func (s *refreshHTTPIdem) Get(_ context.Context, k string) (string, bool, error) {
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *refreshHTTPIdem) Put(_ context.Context, k, v string, _ time.Duration) error {
	s.m[k] = v
	return nil
}

type refreshHTTPAudit struct{}

func (refreshHTTPAudit) Log(_ context.Context, _ string, _ map[string]string) error { return nil }

var _ shared.IdempotencyStore = (*refreshHTTPIdem)(nil)

const (
	refreshCurrentPlain = "R3-actual-plano-43ch-refresh-AAAAAAAAAAAAA"
	refreshParentPlain  = "R2-parent-plano-43ch-refresh-BBBBBBBBBBBBB"
)

func newRefreshHTTPStore() *refreshHTTPStore {
	return &refreshHTTPStore{
		current: sha256hexRefresh(refreshCurrentPlain),
		parent:  sha256hexRefresh(refreshParentPlain),
	}
}

func doRefresh(t *testing.T, h http.HandlerFunc, body, cookie, reqID string, native bool) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Buffer
	if body == "" {
		reader = bytes.NewBufferString("")
	} else {
		reader = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", reader)
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: cookie})
	}
	if reqID == "" {
		reqID = uuid.NewString()
	}
	req.Header.Set("X-Request-ID", reqID)
	if native {
		req.Header.Set("X-Client-Type", "native")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func refreshBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("json: %v %s", err, rr.Body.String())
	}
	return m
}

func TestRefreshHTTP_OkRotadoYReplay(t *testing.T) {
	store := newRefreshHTTPStore()
	h := RefreshHandler(refreshSvcForHTTP(store, false), false)
	body := `{"refresh_token":"` + refreshCurrentPlain + `"}`

	// Web: cookie rotada + body sin refresh plano.
	rr := doRefresh(t, h, body, "", "", false)
	if rr.Code != http.StatusOK {
		t.Fatalf("200, got %d %s", rr.Code, rr.Body.String())
	}
	m := refreshBody(t, rr)
	data := m["data"].(map[string]any)
	if data["status"] != "rotated" || data["sid"] != "sid-h" {
		t.Fatalf("shape: %v", data)
	}
	if _, ok := data["refresh_token"]; ok {
		t.Fatal("web: refresh solo en cookie")
	}
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "refresh_token" && c.Path == "/api/v1/auth/refresh" && c.HttpOnly && c.MaxAge > 1000 {
			found = true
		}
	}
	if !found {
		t.Fatalf("cookie rotada: %v", cookies)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("no-store")
	}
}

func TestRefreshHTTP_GraceReplayMismoRequestID(t *testing.T) {
	store := newRefreshHTTPStore()
	svc := refreshSvcForHTTP(store, false)
	h := RefreshHandler(svc, false)
	// Para replay se necesita un segundo refresh válido: rotamos 1º con
	// reqID fijo y repetimos el MISMO request (mismo body+reqID).
	body1 := `{"refresh_token":"` + refreshCurrentPlain + `"}`
	reqID := uuid.NewString()
	r1 := doRefresh(t, h, body1, "", reqID, true)
	if r1.Code != http.StatusOK {
		t.Fatalf("1º 200: %d", r1.Code)
	}
	// El par emitido quedó guardado bajo reqID: el replay con OTRO body
	// (incluso vacío de refresh válido) devuelve el par guardado... solo si
	// hay refresh válido para pasar forma. Reenviamos mismo body+reqID:
	r2 := doRefresh(t, h, body1, "", reqID, true)
	if r2.Code != http.StatusOK {
		t.Fatalf("replay 200: %d %s", r2.Code, r2.Body.String())
	}
	b1, b2 := refreshBody(t, r1), refreshBody(t, r2)
	if b1["data"].(map[string]any)["access_token"] != b2["data"].(map[string]any)["access_token"] {
		t.Fatal("mismo par en replay")
	}
	// Nativo: refresh plano en body (keystore).
	if _, ok := b2["data"].(map[string]any)["refresh_token"]; !ok {
		t.Fatal("native con refresh en body")
	}
	if store.calls != 1 {
		t.Fatalf("sin re-CAS: %d", store.calls)
	}
}

func TestRefreshHTTP_Errores(t *testing.T) {
	newH := func() (*refreshHTTPStore, http.HandlerFunc) {
		st := newRefreshHTTPStore()
		return st, RefreshHandler(refreshSvcForHTTP(st, false), false)
	}
	// malforma → 400 (sin lookup).
	_, h := newH()
	if rr := doRefresh(t, h, `{"refresh_token":"corto"}`, "", "", false); rr.Code != http.StatusBadRequest {
		t.Fatalf("400, got %d", rr.Code)
	}
	// sin nada → 400.
	if rr := doRefresh(t, h, ``, ``, ``, false); rr.Code != http.StatusBadRequest {
		t.Fatalf("vacío 400, got %d", rr.Code)
	}
	// miss → 401 INVALID_REFRESH.
	if rr := doRefresh(t, h, `{"refresh_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`, "", "", false); rr.Code != http.StatusUnauthorized {
		t.Fatalf("miss 401, got %d", rr.Code)
	} else if !strings.Contains(rr.Body.String(), "INVALID_REFRESH") {
		t.Fatalf("code: %s", rr.Body.String())
	}
	// revoked → 401 FAMILY_REVOKED (sin alarma robo).
	st, h := newH()
	st.revoked = true
	if rr := doRefresh(t, h, `{"refresh_token":"`+refreshCurrentPlain+`"}`, "", "", false); rr.Code != http.StatusUnauthorized ||
		!strings.Contains(rr.Body.String(), "FAMILY_REVOKED") {
		t.Fatalf("revoked: %d %s", rr.Code, rr.Body.String())
	}
	// expirada → 401 SESSION_EXPIRED.
	st, h = newH()
	st.expired = true
	if rr := doRefresh(t, h, `{"refresh_token":"`+refreshCurrentPlain+`"}`, "", "", false); rr.Code != http.StatusUnauthorized ||
		!strings.Contains(rr.Body.String(), "SESSION_EXPIRED") {
		t.Fatalf("expired: %d %s", rr.Code, rr.Body.String())
	}
	// parent fuera de gracia (rotated_at viejo en fake = -1h) → COMPROMISED.
	st, h = newH()
	_ = st
	bodyPar := `{"refresh_token":"` + refreshParentPlain + `"}`
	if rr := doRefresh(t, h, bodyPar, "", "", false); rr.Code != http.StatusUnauthorized ||
		!strings.Contains(rr.Body.String(), "SESSION_COMPROMISED") {
		t.Fatalf("reuse: %d %s", rr.Code, rr.Body.String())
	}
	// rate → 429.
	hd := RefreshHandler(refreshSvcForHTTP(newRefreshHTTPStore(), true), false)
	if rr := doRefresh(t, hd, `{"refresh_token":"`+refreshCurrentPlain+`"}`, "", "", false); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("429, got %d", rr.Code)
	}
	// race CAS perdido → 409 CONCURRENT_ROTATION + meta retry.
	st, h = newH()
	st.casErr = auth.ErrRefreshConcurrent
	if rr := doRefresh(t, h, `{"refresh_token":"`+refreshCurrentPlain+`"}`, "", "", false); rr.Code != http.StatusConflict ||
		!strings.Contains(rr.Body.String(), "CONCURRENT_ROTATION") ||
		!strings.Contains(rr.Body.String(), `"retry":true`) {
		t.Fatalf("409: %d %s", rr.Code, rr.Body.String())
	}
	// PG down → 500 (store Delegate infra: Lookup falla con ErrSessionInfra).
	st, h = newH()
	st.lookupInfra = true
	if rr := doRefresh(t, h, `{"refresh_token":"`+refreshCurrentPlain+`"}`, "", "", false); rr.Code != http.StatusInternalServerError {
		t.Fatalf("500, got %d", rr.Code)
	}
}
