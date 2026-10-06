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

// --- Fakes HTTP CU-CRED-02 ---

type changeHTTPStore struct {
	acct      *auth.ChangeAccount
	hist      []string
	rotateErr error
	rotated   int
	peers     int
	keepSID   string
}

func (f *changeHTTPStore) Current(_ context.Context, _ string) (*auth.ChangeAccount, error) {
	cp := *f.acct
	return &cp, nil
}
func (f *changeHTTPStore) LastN(_ context.Context, _ string, _ int) ([]string, error) {
	return f.hist, nil
}
func (f *changeHTTPStore) RotateTx(_ context.Context, _, oldHash, _ string, _ int, keepSID, _ string) (int, int, error) {
	if f.rotateErr != nil {
		return 0, 0, f.rotateErr
	}
	f.rotated++
	f.keepSID = keepSID
	_ = oldHash
	return 4, f.peers, nil
}

type changeHTTPHasher struct {
	currentOK bool
}

func (h *changeHTTPHasher) Hash(_ context.Context, _ string) (string, error) {
	return "new-hash", nil
}
func (h *changeHTTPHasher) Verify(_ context.Context, plain, _ string) (bool, error) {
	// "actual" verifica; la nueva nunca es la actual aquí.
	return h.currentOK && plain == "actual", nil
}

type changeHTTPMetrics struct{}

func (changeHTTPMetrics) IncChange(string, string)     {}
func (changeHTTPMetrics) ObserveChangeDuration(float64) {}
func (changeHTTPMetrics) IncHistoryHit()               {}
func (changeHTTPMetrics) IncPeersRevoked(int)          {}
func (changeHTTPMetrics) IncChangeLock()               {}
func (changeHTTPMetrics) IncHibpFallback()             {}

type changeHTTPChecker struct {
	mode string
	err  error
}

func (f *changeHTTPChecker) Check(_ context.Context, _ string, _ time.Time, _ auth.StepUpScope, _ string) (string, error) {
	return f.mode, f.err
}

func changeSvcForHTTP(acct *auth.ChangeAccount, hist []string, currentOK bool, checker service.StepUpChecker) (*service.ChangePasswordService, *changeHTTPStore) {
	store := &changeHTTPStore{acct: acct, hist: hist, peers: 2}
	s := service.NewChangePasswordService(store, &changeHTTPHasher{currentOK: currentOK}, nil, nil,
		checker, stubOutbox{}, &stubIdem{m: map[string]string{}}, stubAudit{}, changeHTTPMetrics{}, service.NoopTracer{})
	return s, store
}

func changeUser(acctID string, withPassword bool) *auth.ChangeAccount {
	h := ""
	if withPassword {
		h = "old-hash"
	}
	return &auth.ChangeAccount{ID: acctID, Email: "u@example.com", Hash: h, Ver: 3, Status: user.StatusActive}
}

func doChange(t *testing.T, svc *service.ChangePasswordService, uid, body, stepUpToken string) *httptest.ResponseRecorder {
	t.Helper()
	iss := security.NewSessionIssuer([]byte("test-change-secret-32bytes!!!!"), nil)
	at, _, _, err := iss.Issue(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	req.Header.Set("Authorization", "Bearer "+at)
	if stepUpToken != "" {
		req.Header.Set("X-Step-Up-Token", stepUpToken)
	}
	rr := httptest.NewRecorder()
	middleware.RequireAuth(iss)(ChangePasswordHandler(svc, nil)).ServeHTTP(rr, req)
	return rr
}

func TestChangeHTTP200RevocaPares(t *testing.T) {
	uid := uuid.NewString()
	svc, store := changeSvcForHTTP(changeUser(uid, true), nil, true, &changeHTTPChecker{})
	rr := doChange(t, svc, uid,
		`{"current_password":"actual","new_password":"Nu3va!Valida-2026"}`, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("200, got %d %s", rr.Code, rr.Body.String())
	}
	var decoded map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&decoded)
	data, _ := decoded["data"].(map[string]any)
	if data["status"] != "password_changed" || data["sessions_revoked"] != float64(2) {
		t.Fatalf("body: %v", decoded)
	}
	// Bearer legacy sin sid → corte total fail-closed (keepSID "").
	if store.keepSID != "" || store.rotated != 1 {
		t.Fatal("una rotación (corte total con Bearer legacy)")
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("no-store: %q", cc)
	}
}

func TestChangeHTTP401MalaY400s(t *testing.T) {
	uid := uuid.NewString()
	// Current mala → 401 (hasher que falla).
	svcBad, _ := changeSvcForHTTP(changeUser(uid, true), nil, false, &changeHTTPChecker{})
	rr := doChange(t, svcBad, uid, `{"current_password":"mala","new_password":"Nu3va!Valida-2026"}`, "")
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "INVALID_CURRENT") {
		t.Fatalf("401 current: %d %s", rr.Code, rr.Body.String())
	}
	// Reused → 400 (Verify true para la nueva).
	svcRe2, _ := changeSvcForHTTP(changeUser(uid, true), nil, true, &changeHTTPChecker{})
	svcRe2.Hasher = &changeReuseHasher{}
	rr2 := doChange(t, svcRe2, uid, `{"current_password":"actual","new_password":"Nu3va!Valida-2026"}`, "")
	if rr2.Code != http.StatusBadRequest || !strings.Contains(rr2.Body.String(), "PASSWORD_REUSED") {
		t.Fatalf("reused: %d %s", rr2.Code, rr2.Body.String())
	}
	// Policy débil → 400 con detalle.
	svcPol, _ := changeSvcForHTTP(changeUser(uid, true), nil, true, &changeHTTPChecker{})
	rr3 := doChange(t, svcPol, uid, `{"current_password":"actual","new_password":"corta"}`, "")
	if rr3.Code != http.StatusBadRequest || !strings.Contains(rr3.Body.String(), "PASSWORD_POLICY_FAILED") {
		t.Fatalf("policy: %d %s", rr3.Code, rr3.Body.String())
	}
	// Missing current → 400 MISSING_CURRENT.
	rr4 := doChange(t, svcPol, uid, `{"new_password":"Nu3va!Valida-2026"}`, "")
	if rr4.Code != http.StatusBadRequest || !strings.Contains(rr4.Body.String(), "MISSING_CURRENT") {
		t.Fatalf("missing: %d %s", rr4.Code, rr4.Body.String())
	}
}

// changeReuseHasher verifica todo (actual y nueva) → reused.
type changeReuseHasher struct{}

func (changeReuseHasher) Hash(_ context.Context, _ string) (string, error) { return "h", nil }
func (changeReuseHasher) Verify(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

func TestChangeHTTPFederatedSet(t *testing.T) {
	uid := uuid.NewString()
	// Sin token → 401 STEP_UP_REQUIRED.
	svc, _ := changeSvcForHTTP(changeUser(uid, false), nil, true,
		&changeHTTPChecker{err: auth.ErrStepUpRequired})
	rr := doChange(t, svc, uid, `{"new_password":"Nu3va!Valida-2026"}`, "")
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("required: %d %s", rr.Code, rr.Body.String())
	}
	// Con token válido → 200 via set.
	svc2, _ := changeSvcForHTTP(changeUser(uid, false), nil, true,
		&changeHTTPChecker{mode: "token"})
	rr2 := doChange(t, svc2, uid, `{"new_password":"Nu3va!Valida-2026"}`, "stup")
	if rr2.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rr2.Code, rr2.Body.String())
	}
	// Con current inesperado → 400.
	rr3 := doChange(t, svc2, uid, `{"current_password":"x","new_password":"Nu3va!Valida-2026"}`, "stup")
	if rr3.Code != http.StatusBadRequest || !strings.Contains(rr3.Body.String(), "UNEXPECTED_CURRENT") {
		t.Fatalf("unexpected: %d %s", rr3.Code, rr3.Body.String())
	}
}

func TestChangeHTTPHistory(t *testing.T) {
	uid := uuid.NewString()
	// En historial → 400 IN_HISTORY con meta n=5.
	histHasherSvc, histStore := changeSvcForHTTP(changeUser(uid, true), []string{"h1"}, true, &changeHTTPChecker{})
	_ = histStore
	histSvc := histHasherSvc
	histSvc.Hasher = &changeHistHasher{}
	rr := doChange(t, histSvc, uid, `{"current_password":"actual","new_password":"H1-valida!2026X"}`, "")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "PASSWORD_IN_HISTORY") {
		t.Fatalf("history: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"n":5`) {
		t.Fatalf("meta n=5: %s", rr.Body.String())
	}
}

// changeHistHasher: actual ok, historial con H1.
type changeHistHasher struct{}

func (changeHistHasher) Hash(_ context.Context, _ string) (string, error) { return "h", nil }
func (changeHistHasher) Verify(_ context.Context, plain, hash string) (bool, error) {
	if hash == "old-hash" {
		return plain == "actual", nil
	}
	return plain == "H1-valida!2026X", nil
}
