package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-identity-service/internal/adapter/security"
)

func testIssuer() *security.SessionIssuer {
	return security.NewSessionIssuer([]byte("test-secret-32bytes-1234567890"), nil)
}

func TestRequireAuth(t *testing.T) {
	iss := testIssuer()
	next := RequireAuth(iss)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _, ok := AuthUserFromContext(r.Context())
		if !ok || uid == "" {
			t.Error("sin identidad en ctx")
		}
		w.WriteHeader(http.StatusOK)
	}))
	// Sin token → 401.
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("sin token: %d", rr.Code)
	}
	// Token válido (cookie o Bearer).
	at, _, _, err := iss.Issue(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(*http.Request){
		"bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+at) },
		"cookie": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "access_token", Value: at}) },
	} {
		req := httptest.NewRequest("GET", "/", nil)
		setup(req)
		rr := httptest.NewRecorder()
		next.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d", name, rr.Code)
		}
	}
}

func TestRequireFreshAuth(t *testing.T) {
	h := RequireFreshAuth(5 * time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Fresco pasa.
	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), authUserKey, "u1")
	ctx = context.WithValue(ctx, authTimeKey, time.Now().UTC().Add(-time.Minute))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req.WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("fresco: %d", rr.Code)
	}
	// Stale 30min → 401 + meta.
	ctx2 := context.WithValue(req.Context(), authUserKey, "u1")
	ctx2 = context.WithValue(ctx2, authTimeKey, time.Now().UTC().Add(-30*time.Minute))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req.WithContext(ctx2))
	if rr2.Code != http.StatusUnauthorized || !contains(rr2.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("stale: %d %s", rr2.Code, rr2.Body.String())
	}
}

func TestProviderAllowlist(t *testing.T) {
	h := ProviderAllowlist([]string{"google"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/auth/federated/facebook/authorize", nil)
	req.SetPathValue("provider", "facebook")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound || !contains(rr.Body.String(), "PROVIDER_NOT_SUPPORTED") {
		t.Fatalf("facebook: %d %s", rr.Code, rr.Body.String())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
