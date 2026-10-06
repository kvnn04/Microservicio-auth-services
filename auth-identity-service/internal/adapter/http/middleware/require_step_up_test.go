package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
)

// fakeStepUpChecker guioniza el guard sin Redis/DB.
type fakeStepUpChecker struct {
	mode string
	err  error
}

func (f *fakeStepUpChecker) Check(_ context.Context, _ string, _ time.Time, _ auth.StepUpScope, _ string) (string, error) {
	return f.mode, f.err
}

func stepUpAuthedReq(scope, token string, age time.Duration) *http.Request {
	req := httptest.NewRequest("POST", "/op", nil)
	ctx := context.WithValue(req.Context(), authUserKey, "user-1")
	ctx = context.WithValue(ctx, authTimeKey, time.Now().UTC().Add(-age))
	if token != "" {
		req.Header.Set("X-Step-Up-Token", token)
	}
	return req.WithContext(ctx)
}

func TestRequireStepUp_FastPassSinToken(t *testing.T) {
	next := RequireStepUp(auth.ScopeFederatedUnlink,
		&fakeStepUpChecker{mode: "fast_pass"}, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, stepUpAuthedReq("federated:unlink", "", time.Minute))
	if rr.Code != http.StatusOK {
		t.Fatalf("fresco sin token 200: %d", rr.Code)
	}
}

func TestRequireStepUp_StaleSinToken401ConMeta(t *testing.T) {
	next := RequireStepUp(auth.ScopeAccountDelete,
		&fakeStepUpChecker{err: auth.ErrStepUpRequired}, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, stepUpAuthedReq("account:delete", "", time.Hour))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("401: %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"STEP_UP_REQUIRED", "account:delete", "300", "step-up/challenge"} {
		if !strings.Contains(body, want) {
			t.Fatalf("meta %q en %s", want, body)
		}
	}
}

func TestRequireStepUp_TokenOKReusedUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
		want string
	}{
		{"reused", auth.ErrStepUpReused, 401, "STEP_UP_REUSED"},
		{"invalid", auth.ErrStepUpInvalid, 401, "INVALID_STEP_UP"},
		{"unavailable", auth.ErrStepUpUnavailable, 500, "STEP_UP_UNAVAILABLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checker := &fakeStepUpChecker{}
			if tc.err == nil {
				checker.mode = "token"
			} else {
				checker.err = tc.err
			}
			next := RequireStepUp(auth.ScopeMFADisable, checker, false)(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			rr := httptest.NewRecorder()
			next.ServeHTTP(rr, stepUpAuthedReq("mfa:disable", "tok", time.Hour))
			if rr.Code != tc.code || !strings.Contains(rr.Body.String(), tc.want) {
				t.Fatalf("%d %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestRequireStepUp_SinAuthYEnforce(t *testing.T) {
	next := RequireStepUp(auth.ScopeBackupRegen,
		&fakeStepUpChecker{mode: "fast_pass"}, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, httptest.NewRequest("POST", "/op", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("sin auth 401: %d", rr.Code)
	}
	// Enforce: fast-pass ya no basta.
	strict := RequireStepUp(auth.ScopeBackupRegen,
		&fakeStepUpChecker{mode: "fast_pass"}, true)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rr2 := httptest.NewRecorder()
	strict.ServeHTTP(rr2, stepUpAuthedReq("backup:regenerate", "", time.Minute))
	if rr2.Code != http.StatusUnauthorized || !strings.Contains(rr2.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("enforce: %d %s", rr2.Code, rr2.Body.String())
	}
}
