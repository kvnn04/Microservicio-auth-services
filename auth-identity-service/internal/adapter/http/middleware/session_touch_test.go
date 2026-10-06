package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
)

type touchVerifierFake struct {
	claims auth.AccessClaims
	err    error
}

func (f *touchVerifierFake) Verify(string) (auth.AccessClaims, error) {
	if f.err != nil {
		return auth.AccessClaims{}, f.err
	}
	return f.claims, nil
}

type touchStoreFake struct {
	calls [][3]string // user, sid, iso-time marker
}

func (f *touchStoreFake) Touch(_ context.Context, user, sid string, _ time.Time) error {
	f.calls = append(f.calls, [3]string{user, sid})
	return nil
}

func TestSessionTouch_AsyncYNeverBlocks(t *testing.T) {
	now := time.Now().UTC()
	ver := &touchVerifierFake{claims: auth.AccessClaims{
		Sub: "u1", SID: "sid-1", Exp: now.Add(10 * time.Minute).Unix(),
	}}
	store := &touchStoreFake{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer jwt-bueno")
	rr := httptest.NewRecorder()
	SessionTouch(ver, store)(next).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("nunca bloquea: %d", rr.Code)
	}
	// Async: espera acotada al Touch.
	deadline := time.Now().Add(2 * time.Second)
	for len(store.calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(store.calls) != 1 || store.calls[0][0] != "u1" || store.calls[0][1] != "sid-1" {
		t.Fatalf("touch (u1,sid-1): %v", store.calls)
	}
}

func TestSessionTouch_SinBearerNoOp(t *testing.T) {
	ver := &touchVerifierFake{err: errors.New("bad")}
	store := &touchStoreFake{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for _, h := range []http.Header{
		{},
		{"Authorization": {"Bearer malo"}},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
		req.Header = h
		rr := httptest.NewRecorder()
		SessionTouch(ver, store)(next).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("no-op: %d", rr.Code)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if len(store.calls) != 0 {
		t.Fatalf("sin touch: %v", store.calls)
	}
}
