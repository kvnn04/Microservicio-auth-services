package handlers

import (
	"context"
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

type regenSecretStore struct{ active map[string]bool }

func (s *regenSecretStore) Stage(_ context.Context, _ string, _ []byte) error {
	return nil
}
func (s *regenSecretStore) Staged(_ context.Context, _ string) ([]byte, bool, error) {
	return nil, false, auth.ErrNoStaged
}
func (s *regenSecretStore) PromoteTx(_ context.Context, _ string) error { return nil }
func (s *regenSecretStore) GetActive(_ context.Context, uid string) ([]byte, error) {
	if s.active[uid] {
		return []byte("enc"), nil
	}
	return nil, user.ErrNotFound
}
func (s *regenSecretStore) DisableTx(_ context.Context, _ string) error { return nil }

type regenIssuer struct{ n int }

func (f *regenIssuer) Generate(_ context.Context) (string, string, error) {
	f.n++
	a := string(rune('A' + f.n%26))
	b := string(rune('A' + (f.n/26)%26))
	plain := "ABCD-EFGH" + a + b // canónico 10ch
	return plain, "h:" + plain, nil
}
func (*regenIssuer) Hash(c string) string              { return "h:" + c }
func (*regenIssuer) HashPrev(c string) (string, bool)  { return "p:" + c, false }
func (*regenIssuer) Verify(_ context.Context, _, _ string) bool { return true }

type regenStore struct{ remaining int }

func (s *regenStore) GenerateTx(_ context.Context, _ string, _ []string, _ bool) (int, error) {
	return 0, nil
}
func (s *regenStore) ConsumeTx(_ context.Context, _, _, _ string) (int, error) {
	return 0, auth.ErrBackupNotFound
}
func (s *regenStore) CountRemaining(_ context.Context, _ string) (int, error) {
	return s.remaining, nil
}
func (s *regenStore) BurnAll(_ context.Context, _ string) error { return nil }

func regenSvc(users map[string]*user.User, remaining int) (*service.MFAService, *security.SessionIssuer, *regenSecretStore) {
	iss := security.NewSessionIssuer([]byte("test-session-secret-32bytes!!"), nil)
	store := &regenSecretStore{active: map[string]bool{}}
	svc := service.NewMFAService(nil, nil,
		store, nil, nil, &regenIssuer{}, &regenStore{remaining: remaining},
		&mfaHTTPUsers{users: users}, nil, mfaHTTPSessions{},
		nil, &stubIdem{m: map[string]string{}}, stubAudit{},
		service.NoopMFAMetrics{}, service.NoopTracer{}, "Example")
	svc.Sleep = func(time.Duration) {}
	return svc, iss, store
}

func regenAuthed(t *testing.T, iss *security.SessionIssuer, uid string, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	at, _, _, err := iss.Issue(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/mfa/backup-codes/regenerate", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	chain := middleware.Recover(middleware.RequestID(
		middleware.RequireAuth(iss)(middleware.RequireFreshAuth(5 * time.Minute)(h))))
	chain.ServeHTTP(rr, req)
	return rr
}

func TestRegenStale401(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"u@example.com": activeMFAUser(uid, "u@example.com")}
	svc, iss, _ := regenSvc(users, 10)
	// Bearer inválido → 401 sin quemar nada.
	req := httptest.NewRequest("POST", "/mfa/backup-codes/regenerate", nil)
	req.Header.Set("Authorization", "Bearer invalido")
	rr := httptest.NewRecorder()
	middleware.RequireAuth(iss)(MFARegenerateHandler(svc, nil)).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rr.Code)
	}
	_ = iss
}

func TestRegenOKYStatus(t *testing.T) {
	uid := uuid.NewString()
	users := map[string]*user.User{"u@example.com": activeMFAUser(uid, "u@example.com")}
	svc, iss, store := regenSvc(users, 7)
	store.active[uid] = true
	// Activa secreto para pasar GetActive.
	rr := regenAuthed(t, iss, uid, MFARegenerateHandler(svc, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("regen: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "backup_codes") {
		t.Fatalf("sin códigos: %s", rr.Body.String())
	}
	// Status con remaining/warning.
	sreq := httptest.NewRequest("GET", "/mfa/status", nil)
	at, _, _, _ := iss.Issue(context.Background(), uid)
	sreq.Header.Set("Authorization", "Bearer "+at)
	srr := httptest.NewRecorder()
	middleware.RequireAuth(iss)(MFAStatusHandler(svc)).ServeHTTP(srr, sreq)
	if srr.Code != http.StatusOK || !strings.Contains(srr.Body.String(), "backup_remaining") {
		t.Fatalf("status: %d %s", srr.Code, srr.Body.String())
	}
}
