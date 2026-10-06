package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/adapter/persistencia/postgres"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

type stubLegal struct {
	terms, privacy shared.LegalDocument
	err            error
}

func (s *stubLegal) GetActive(_ context.Context) (shared.LegalDocument, shared.LegalDocument, error) {
	if s.err != nil {
		return shared.LegalDocument{}, shared.LegalDocument{}, s.err
	}
	return s.terms, s.privacy, nil
}

func activeStubLegal() *stubLegal {
	return &stubLegal{
		terms:   shared.LegalDocument{DocType: shared.DocTerms, Version: "v2026.10"},
		privacy: shared.LegalDocument{DocType: shared.DocPrivacy, Version: "v2026.10"},
	}
}

func legalRegisterSvc(users map[string]*user.User, legal *stubLegal) *service.RegisterUserService {
	s := newSvc(users)
	s.Legal = legal
	s.Sleep = func(time.Duration) {}
	return s
}

func postRegister(t *testing.T, svc *service.RegisterUserService, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	RegisterHandler(svc).ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

func TestLegalActiveGETFallback(t *testing.T) {
	// Sin pool/cache + fallback env → 200 stale (degradado documentado).
	p := postgres.NewCombinedLegalProvider(nil, nil, "v2026.10", "v2026.10", nil)
	req := httptest.NewRequest("GET", "/api/v1/legal/active", nil)
	rr := httptest.NewRecorder()
	LegalActiveHandler(p).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"stale":true`) {
		t.Fatalf("debe ser stale: %s", rr.Body.String())
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Fatalf("cache %q", cc)
	}
	// Sin fallback → 500.
	p2 := postgres.NewCombinedLegalProvider(nil, nil, "", "", nil)
	rr2 := httptest.NewRecorder()
	LegalActiveHandler(p2).ServeHTTP(rr2, httptest.NewRequest("GET", "/api/v1/legal/active", nil))
	if rr2.Code != http.StatusInternalServerError {
		t.Fatalf("sin fallback debe ser 500, got %d", rr2.Code)
	}
}

func TestRegisterSinTerms400(t *testing.T) {
	svc := legalRegisterSvc(map[string]*user.User{}, activeStubLegal())
	code, body := postRegister(t, svc,
		`{"email":"a@b.co","password":"Str0ng!Passw0rd-2026","terms_accepted":false,"terms_version":"v2026.10","privacy_version":"v2026.10"}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "TERMS_REQUIRED") {
		t.Fatalf("code=%d body=%s", code, body)
	}
}

func TestRegisterVersionVieja400ConMeta(t *testing.T) {
	svc := legalRegisterSvc(map[string]*user.User{}, activeStubLegal())
	code, body := postRegister(t, svc,
		`{"email":"a@b.co","password":"Str0ng!Passw0rd-2026","terms_accepted":true,"terms_version":"v2026.09","privacy_version":"v2026.10"}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "TERMS_OUTDATED") {
		t.Fatalf("code=%d body=%s", code, body)
	}
	if !strings.Contains(body, `"terms":"v2026.10"`) || !strings.Contains(body, `"privacy":"v2026.10"`) {
		t.Fatalf("falta meta.active: %s", body)
	}
}

func TestRegisterVigentePasa(t *testing.T) {
	svc := legalRegisterSvc(map[string]*user.User{}, activeStubLegal())
	code, body := postRegister(t, svc,
		`{"email":"ok-legal@example.com","password":"Str0ng!Passw0rd-2026","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}`)
	if code != http.StatusCreated {
		t.Fatalf("code=%d body=%s", code, body)
	}
}
