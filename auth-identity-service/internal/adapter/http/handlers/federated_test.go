package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
)

type fedTestIdP struct {
	url      string
	state    string
	nonce    string
	verifier string
	claims   auth.OIDClaims
	xErr     error
	vErr     error
}

func (f *fedTestIdP) BuildAuthorizeURL(_ context.Context, _ auth.AuthorizeReq) (auth.AuthURL, string, error) {
	return auth.AuthURL{URL: f.url, State: f.state, Nonce: f.nonce}, f.verifier, nil
}
func (f *fedTestIdP) ExchangeCode(_ context.Context, _ user.Provider, _, _, _ string) (auth.TokenSet, error) {
	if f.xErr != nil {
		return auth.TokenSet{}, f.xErr
	}
	return auth.TokenSet{IDToken: "idtok"}, nil
}
func (f *fedTestIdP) VerifyIDToken(_ context.Context, _ user.Provider, _, _ string) (auth.OIDClaims, error) {
	if f.vErr != nil {
		return auth.OIDClaims{}, f.vErr
	}
	return f.claims, nil
}

type fedTestRepo struct {
	ident *user.FederatedIdentity
	u     *user.User
	byEm  *user.User
}

func (f *fedTestRepo) FindByProviderSub(_ context.Context, _ user.Provider, _ string) (*user.FederatedIdentity, *user.User, error) {
	if f.ident == nil {
		return nil, nil, user.ErrNotFound
	}
	return f.ident, f.u, nil
}
func (f *fedTestRepo) FindUserByEmailNormalized(_ context.Context, _ string) (*user.User, error) {
	if f.byEm == nil {
		return nil, user.ErrNotFound
	}
	return f.byEm, nil
}
func (f *fedTestRepo) CreateUserWithFederation(_ context.Context, _ *user.User, _ *user.FederatedIdentity, _ []user.OutboxPayload, _ user.MailPayload, _ user.RegistrationContext) error {
	return nil
}

type fedTestState struct{ st auth.FederatedState }

func (f *fedTestState) SaveState(_ context.Context, _ string, st auth.FederatedState) error {
	f.st = st
	return nil
}
func (f *fedTestState) ConsumeState(_ context.Context, _ string) (auth.FederatedState, error) {
	return f.st, nil
}

type fedTestSessions struct{ withSession bool }

func (f fedTestSessions) Issue(_ context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	if !f.withSession {
		return auth.IssuedPair{}, nil
	}
	return auth.IssuedPair{
		AccessJWT: "at", RefreshPlain: "rt-43ch-test-vector-0000000000000000000",
		SID: "sid-test", JTI: "jti", Family: "fam", KID: "2026-10-a",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

func fedSvcHTTP(claims auth.OIDClaims) *service.RegisterFederatedService {
	idp := &fedTestIdP{
		url: "https://idp.example/auth", state: "st", nonce: "nn", verifier: "vv",
		claims: claims,
	}
	return service.NewRegisterFederatedService(idp, &fedTestRepo{}, &fedTestState{},
		nil, nil, fedTestSessions{withSession: true}, nil, nil,
		&hIdem{m: map[string]string{}}, hAudit{}, hMetrics{}, service.NoopTracer{}, "v2026.10", false)
}

func TestFederatedAuthorize302(t *testing.T) {
	svc := fedSvcHTTP(auth.OIDClaims{})
	req := httptest.NewRequest("GET", "/api/v1/auth/federated/google/authorize?return_to=/app", nil)
	req.SetPathValue("provider", "google")
	rr := httptest.NewRecorder()
	FederatedAuthorizeHandler(svc, false).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "https://idp.example/auth") {
		t.Fatalf("location=%q", loc)
	}
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "fed_state" && c.HttpOnly && c.SameSite == http.SameSiteLaxMode {
			found = true
		}
	}
	if !found {
		t.Fatal("cookie fed_state HttpOnly/Lax ausente")
	}
}

func TestFederatedCallbackActive(t *testing.T) {
	svc := fedSvcHTTP(auth.OIDClaims{Sub: "s1", Email: "n@e.co", EmailVerified: &[]bool{true}[0], Nonce: "nn"})
	req := httptest.NewRequest("GET", "/api/v1/auth/federated/google/callback?code=c&state=st", nil)
	req.SetPathValue("provider", "google")
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	FederatedCallbackHandler(svc, nil, false).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"active"`) {
		t.Fatalf("body=%s", rr.Body.String())
	}
	setCookies := rr.Result().Cookies()
	names := map[string]bool{}
	for _, c := range setCookies {
		names[c.Name] = true
		if c.Name == "refresh_token" && !c.HttpOnly {
			t.Fatalf("cookie %s debe ser HttpOnly", c.Name)
		}
		if c.Name == "access_token" {
			t.Fatal("Access NUNCA en cookie")
		}
	}
	if !names["refresh_token"] {
		t.Fatal("falta refresh_token")
	}
	if !strings.Contains(rr.Body.String(), "access_token") {
		t.Fatalf("body debe traer access_token: %s", rr.Body.String())
	}
}

func TestFederatedCallbackCollision409(t *testing.T) {
	idp := &fedTestIdP{claims: auth.OIDClaims{Sub: "otro", Email: "e@x.co", EmailVerified: &[]bool{true}[0], Nonce: "nn"}}
	repo := &fedTestRepo{byEm: &user.User{ID: uuid.NewString(), EmailNormalized: "e@x.co", Status: user.StatusActive}}
	svc := service.NewRegisterFederatedService(idp, repo, &fedTestState{},
		nil, nil, fedTestSessions{}, nil, nil,
		&hIdem{m: map[string]string{}}, hAudit{}, hMetrics{}, service.NoopTracer{}, "v2026.10", false)
	req := httptest.NewRequest("GET", "/api/v1/auth/federated/google/callback?code=c&state=st", nil)
	req.SetPathValue("provider", "google")
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	FederatedCallbackHandler(svc, nil, false).ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "ACCOUNT_LINK_REQUIRED") {
		t.Fatalf("body=%s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "google123") || strings.Contains(rr.Body.String(), "e@x.co") {
		t.Fatal("el 409 no debe filtrar sub/email previo")
	}
}
