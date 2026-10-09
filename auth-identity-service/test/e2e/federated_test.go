//go:build e2e

package e2e

// E2E CU-REG-04 con fake-IdP (JWKS propia RSA) + Postgres/Redis reales.
// Requiere infra local (docker compose up). Escenarios spec §7.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	adapterhttp "auth-identity-service/internal/adapter/http"
	"auth-identity-service/internal/adapter/http/handlers"
	"auth-identity-service/internal/adapter/http/middleware"
	"auth-identity-service/internal/adapter/identity"
	"auth-identity-service/internal/adapter/persistencia/postgres"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/adapter/security"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type fakeGrant struct {
	Sub      string
	Email    string
	Verified bool
	Nonce    string
}

type fakeIdPServer struct {
	t         *testing.T
	priv      *rsa.PrivateKey
	kid       string
	issuer    string
	clientID  string
	mu        sync.Mutex
	grants    map[string]fakeGrant // code -> grant
	failMode  string               // "", "500", "bad-sig", "unknown-kid"
	srv       *httptest.Server
}

func newFakeIdP(t *testing.T, clientID string) *fakeIdPServer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdPServer{priv: priv, kid: "e2e-kid", clientID: clientID, grants: map[string]fakeGrant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": f.issuer + "/auth",
			"token_endpoint":         f.issuer + "/token",
			"jwks_uri":               f.issuer + "/certs",
		})
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(f.priv.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.priv.PublicKey.E)).Bytes())
		kid := f.kid
		if f.failMode == "unknown-kid" {
			kid = "rotated-kid"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []any{map[string]string{"kty": "RSA", "kid": kid, "n": n, "e": e}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if f.failMode == "500" {
			w.WriteHeader(500)
			return
		}
		_ = r.ParseForm()
		code := r.Form.Get("code")
		f.mu.Lock()
		g, ok := f.grants[code]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		idtok := f.mint(g, f.failMode == "bad-sig")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idtok, "access_token": "fake-access"})
	})
	f.srv = httptest.NewServer(mux)
	f.issuer = f.srv.URL
	return f
}

func (f *fakeIdPServer) mint(g fakeGrant, badSig bool) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"` + f.kid + `"}`))
	vb := false
	if g.Verified {
		vb = true
	}
	now := time.Now().Unix()
	payload, _ := json.Marshal(map[string]any{
		"sub": g.Sub, "email": g.Email, "email_verified": vb,
		"nonce": g.Nonce, "iss": f.issuer, "aud": f.clientID,
		"exp": now + 3600, "iat": now,
	})
	seg := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(seg))
	key := f.priv
	if badSig {
		// Firma sobre digest alterado (inválida).
		bad := sha256.Sum256([]byte(seg + "x"))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, f.priv, crypto.SHA256, bad[:])
		_ = key
		return seg + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.priv, crypto.SHA256, digest[:])
	return seg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func e2eStack(t *testing.T, fake *fakeIdPServer) (http.Handler, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://auth:auth@localhost:5432/auth_db?sslmode=disable"
	}
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("sin postgres: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	// Limpieza E2E.
	_, _ = pool.Exec(ctx, "DELETE FROM outbox")
	_, _ = pool.Exec(ctx, "DELETE FROM email_queue")
	_, _ = pool.Exec(ctx, "DELETE FROM verification_tokens")
	_, _ = pool.Exec(ctx, "DELETE FROM federated_identities")
	_, _ = pool.Exec(ctx, "DELETE FROM users")
	_ = rdb.FlushAll(ctx)

	client := identity.NewGoogleOIDCClient(fake.issuer, fake.clientID, "e2e-secret",
		"http://localhost:8080/api/v1/auth/federated/google/callback", "", "", "")
	repo := postgres.NewUserRepository(pool, "http://localhost:3000")
	fedRepo := postgres.NewFederatedRepository(pool)
	cache := redisadapter.NewVerificationCache(rdb)
	vstore := postgres.NewCombinedVerificationStore(pool, cache, "http://localhost:3000", nil)
	states := redisadapter.NewRedisFederatedStateStore(rdb)
	tokens := security.NewTokenIssuer()
	sessions := &e2eIssueSessions{}
	idem := redisadapter.NewIdempotencyStore(rdb)
	svc := service.NewRegisterFederatedService(client, fedRepo, states, vstore, tokens,
		sessions, repo, nil, idem, nil,
		adapterhttp.NewPrometheusFederatedMetrics(), adapterhttp.NewOtelTracer(), "v2026.10", false)

	mux := http.NewServeMux()
	allow := middleware.ProviderAllowlist([]string{"google"})
	chain := func(h http.Handler) http.Handler {
		return middleware.Recover(middleware.RequestID(allow(h)))
	}
	limiter := redisadapter.NewRateLimiter(rdb, false)
	rl := middleware.RateLimitKey(limiter, func(r *http.Request) string { return "e2e" }, 1000, time.Minute)
	mux.Handle("GET /api/v1/auth/federated/{provider}/authorize",
		chain(rl(handlers.FederatedAuthorizeHandler(svc, false))))
	mux.Handle("GET /api/v1/auth/federated/{provider}/callback",
		chain(rl(handlers.FederatedCallbackHandler(svc, nil, false))))
	return mux, pool
}

func doAuthorize(t *testing.T, api http.Handler, terms string) (state, cookie string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/auth/federated/google/authorize?return_to=/app&terms_accepted="+terms, nil)
	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize code=%d body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	u, _ := url.Parse(loc)
	state = u.Query().Get("state")
	if u.Query().Get("code_challenge") == "" || u.Query().Get("nonce") == "" {
		t.Fatal("faltan PKCE/nonce en Location")
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "fed_state" {
			cookie = c.Value
		}
	}
	if state == "" || cookie == "" || state != cookie {
		t.Fatalf("state/cookie mismatch: %q %q", state, cookie)
	}
	return state, cookie
}

func readNonce(t *testing.T, state string) string {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	v, err := rdb.Get(context.Background(), "fed:state:"+state).Result()
	if err != nil {
		t.Fatalf("state no persistido: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(v), &m)
	return m["nonce"].(string)
}

func doCallback(t *testing.T, api http.Handler, code, state string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET",
		"/api/v1/auth/federated/google/callback?code="+code+"&state="+state, nil)
	req.Header.Set("X-Request-ID", uuid.NewString())
	req.AddCookie(&http.Cookie{Name: "fed_state", Value: state})
	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

func TestFederatedE2E(t *testing.T) {
	fake := newFakeIdP(t, "e2e-client")
	defer fake.srv.Close()
	api, pool := e2eStack(t, fake)
	ctx := context.Background()

	// Escenario 1: verified nuevo → active + cookies + filas.
	st1, _ := doAuthorize(t, api, "true")
	fake.mu.Lock()
	fake.grants["code-1"] = fakeGrant{Sub: "google-1", Email: "Nuevo@Example.com ", Verified: true, Nonce: readNonce(t, st1)}
	fake.mu.Unlock()
	code, body := doCallback(t, api, "code-1", st1)
	if code != 200 || !strings.Contains(body, `"status":"active"`) {
		t.Fatalf("esc1: %d %s", code, body)
	}
	var status, algo string
	if err := pool.QueryRow(ctx, "SELECT status, password_algo FROM users WHERE email_normalized='nuevo@example.com'").Scan(&status, &algo); err != nil || status != "ACTIVE" || algo != "federated" {
		t.Fatalf("fila: %v %s %s", err, status, algo)
	}
	var linkN int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM federated_identities WHERE provider='google' AND sub='google-1'").Scan(&linkN)
	if linkN != 1 {
		t.Fatal("falta link federado")
	}

	// Replay mismo state → 400 (un solo uso).
	code, body = doCallback(t, api, "code-1", st1)
	if code != 400 || !strings.Contains(body, "INVALID_FEDERATED_STATE") {
		t.Fatalf("replay: %d %s", code, body)
	}

	// Escenario 2: no-verified → pending + OTP encolado, sin sesión.
	st2, _ := doAuthorize(t, api, "true")
	fake.mu.Lock()
	fake.grants["code-2"] = fakeGrant{Sub: "google-2", Email: "pend@test.co", Verified: false, Nonce: readNonce(t, st2)}
	fake.mu.Unlock()
	code, body = doCallback(t, api, "code-2", st2)
	if code != 200 || !strings.Contains(body, "pending_verification") {
		t.Fatalf("esc2: %d %s", code, body)
	}
	var tokN, mailN int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM verification_tokens").Scan(&tokN)
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM email_queue").Scan(&mailN)
	if tokN < 1 || mailN < 1 {
		t.Fatalf("falta OTP/email: tok=%d mail=%d", tokN, mailN)
	}

	// Escenario 3: colisión con cuenta clásica → 409 sin fusión.
	_, _ = pool.Exec(ctx, `INSERT INTO users (id, email_normalized, email_original, password_hash, password_algo, status, terms_version, privacy_version, terms_accepted_at)
		VALUES (gen_random_uuid(), 'dueno@example.com', 'dueno@example.com', '$argon2id$v=19$m=1,t=1,p=1$cw$dg', 'argon2id', 'ACTIVE', 'v2026.10', 'v2026.10', now())`)
	st3, _ := doAuthorize(t, api, "true")
	fake.mu.Lock()
	fake.grants["code-3"] = fakeGrant{Sub: "otro-sub", Email: "dueno@example.com", Verified: true, Nonce: readNonce(t, st3)}
	fake.mu.Unlock()
	code, body = doCallback(t, api, "code-3", st3)
	if code != 409 || !strings.Contains(body, "ACCOUNT_LINK_REQUIRED") {
		t.Fatalf("colisión: %d %s", code, body)
	}
	var usersN int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE email_normalized='dueno@example.com'").Scan(&usersN)
	if usersN != 1 {
		t.Fatal("colisión no debe crear filas")
	}
	var collN int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE topic='auth.security.federated_collision.v1'").Scan(&collN)
	if collN < 1 {
		t.Fatal("falta evento colisión")
	}

	// Escenario 4: cancel + IdP caído + firma mala.
	req := httptest.NewRequest("GET", "/api/v1/auth/federated/google/callback?error=access_denied&state=x", nil)
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	api.ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("cancel: %d", rr.Code)
	}
	fake.failMode = "500"
	st4, _ := doAuthorize(t, api, "true")
	fake.mu.Lock()
	fake.grants["code-4"] = fakeGrant{Sub: "g4", Email: "x4@y.co", Verified: true, Nonce: readNonce(t, st4)}
	fake.mu.Unlock()
	code, _ = doCallback(t, api, "code-4", st4)
	if code != 502 {
		t.Fatalf("idp 500: %d", code)
	}
	fake.failMode = "bad-sig"
	st5, _ := doAuthorize(t, api, "true")
	fake.mu.Lock()
	fake.grants["code-5"] = fakeGrant{Sub: "g5", Email: "x5@y.co", Verified: true, Nonce: readNonce(t, st5)}
	fake.mu.Unlock()
	code, body = doCallback(t, api, "code-5", st5)
	if code != 401 {
		t.Fatalf("bad-sig: %d %s", code, body)
	}
	fake.failMode = ""
	fmt.Println("E2E FEDERATED PASSED")
}
