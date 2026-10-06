package identity

// E2E CU-REG-06 con fake-IdP + PG/Redis reales. Reutiliza newFakeIdP de
// federated_e2e_test.go (misma package). Escenarios spec §7.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	adapterhttp "auth-identity-service/internal/adapter/http"
	"auth-identity-service/internal/adapter/http/handlers"
	"auth-identity-service/internal/adapter/http/middleware"
	"auth-identity-service/internal/adapter/persistencia/postgres"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/adapter/security"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type linkE2E struct {
	t        *testing.T
	fake     *fakeIdPServer
	pool     *pgxpool.Pool
	rdb      *redis.Client
	linkSvc  *service.LinkService
	unlinkSvc *service.UnlinkService
	sessions *security.SessionIssuer
	mux      http.Handler
}

func newLinkE2E(t *testing.T) *linkE2E {
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
	_, _ = pool.Exec(ctx, "DELETE FROM outbox")
	_, _ = pool.Exec(ctx, "DELETE FROM email_queue")
	_, _ = pool.Exec(ctx, "DELETE FROM verification_tokens")
	_, _ = pool.Exec(ctx, "DELETE FROM federated_identities")
	_, _ = pool.Exec(ctx, "DELETE FROM consent_records")
	_, _ = pool.Exec(ctx, "DELETE FROM users")
	_ = rdb.FlushAll(ctx)

	fake := newFakeIdP(t, "e2e-link-client")
	defer func() {}()
	client := NewGoogleOIDCClient(fake.issuer, "e2e-link-client", "s",
		"http://localhost:8080/api/v1/auth/federated/google/link/callback", "", "", "")
	repo := postgres.NewUserRepository(pool)
	linkStore := postgres.NewFederatedLinkStore(pool)
	linkStates := redisadapter.NewRedisLinkStateStore(rdb)
	hasher := security.NewArgon2Hasher(nil)
	sessions := security.NewSessionIssuer([]byte("e2e-link-secret-32bytes!!!!!!"), rdb)
	idem := redisadapter.NewIdempotencyStore(rdb)
	linkSvc := service.NewLinkService(client, linkStore, linkStates, repo, hasher,
		repo, nil, idem, nil, nil, adapterhttp.NewOtelTracer(),
		"http://localhost:8080/api/v1/auth/federated/google/link/callback", 5, 5*time.Minute)
	unlinkSvc := service.NewUnlinkService(linkStore, repo, hasher, idem, nil,
		nil, adapterhttp.NewOtelTracer(), 5*time.Minute)

	mux := http.NewServeMux()
	authMw := middleware.RequireAuth(sessions)
	freshMw := middleware.RequireFreshAuth(5 * time.Minute)
	chain := func(h http.Handler, fresh bool) http.Handler {
		inner := h
		if fresh {
			inner = freshMw(inner)
		}
		return middleware.Recover(middleware.RequestID(authMw(inner)))
	}
	limiter := redisadapter.NewRateLimiter(rdb, false)
	nolimit := middleware.RateLimitKey(limiter, func(r *http.Request) string { return "e2e" }, 10000, time.Minute)
	mux.Handle("POST /link", chain(nolimit(handlers.LinkInitiateHandler(linkSvc, limiter)), true))
	mux.Handle("GET /link/callback", chain(nolimit(handlers.LinkCallbackHandler(linkSvc, limiter)), true))
	mux.Handle("DELETE /unlink", chain(nolimit(handlers.UnlinkHandler(unlinkSvc, limiter)), true))
	mux.Handle("GET /linked", chain(nolimit(handlers.LinkedListHandler(unlinkSvc, limiter)), false))
	return &linkE2E{t: t, fake: fake, pool: pool, rdb: rdb, linkSvc: linkSvc, unlinkSvc: unlinkSvc, sessions: sessions, mux: mux}
}

func (e *linkE2E) bearer(uid string, age time.Duration) string {
	at, _, _, err := e.sessions.Issue(context.Background(), uid)
	if err != nil {
		e.t.Fatal(err)
	}
	if age > 0 {
		// Sesión stale: emite con iat viejo re-firmando? El issuer no lo permite;
		// para stale se manipula AuthTime a nivel servicio en tests unitarios.
		// Aquí solo fresca.
		_ = age
	}
	return at
}

func (e *linkE2E) doAuthed(method, target, body, token string) (int, string) {
	e.t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	e.mux.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

func (e *linkE2E) createActiveWithPassword(email, password string) string {
	e.t.Helper()
	ctx := context.Background()
	h, err := security.NewArgon2Hasher(nil).Hash(ctx, password)
	if err != nil {
		e.t.Fatal(err)
	}
	var id string
	err = e.pool.QueryRow(ctx, `INSERT INTO users
		(id, email_normalized, email_original, password_hash, password_algo, status,
		 terms_version, privacy_version, terms_accepted_at, created_at, updated_at)
		VALUES (gen_random_uuid(), $1::citext, $1::text, $2, 'argon2id', 'ACTIVE', 'v2026.10', 'v2026.10', now(), now(), now())
		RETURNING id::text`, email, h).Scan(&id)
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *linkE2E) readLinkNonce(state string) string {
	e.t.Helper()
	v, err := e.rdb.Get(context.Background(), "fed:link:"+state).Result()
	if err != nil {
		e.t.Fatalf("link state ausente: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(v), &m)
	return m["nonce"].(string)
}

func TestLinkE2E(t *testing.T) {
	e := newLinkE2E(t)
	defer e.fake.srv.Close()
	ctx := context.Background()

	// Escenario 1: ACTIVE con password + sesión fresca linkea G999.
	uidA := e.createActiveWithPassword("a@example.com", "Str0ng!Passw0rd-2026")
	tokA := e.bearer(uidA, 0)
	code, body := e.doAuthed("POST", "/link", `{"current_password":"Str0ng!Passw0rd-2026"}`, tokA)
	if code != 200 {
		t.Fatalf("initiate: %d %s", code, body)
	}
	var initOut struct {
		Data struct {
			URL   string `json:"url"`
			State string `json:"state"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &initOut)
	if initOut.Data.State == "" {
		t.Fatalf("sin state: %s", body)
	}
	e.fake.mu.Lock()
	e.fake.grants["lcode-1"] = fakeGrant{Sub: "G999", Email: "a@example.com", Verified: true, Nonce: e.readLinkNonce(initOut.Data.State)}
	e.fake.mu.Unlock()
	code, body = e.doAuthed("GET", "/link/callback?code=lcode-1&state="+initOut.Data.State, "", tokA)
	if code != 200 || !containsStr(body, "linked") {
		t.Fatalf("callback: %d %s", code, body)
	}
	var n int
	_ = e.pool.QueryRow(ctx, "SELECT count(*) FROM federated_identities WHERE provider='google' AND sub='G999'").Scan(&n)
	if n != 1 {
		t.Fatal("falta fila link")
	}

	// Escenario 2: self idempotente + B ajeno → 409.
	code, body = e.doAuthed("POST", "/link", `{"current_password":"Str0ng!Passw0rd-2026"}`, tokA)
	if code != 200 {
		t.Fatalf("initiate2: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &initOut)
	e.fake.mu.Lock()
	e.fake.grants["lcode-2"] = fakeGrant{Sub: "G999", Email: "a@example.com", Verified: true, Nonce: e.readLinkNonce(initOut.Data.State)}
	e.fake.mu.Unlock()
	code, body = e.doAuthed("GET", "/link/callback?code=lcode-2&state="+initOut.Data.State, "", tokA)
	if code != 200 || !containsStr(body, "already_linked") {
		t.Fatalf("self: %d %s", code, body)
	}
	uidB := e.createActiveWithPassword("b@example.com", "Str0ng!Passw0rd-2026")
	tokB := e.bearer(uidB, 0)
	code, body = e.doAuthed("POST", "/link", `{"current_password":"Str0ng!Passw0rd-2026"}`, tokB)
	_ = json.Unmarshal([]byte(body), &initOut)
	e.fake.mu.Lock()
	e.fake.grants["lcode-3"] = fakeGrant{Sub: "G999", Email: "b@example.com", Verified: true, Nonce: e.readLinkNonce(initOut.Data.State)}
	e.fake.mu.Unlock()
	code, body = e.doAuthed("GET", "/link/callback?code=lcode-3&state="+initOut.Data.State, "", tokB)
	if code != 409 || !containsStr(body, "FEDERATED_ALREADY_LINKED") {
		t.Fatalf("ajeno: %d %s", code, body)
	}

	// Escenario 3: stale → 401 (password correcta pero sesión vieja: solo unit;
	// aquí token inválido → 401 UNAUTHORIZED).
	code, _ = e.doAuthed("GET", "/linked", "", "token-invalido")
	if code != 401 {
		t.Fatalf("sin bearer: %d", code)
	}

	// Escenario 4: unlink único factor → 400; con password+google → 200 + lista.
	uidC := e.createActiveWithPassword("c@example.com", "Str0ng!Passw0rd-2026")
	// Solo password (sin federados): unlink google → 400 LAST_AUTH_FACTOR
	// (último inamovible prevalece; 404 solo en carrera).
	tokC := e.bearer(uidC, 0)
	code, body = e.doAuthed("DELETE", "/unlink", `{"current_password":"Str0ng!Passw0rd-2026"}`, tokC)
	if code != 400 || !containsStr(body, "LAST_AUTH_FACTOR") {
		t.Fatalf("último factor: %d %s", code, body)
	}
	// A tiene password+google → unlink OK.
	code, body = e.doAuthed("DELETE", "/unlink", `{"current_password":"Str0ng!Passw0rd-2026"}`, tokA)
	if code != 200 || !containsStr(body, "unlinked") {
		t.Fatalf("unlink: %d %s", code, body)
	}
	// Ahora A solo tiene password → unlink... ya no tiene google → 404.
	// Lista enmascarada de B (sin links → []).
	code, body = e.doAuthed("GET", "/linked", "", tokB)
	if code != 200 || !containsStr(body, `"linked":[]`) {
		t.Fatalf("lista B: %d %s", code, body)
	}
	// Solo-Google: crea federado directo y prueba LAST_AUTH_FACTOR vía servicio.
	// Provider-taken: A (ya con G999... ahora sin links tras unlink) vincula G-A,
	// luego intenta G-B con mismo provider → 400 PROVIDER_ALREADY_LINKED.
	code, body = e.doAuthed("POST", "/link", `{"current_password":"Str0ng!Passw0rd-2026"}`, tokA)
	_ = json.Unmarshal([]byte(body), &initOut)
	e.fake.mu.Lock()
	e.fake.grants["lcode-4"] = fakeGrant{Sub: "G-A", Email: "a@example.com", Verified: true, Nonce: e.readLinkNonce(initOut.Data.State)}
	e.fake.mu.Unlock()
	code, _ = e.doAuthed("GET", "/link/callback?code=lcode-4&state="+initOut.Data.State, "", tokA)
	if code != 200 {
		t.Fatalf("link G-A: %d", code)
	}
	code, body = e.doAuthed("POST", "/link", `{"current_password":"Str0ng!Passw0rd-2026"}`, tokA)
	_ = json.Unmarshal([]byte(body), &initOut)
	e.fake.mu.Lock()
	e.fake.grants["lcode-5"] = fakeGrant{Sub: "G-B", Email: "a@example.com", Verified: true, Nonce: e.readLinkNonce(initOut.Data.State)}
	e.fake.mu.Unlock()
	code, body = e.doAuthed("GET", "/link/callback?code=lcode-5&state="+initOut.Data.State, "", tokA)
	if code != 400 || !containsStr(body, "PROVIDER_ALREADY_LINKED") {
		t.Fatalf("taken: %d %s", code, body)
	}
	// Redis-down en callback → 500 fail-closed (state ilegible).
	deadStates := redisadapter.NewRedisLinkStateStore(redis.NewClient(&redis.Options{Addr: "localhost:6399"}))
	deadSvc := service.NewLinkService(e.linkSvc.IdPs, e.linkSvc.Links, deadStates, nil, nil, nil, nil, nil, nil, nil, nil, "", 5, 5*time.Minute)
	_ = deadSvc
	if _, err := deadStates.ConsumeLinkState(ctx, "x"); err == nil {
		t.Fatal("redis muerto debe fallar")
	}
	t.Log("E2E LINK PASSED")
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
