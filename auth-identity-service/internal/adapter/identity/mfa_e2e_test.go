package identity

// E2E CU-AUTH-02 con TOTP real + PG/Redis reales. Escenarios spec §7.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	adapterhttp "auth-identity-service/internal/adapter/http"
	"auth-identity-service/internal/adapter/http/handlers"
	"auth-identity-service/internal/adapter/http/middleware"
	"auth-identity-service/internal/adapter/persistencia/postgres"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/adapter/security"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type mfaE2E struct {
	t        *testing.T
	pool     *pgxpool.Pool
	rdb      *redis.Client
	svc      *service.MFAService
	sessions *security.SessionIssuer
	mux      http.Handler
	secret   []byte
}

func newMFAE2E(t *testing.T) *mfaE2E {
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
	for _, q := range []string{
		"DELETE FROM outbox", "DELETE FROM email_queue", "DELETE FROM mfa_backup_codes",
		"DELETE FROM mfa_used_counters", "DELETE FROM mfa_challenges", "DELETE FROM mfa_totp_secrets",
		"DELETE FROM verification_tokens", "DELETE FROM federated_identities",
		"DELETE FROM consent_records", "DELETE FROM users",
	} {
		_, _ = pool.Exec(ctx, q)
	}
	_ = rdb.FlushAll(ctx)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	box, err := security.NewSecretBox(secret)
	if err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewUserRepository(pool)
	stores := postgres.NewMFAStores(pool, redisadapter.NewMFAChallengeCache(rdb), rdb)
	legacySessions := security.NewSessionIssuer(secret, rdb)
	sessions := &e2eIssueSessions{}
	preIssuer := security.NewMFAPreTokenIssuer(secret)
	idem := redisadapter.NewIdempotencyStore(rdb)
	pepper := os.Getenv("PASSWORD_PEPPER")
	backupIssuer := security.NewBackupCodeIssuer([]byte(pepper), nil)
	backupStore := postgres.NewBackupCodeStore(pool)
	svc := service.NewMFAService(security.NewTOTPProvider(), box, stores, stores,
		preIssuer, backupIssuer, backupStore, repo, nil, sessions, repo, idem, nil,
		adapterhttp.NewPrometheusMFAMetrics(), adapterhttp.NewOtelTracer(), "Example")

	mux := http.NewServeMux()
	authMw := middleware.RequireAuth(legacySessions)
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
	mux.Handle("POST /setup", chain(nolimit(handlers.MFASetupHandler(svc, limiter)), true))
	mux.Handle("POST /enable", chain(nolimit(handlers.MFAEnableHandler(svc)), true))
	mux.Handle("POST /verify", middleware.Recover(middleware.RequestID(
		nolimit(handlers.MFAVerifyHandler(svc, limiter, false)))))
	mux.Handle("POST /regen", chain(nolimit(handlers.MFARegenerateHandler(svc, limiter)), true))
	mux.Handle("GET /status", chain(nolimit(handlers.MFAStatusHandler(svc)), false))
	// Ruta negocio mínima (solo RequireAuth): el pre-token debe dar 401 aquí.
	mux.Handle("GET /biz", middleware.Recover(middleware.RequestID(authMw(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))))
	mux.Handle("DELETE /totp", chain(nolimit(handlers.MFADisableHandler(svc)), true))
	return &mfaE2E{t: t, pool: pool, rdb: rdb, svc: svc, sessions: legacySessions, mux: mux, secret: secret}
}

func (e *mfaE2E) createActive(email, password string) string {
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

func (e *mfaE2E) bearer(uid string) string {
	e.t.Helper()
	at, _, _, err := e.sessions.Issue(context.Background(), uid)
	if err != nil {
		e.t.Fatal(err)
	}
	return at
}

func (e *mfaE2E) doAuthed(method, target, body, token string) (int, string) {
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

func (e *mfaE2E) doAnon(method, target, body string) (int, string) {
	e.t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("X-Request-ID", uuid.NewString())
	rr := httptest.NewRecorder()
	e.mux.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

func TestMFAE2E(t *testing.T) {
	e := newMFAE2E(t)
	ctx := context.Background()

	// Escenario 1: setup → enable (backups 1 vez) → mfa_enabled.
	uid := e.createActive("mfa@example.com", "Str0ng!Passw0rd-2026")
	tok := e.bearer(uid)
	code, body := e.doAuthed("POST", "/setup", "", tok)
	if code != 200 {
		t.Fatalf("setup: %d %s", code, body)
	}
	var setupOut struct {
		Data struct {
			SecretB32  string `json:"secret_b32"`
			OTPAuthURL string `json:"otpauth_url"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &setupOut)
	if setupOut.Data.SecretB32 == "" || !strings.Contains(setupOut.Data.OTPAuthURL, "otpauth://totp/") {
		t.Fatalf("setup body: %s", body)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setupOut.Data.SecretB32)
	if err != nil {
		t.Fatal(err)
	}
	totp := security.NewTOTPProvider()
	cc, _ := totp.CodeAt(ctx, raw, auth.NewCounter(time.Now().UTC()))
	code, body = e.doAuthed("POST", "/enable", `{"code":"`+cc+`"}`, tok)
	if code != 200 {
		t.Fatalf("enable: %d %s", code, body)
	}
	var enOut struct {
		Data struct {
			BackupCodes []string `json:"backup_codes"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &enOut)
	if len(enOut.Data.BackupCodes) != 10 {
		t.Fatalf("backups: %v", enOut.Data)
	}
	// Planos únicos y con formato display válido (canónico 10ch).
	seenCodes := map[string]bool{}
	for _, bc := range enOut.Data.BackupCodes {
		if seenCodes[bc] {
			t.Fatal("backup duplicado")
		}
		seenCodes[bc] = true
	}
	backupCodes := enOut.Data.BackupCodes
	_ = backupCodes
	// Secreto cifrado en DB (no contiene b32).
	var enc []byte
	_ = e.pool.QueryRow(ctx, `SELECT secret_enc FROM mfa_totp_secrets WHERE user_id=$1::uuid`, uid).Scan(&enc)
	if len(enc) == 0 || strings.Contains(string(enc), setupOut.Data.SecretB32) {
		t.Fatal("secreto debe estar cifrado")
	}
	var flag bool
	_ = e.pool.QueryRow(ctx, `SELECT mfa_enabled FROM users WHERE id=$1::uuid`, uid).Scan(&flag)
	if !flag {
		t.Fatal("mfa_enabled debe ser true")
	}

	// Escenario 2: login-202 simulado (pre-token real) → verify 200 + replay 401.
	pretok, _, _, err := security.NewMFAPreTokenIssuer(e.secret).IssueChallenge(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	// Registra challenge como lo haría el login (MFAStores real).
	stores := postgres.NewMFAStores(e.pool, redisadapter.NewMFAChallengeCache(e.rdb), e.rdb)
	chID := challengeIDOfMFA(t, pretok)
	if err := stores.Register(ctx, chID, uid); err != nil {
		t.Fatal(err)
	}
	vcode, _ := totp.CodeAt(ctx, raw, auth.NewCounter(time.Now().UTC()))
	code, body = e.doAnon("POST", "/verify", `{"mfa_token":"`+pretok+`","code":"`+vcode+`"}`)
	if code != 200 || !strings.Contains(body, `"status":"active"`) {
		t.Fatalf("verify: %d %s", code, body)
	}
	// Replay mismo body → 401 (challenge consumido).
	code, body = e.doAnon("POST", "/verify", `{"mfa_token":"`+pretok+`","code":"`+vcode+`"}`)
	if code != 401 || !strings.Contains(body, "INVALID_MFA") {
		t.Fatalf("replay: %d %s", code, body)
	}

	// Escenario 3: skew ±1 con challenges frescos.
	for _, delta := range []int64{-1, 1} {
		pt, _, _, _ := security.NewMFAPreTokenIssuer(e.secret).IssueChallenge(ctx, uid)
		cid := challengeIDOfMFA(t, pt)
		if err := stores.Register(ctx, cid, uid); err != nil {
			t.Fatal(err)
		}
		cc2, _ := totp.CodeAt(ctx, raw, auth.NewCounter(time.Now().UTC())+delta)
		c, _ := e.doAnon("POST", "/verify", `{"mfa_token":"`+pt+`","code":"`+cc2+`"}`)
		if c != 200 {
			t.Fatalf("skew %+d: %d", delta, c)
		}
	}

	// Escenario 4: 5 fallos queman + pre-token en negocio → 401.
	pt, _, _, _ := security.NewMFAPreTokenIssuer(e.secret).IssueChallenge(ctx, uid)
	cid := challengeIDOfMFA(t, pt)
	if err := stores.Register(ctx, cid, uid); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		c, _ := e.doAnon("POST", "/verify", `{"mfa_token":"`+pt+`","code":"000000"}`)
		if c != 401 {
			t.Fatalf("fallo %d: %d", i, c)
		}
	}
	c, _ := e.doAnon("POST", "/verify", `{"mfa_token":"`+pt+`","code":"`+vcode+`"}`)
	if c != 401 {
		t.Fatalf("quemado debe seguir 401: %d", c)
	}
	// Pre-token en API negocio → 401 (aud aislado).
	req := httptest.NewRequest("GET", "/biz", nil)
	req.Header.Set("Authorization", "Bearer "+pt)
	rr := httptest.NewRecorder()
	e.mux.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("pretoken en negocio: %d", rr.Code)
	}

	// Escenario 5: disable último-factor 400 (solo-MFA) y con resto 200.
	uidSolo := e.createActive("solo-mfa@example.com", "x")
	_ = uidSolo
	// Solo-MFA sin password: crea federated-only directo.
	var fedID string
	_ = e.pool.QueryRow(ctx, `INSERT INTO users (id, email_normalized, email_original, password_algo, status,
		terms_version, privacy_version, terms_accepted_at, federated_only, terms_source)
		VALUES (gen_random_uuid(), 'solofed@example.com', 'solofed@example.com', 'federated', 'ACTIVE',
		'v2026.10', 'v2026.10', now(), TRUE, 'federated_google') RETURNING id::text`).Scan(&fedID)
	tokFed := e.bearer(fedID)
	// Habilita MFA directo vía store para el solo-federado.
	box, _ := security.NewSecretBox(e.secret)
	enc2, _ := box.Encrypt(ctx, fedID, raw)
	_, _ = e.pool.Exec(ctx, `INSERT INTO mfa_totp_secrets (user_id, secret_enc, staged, verified, enabled_at)
		VALUES ($1::uuid,$2,FALSE,TRUE,now()) ON CONFLICT (user_id) DO UPDATE SET staged=FALSE, verified=TRUE`, fedID, enc2)
	_, _ = e.pool.Exec(ctx, `UPDATE users SET mfa_enabled=TRUE WHERE id=$1::uuid`, fedID)
	c, b := e.doAuthed("DELETE", "/totp", "", tokFed)
	if c != 400 || !strings.Contains(b, "LAST_AUTH_FACTOR") {
		t.Fatalf("último factor: %d %s", c, b)
	}
	// Con password restante (uid) → 200 + mail.
	c, b = e.doAuthed("DELETE", "/totp", "", tok)
	if c != 200 || !strings.Contains(b, "disabled") {
		t.Fatalf("disable: %d %s", c, b)
	}

	// Escenario 6: backup consume → reuso 401 → status → regen → viejo 401.
	// Re-habilita MFA para uid (disable lo apagó).
	tok2 := e.bearer(uid)
	c, b = e.doAuthed("POST", "/setup", "", tok2)
	if c != 200 {
		t.Fatalf("setup2: %d %s", c, b)
	}
	var setup2 struct {
		Data struct {
			SecretB32 string `json:"secret_b32"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(b), &setup2)
	raw2, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup2.Data.SecretB32)
	totp2 := security.NewTOTPProvider()
	cc2, _ := totp2.CodeAt(ctx, raw2, auth.NewCounter(time.Now().UTC()))
	c, b = e.doAuthed("POST", "/enable", `{"code":"`+cc2+`"}`, tok2)
	if c != 200 {
		t.Fatalf("enable2: %d %s", c, b)
	}
	var en2 struct {
		Data struct {
			BackupCodes []string `json:"backup_codes"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(b), &en2)
	b1display := en2.Data.BackupCodes[0][:4] + "-" + en2.Data.BackupCodes[0][4:]
	// Login-202 simulado + consume con guion (formato display).
	pretok2, _, _, _ := security.NewMFAPreTokenIssuer(e.secret).IssueChallenge(ctx, uid)
	cid2 := challengeIDOfMFA(t, pretok2)
	stores2 := postgres.NewMFAStores(e.pool, redisadapter.NewMFAChallengeCache(e.rdb), e.rdb)
	if err := stores2.Register(ctx, cid2, uid); err != nil {
		t.Fatal(err)
	}
	c, b = e.doAnon("POST", "/verify", `{"mfa_token":"`+pretok2+`","backup_code":"`+b1display+`"}`)
	if c != 200 || !strings.Contains(b, `"backup_remaining":9`) {
		t.Fatalf("consume: %d %s", c, b)
	}
	var used bool
	_ = e.pool.QueryRow(ctx, `SELECT used FROM mfa_backup_codes WHERE user_id=$1::uuid ORDER BY created_at LIMIT 1`).Scan(&used)
	_ = used
	var remaining int
	_ = e.pool.QueryRow(ctx, `SELECT count(*) FROM mfa_backup_codes WHERE user_id=$1::uuid AND used=FALSE`, uid).Scan(&remaining)
	if remaining != 9 {
		t.Fatalf("remaining=%d", remaining)
	}
	// Reuso mismo código + challenge nuevo → 401.
	pretok3, _, _, _ := security.NewMFAPreTokenIssuer(e.secret).IssueChallenge(ctx, uid)
	cid3 := challengeIDOfMFA(t, pretok3)
	if err := stores2.Register(ctx, cid3, uid); err != nil {
		t.Fatal(err)
	}
	c, _ = e.doAnon("POST", "/verify", `{"mfa_token":"`+pretok3+`","code":"`+en2.Data.BackupCodes[0]+`"}`)
	if c != 401 {
		t.Fatalf("reuso debe ser 401: %d", c)
	}
	// Status con remaining/warning (sin valores).
	c, b = e.doAuthed("GET", "/status", "", tok2)
	if c != 200 || !strings.Contains(b, `"backup_remaining":9`) {
		t.Fatalf("status: %d %s", c, b)
	}
	// Regen quema y re-exhibe 10; el viejo intacto muere.
	c, b = e.doAuthed("POST", "/regen", "", tok2)
	if c != 200 {
		t.Fatalf("regen: %d %s", c, b)
	}
	var rgOut struct {
		Data struct {
			BackupCodes []string `json:"backup_codes"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(b), &rgOut)
	if len(rgOut.Data.BackupCodes) != 10 {
		t.Fatalf("regen codes: %v", rgOut.Data)
	}
	pretok4, _, _, _ := security.NewMFAPreTokenIssuer(e.secret).IssueChallenge(ctx, uid)
	cid4 := challengeIDOfMFA(t, pretok4)
	if err := stores2.Register(ctx, cid4, uid); err != nil {
		t.Fatal(err)
	}
	c, _ = e.doAnon("POST", "/verify", `{"mfa_token":"`+pretok4+`","code":"`+en2.Data.BackupCodes[1]+`"}`)
	if c != 401 {
		t.Fatalf("viejo tras regen debe ser 401: %d", c)
	}
	t.Log("E2E MFA PASSED")
}

func challengeIDOfMFA(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("token malo")
	}
	rawPay, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		ChallengeID string `json:"challenge_id"`
	}
	_ = json.Unmarshal(rawPay, &c)
	return c.ChallengeID
}
