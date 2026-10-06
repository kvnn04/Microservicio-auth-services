package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"auth-identity-service/internal/adapter/colas/kafka"
	adapterhttp "auth-identity-service/internal/adapter/http"
	"auth-identity-service/internal/adapter/http/handlers"
	"auth-identity-service/internal/adapter/http/middleware"
	"auth-identity-service/internal/adapter/identity"
	"auth-identity-service/internal/adapter/persistencia/postgres"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/adapter/security"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"
	"auth-identity-service/pkg/logger"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

func mustEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	var v int
	if _, err := fmt.Sscanf(os.Getenv(k), "%d", &v); err == nil && v > 0 {
		return v
	}
	return def
}

func main() {
	log := logger.New("api")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dbURL := mustEnv("DATABASE_URL", "postgres://auth:auth@localhost:5432/auth_db?sslmode=disable")
	redisURL := mustEnv("REDIS_URL", "redis://localhost:6379/0")
	addr := mustEnv("HTTP_ADDR", ":8080")
	strict := strings.ToLower(os.Getenv("ENV")) == "production-strict"
	pepper := []byte(os.Getenv("PASSWORD_PEPPER"))

	poolCfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Error("postgres config failed", slog.String("error_code", "DB_UNAVAILABLE"))
		os.Exit(1)
	}
	// Concurrencia de verificación (Tx cortas): pool acorde a VUs esperados.
	// Sin esto pgxpool encola y el p95 se degrada bajo carga (ver T-13).
	poolCfg.MaxConns = 25
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Error("postgres connect failed", slog.String("error_code", "DB_UNAVAILABLE"))
		os.Exit(1)
	}
	defer pool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr(redisURL)})
	limiter := redisadapter.NewRateLimiter(rdb, strict)
	idem := redisadapter.NewIdempotencyStore(rdb)
	repo := postgres.NewUserRepository(pool)
	hasher := security.NewArgon2Hasher(pepper)
	breachTimeout := 800 * time.Millisecond
	if v := os.Getenv("HIBP_TIMEOUT_MS"); v != "" {
		if d, err := time.ParseDuration(v + "ms"); err == nil {
			breachTimeout = d
		}
	}
	breach := security.NewHIBPBreachChecker(breachTimeout)
	tokens := security.NewTokenIssuer()
	audit := kafka.NewAuditLogger(pool)
	frontURL := mustEnv("FRONT_BASE_URL", "http://localhost:3000")

	svc := service.NewRegisterUserService(repo, hasher, breach, tokens, repo, idem, audit,
		adapterhttp.NewPrometheusMetrics(), adapterhttp.NewOtelTracer())

	// CU-REG-05 (transversal): consentimiento legal fail-closed + ledger.
	// Env: LEGAL_FALLBACK_TERMS/PRIVACY (solo degradan GET), LEGAL_CACHE_TTL=1h.
	consentMetrics := adapterhttp.NewPrometheusConsentMetrics()
	legalProvider := postgres.NewCombinedLegalProvider(pool,
		redisadapter.NewLegalCache(rdb),
		os.Getenv("LEGAL_FALLBACK_TERMS"), os.Getenv("LEGAL_FALLBACK_PRIVACY"),
		func() { log.Warn("legal cache stale") })
	svc.Legal = legalProvider
	svc.Consents = consentMetrics

	// CU-REG-03 (transversal): throttle notify 1/h + 3/día + bloqueo progresivo.
	// Env: NOTIFY_THROTTLE_H, NOTIFY_MAX_DAY, IP_BLOCK_THRESHOLD (=50x429/15min).
	promReg := adapterhttp.NewPrometheusMetrics()
	throttle := redisadapter.NewRedisNotifyThrottle(rdb, envInt("NOTIFY_THROTTLE_H", 1), envInt("NOTIFY_MAX_DAY", 3),
		func(reason string) { log.Warn("notify throttle fallback", slog.String("reason", reason)) })
	svc.Throttle = throttle
	blocks := adapterhttp.BlockCounter{M: promReg}
	blockThreshold := envInt("IP_BLOCK_THRESHOLD", 50)

	// CU-REG-02: store combinado Redis-verdad + Postgres-backup.
	verifyCache := redisadapter.NewVerificationCache(rdb)
	verifyMetrics := adapterhttp.NewPrometheusVerifyMetrics()
	vstore := postgres.NewCombinedVerificationStore(pool, verifyCache, frontURL,
		func(reason string) { verifyMetrics.IncRedisFallback(reason) })
	verifySvc := service.NewVerifyEmailService(vstore, repo, idem, audit, verifyMetrics, adapterhttp.NewOtelTracer())
	resendSvc := service.NewResendService(repo, vstore, tokens, idem, audit, verifyMetrics, adapterhttp.NewOtelTracer())

	// CU-AUTH-05: passwordless (Redis-verdad + PG-backup, secreto dual email).
	plessCache := redisadapter.NewPasswordlessCache(rdb)
	plessMetrics := adapterhttp.NewPrometheusPlessMetrics()
	plessStore := postgres.NewCombinedPasswordlessStore(pool, plessCache, frontURL,
		func(reason string) { plessMetrics.IncPlessFallback(reason) })
	plessStartSvc := service.NewPasswordlessStartService(plessStore, tokens, idem, audit,
		plessMetrics, adapterhttp.NewOtelTracer())

	// CU-REG-04: federado Google (MVP). URLs configurables para fake-IdP en tests.
	allowedProviders := strings.Split(mustEnv("ALLOWED_PROVIDERS", "google"), ",")
	googleClient := identity.NewGoogleOIDCClient(
		mustEnv("FEDERATED_ISSUER", "https://accounts.google.com"),
		os.Getenv("FEDERATED_GOOGLE_CLIENT_ID"),
		os.Getenv("FEDERATED_GOOGLE_CLIENT_SECRET"),
		mustEnv("FEDERATED_GOOGLE_REDIRECT_URI", "http://localhost:8080/api/v1/auth/federated/google/callback"),
		os.Getenv("FEDERATED_DISCOVERY_URL"),
		os.Getenv("FEDERATED_TOKEN_URL"),
		os.Getenv("FEDERATED_JWKS_URL"),
	)
	fedRepo := postgres.NewFederatedRepository(pool)
	fedStates := redisadapter.NewRedisFederatedStateStore(rdb)
	fedMetrics := adapterhttp.NewPrometheusFederatedMetrics()
	legacySessions := security.NewSessionIssuer([]byte(os.Getenv("SESSION_SECRET")), rdb)
	// CU-AUTH-04 enterprise: Ed25519 + PG Tx + Redis write-through.
	// Env: SESSION_SIGNING_KEY (base64 seed/priv), SESSION_SIGNING_KID,
	// SESSION_ISS/AUD, MAX_SESSIONS (documentado, default 20 en dominio).
	signingKID := mustEnv("SESSION_SIGNING_KID", "2026-10-a")
	signingIss := mustEnv("SESSION_ISS", "https://auth.example.com")
	signingAud := mustEnv("SESSION_AUD", "api")
	var edSigner *security.Ed25519Signer
	var edPriv ed25519.PrivateKey
	if raw := strings.TrimSpace(os.Getenv("SESSION_SIGNING_KEY")); raw != "" {
		priv, perr := security.ParseEd25519PrivateKey(raw)
		if perr != nil {
			log.Error("session signing key invalid", slog.String("error_code", "ISSUE_UNAVAILABLE"))
			os.Exit(1)
		}
		edPriv = priv
		if s, serr := security.NewEd25519Signer(priv, signingKID, signingIss, signingAud); serr == nil {
			edSigner = s
		} else {
			log.Error("ed25519 signer invalid", slog.String("error_code", "ISSUE_UNAVAILABLE"))
			os.Exit(1)
		}
	} else if strings.ToLower(os.Getenv("ENV")) == "production" {
		log.Error("session signing key missing", slog.String("error_code", "ISSUE_UNAVAILABLE"))
		os.Exit(1)
	} else {
		// Dev/ephemeral (WARN): nunca en prod.
		priv, _, _ := security.GenerateEd25519Key()
		edPriv = priv
		// GenerateEd25519Key retorna (priv, pubB64, err); reconstruye signer.
		if s, serr := security.NewEd25519Signer(priv, signingKID, signingIss, signingAud); serr == nil {
			edSigner = s
			log.Warn("SESSION_SIGNING_KEY missing: ephemeral Ed25519 (dev only)")
		} else {
			log.Error("ephemeral signer failed", slog.String("error_code", "ISSUE_UNAVAILABLE"))
			os.Exit(1)
		}
	}
	sessionStore := postgres.NewSessionStore(pool)
	sessionCache := redisadapter.NewSessionCache(rdb)
	issueMetrics := adapterhttp.NewPrometheusIssueMetrics()
	issueSvc := service.NewIssueService(edSigner, security.NewRefreshGenerator(),
		sessionStore, sessionCache, repo, audit, issueMetrics,
		adapterhttp.NewOtelTracer(), signingIss, signingAud)
	// Verificador híbrido (Ed25519 + fallback HS256) para RequireAuth.
	hybridVerifier := security.NewHybridVerifier(edSigner, legacySessions)
	fedSvc := service.NewRegisterFederatedService(googleClient, fedRepo, fedStates,
		vstore, tokens, issueSvc, repo, throttle, idem, audit,
		fedMetrics, adapterhttp.NewOtelTracer(), "v2026.10", true)
	fedSvc.Legal = legalProvider
	fedSvc.Consents = consentMetrics
	secureCookies := strings.ToLower(os.Getenv("ENV")) == "production"
	envIsDev := strings.ToLower(os.Getenv("ENV")) == "dev" || strings.ToLower(os.Getenv("ENV")) == "development" || os.Getenv("ENV") == ""
	_ = envIsDev
	if !secureCookies && strings.ToLower(os.Getenv("ENV")) != "production" && os.Getenv("ENV") != "" && strings.ToLower(os.Getenv("ENV")) != "dev" && strings.ToLower(os.Getenv("ENV")) != "development" {
		// Secure se relaja solo en dev (WARN, documentado SEC-05).
		log.Warn("cookies without Secure (dev only)")
	}

	// CU-AUTH-01: login estándar (ahora vía IssueService enterprise).
	loginTracker := redisadapter.NewLoginTracker(limiter)
	loginMetrics := adapterhttp.NewPrometheusLoginMetrics()
	mfaIssuer := security.NewMFAPreTokenIssuer([]byte(os.Getenv("SESSION_SECRET")))
	mfaStores := postgres.NewMFAStores(pool, redisadapter.NewMFAChallengeCache(rdb), rdb)
	loginSvc := service.NewLoginService(repo, hasher, loginTracker, issueSvc, mfaIssuer,
		mfaStores, repo, idem, audit, loginMetrics, adapterhttp.NewOtelTracer())

	// CU-AUTH-02: MFA TOTP (secret cifrado AES-GCM, fail-fast sin key).
	mfaSecretsKey, err := security.ParseSecretsKey(os.Getenv("MFA_SECRETS_KEY"))
	if err != nil {
		log.Error("mfa secrets key missing/invalid", slog.String("error_code", "MFA_KEY_UNAVAILABLE"))
		os.Exit(1)
	}
	mfaBox, err := security.NewSecretBox(mfaSecretsKey)
	if err != nil {
		log.Error("mfa secrets key invalid", slog.String("error_code", "MFA_KEY_UNAVAILABLE"))
		os.Exit(1)
	}
	mfaMetrics := adapterhttp.NewPrometheusMFAMetrics()
	// CU-REG-06 store (también lo usa MFA disable para último-factor).
	// Se declara aquí arriba porque MFA (debajo) lo necesita.
	linkStore := postgres.NewFederatedLinkStore(pool)

	mfaSvc := service.NewMFAService(security.NewTOTPProvider(), mfaBox, mfaStores, mfaStores,
		mfaIssuer, security.NewBackupCodeIssuer([]byte(os.Getenv("PASSWORD_PEPPER")), []byte(os.Getenv("PEPPER_PREV"))),
		postgres.NewBackupCodeStore(pool), repo, linkStore, issueSvc, repo, idem, audit,
		mfaMetrics, adapterhttp.NewOtelTracer(), mustEnv("MFA_ISSUER", "Example"))
	mfaSvc.BackupMetrics = adapterhttp.NewPrometheusBackupMetrics()
	if os.Getenv("PASSWORD_PEPPER") == "" {
		log.Warn("password pepper missing: backup codes use plain SHA-256 (dev only)")
	}

	// CU-AUTH-05 verify (tras IssueService + MFA): secreto → sesión/MFA.
	plessVerifySvc := service.NewPasswordlessVerifyService(plessStore, issueSvc, mfaIssuer, mfaStores,
		idem, audit, plessMetrics, adapterhttp.NewOtelTracer())

	// CU-CRED-01: recuperación de contraseña (sin auto-login: no usa IssueService).
	pwdResetCache := redisadapter.NewPasswordResetCache(rdb)
	pwdResetMetrics := adapterhttp.NewPrometheusPwdResetMetrics()
	pwdResetStore := postgres.NewCombinedPasswordResetStore(pool, pwdResetCache, sessionCache, frontURL,
		func(reason string) { pwdResetMetrics.IncResetFallback(reason) })
	pwdResetStartSvc := service.NewPasswordResetStartService(pwdResetStore, tokens, idem, audit,
		pwdResetMetrics, adapterhttp.NewOtelTracer())
	pwdResetConfirmSvc := service.NewPasswordResetConfirmService(pwdResetStore, hasher, breach, idem, audit,
		pwdResetMetrics, adapterhttp.NewOtelTracer())

	// CU-AUTH-06: Step-Up (misma clave Ed25519, aud=step-up aislado; jti en Redis).
	// Env: STEP_UP_MAX_AGE=300s, STEP_UP_TTL=300s (consts de dominio),
	// ENFORCE_STEP_UP_TOKEN=false (compat fast-pass O token).
	stepUpTokenIssuer, err := security.NewStepUpTokenIssuer(edPriv, signingKID, signingIss)
	if err != nil {
		log.Error("step-up signer invalid", slog.String("error_code", "STEP_UP_UNAVAILABLE"))
		os.Exit(1)
	}
	stepUpJTIs := redisadapter.NewStepUpJTIStore(rdb)
	stepUpMetrics := adapterhttp.NewPrometheusStepUpMetrics()
	enforceStepUp := strings.ToLower(os.Getenv("ENFORCE_STEP_UP_TOKEN")) == "true"
	stepUpSvc := service.NewStepUpService(repo, hasher, loginTracker,
		security.NewTOTPProvider(), mfaBox, mfaStores, mfaStores,
		security.NewBackupCodeIssuer([]byte(os.Getenv("PASSWORD_PEPPER")), []byte(os.Getenv("PEPPER_PREV"))),
		postgres.NewBackupCodeStore(pool), stepUpTokenIssuer, stepUpJTIs,
		repo, idem, audit, stepUpMetrics, adapterhttp.NewOtelTracer())
	stepUpSvc.BackupMetrics = adapterhttp.NewPrometheusBackupMetrics()

	// CU-CRED-02: cambio con sesión (preserva actual, revoca pares).
	// Sin auto-login: no usa IssueService. TTL/history son consts de dominio.
	pwdHistStore := postgres.NewCombinedPasswordHistoryStore(pool, sessionCache, frontURL,
		func(reason string) { pwdResetMetrics.IncResetFallback(reason) })
	changeMetrics := adapterhttp.NewPrometheusChangeMetrics()
	changeSvc := service.NewChangePasswordService(pwdHistStore, hasher, breach, loginTracker, stepUpSvc,
		repo, idem, audit, changeMetrics, adapterhttp.NewOtelTracer())

	// CU-CRED-03: cambio de email (Step-Up en servicio, doble-mail, corte+relogin).
	emailChangeCache := redisadapter.NewEmailChangeCache(rdb)
	emailChangeMetrics := adapterhttp.NewPrometheusEmailChangeMetrics()
	emailChangeStore := postgres.NewCombinedEmailChangeStore(pool, emailChangeCache, sessionCache, frontURL,
		func(reason string) { emailChangeMetrics.IncEmailChangeFallback(reason) })
	emailChangeStartSvc := service.NewEmailChangeStartService(repo, emailChangeStore, stepUpSvc, tokens,
		idem, audit, emailChangeMetrics, adapterhttp.NewOtelTracer())
	emailChangeConfirmSvc := service.NewEmailChangeConfirmService(emailChangeStore,
		idem, audit, emailChangeMetrics, adapterhttp.NewOtelTracer())

	mux := http.NewServeMux()
	registerLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return redisadapter.IPKey(verifyClientIP(r))
	}, 10, time.Minute, blockThreshold, blocks)
	mux.Handle("POST /api/v1/auth/register",
		middleware.Recover(middleware.RequestID(registerLimit(handlers.RegisterHandler(svc)))),
	)
	// login:ip 10/min + login:account 5/min (tracker) + progresivo IP.
	loginIPLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:login:ip:" + verifyClientIP(r)
	}, 10, time.Minute, blockThreshold, blocks)
	mux.Handle("POST /api/v1/auth/login",
		middleware.Recover(middleware.RequestID(loginIPLimit(handlers.LoginHandler(loginSvc, secureCookies)))),
	)
	verifyIPLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:verify:ip:" + verifyClientIP(r)
	}, 10, time.Minute, blockThreshold, blocks)
	verifyChain := func(h http.Handler) http.Handler {
		return middleware.Recover(middleware.RequestID(verifyIPLimit(h)))
	}
	mux.Handle("POST /api/v1/auth/verify-email", verifyChain(handlers.VerifyHandler(verifySvc, limiter)))
	mux.Handle("GET /api/v1/auth/verify-email", verifyChain(handlers.VerifyHandler(verifySvc, limiter)))
	resendIPLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:resend:ip:" + verifyClientIP(r)
	}, 10, time.Hour, blockThreshold, blocks)
	mux.Handle("POST /api/v1/auth/resend-verification",
		middleware.Recover(middleware.RequestID(resendIPLimit(handlers.ResendHandler(resendSvc, limiter)))),
	)
	// CU-AUTH-05: passwordless sin contraseña (emisor de correos: 10/hora/IP).
	plessStartIPLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:pless:start:ip:" + verifyClientIP(r)
	}, 10, time.Hour, blockThreshold, blocks)
	plessVerifyIPLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:pless:verify:ip:" + verifyClientIP(r)
	}, 20, time.Minute, blockThreshold, blocks)
	mux.Handle("POST /api/v1/auth/passwordless/start",
		middleware.Recover(middleware.RequestID(plessStartIPLimit(handlers.PlessStartHandler(plessStartSvc, limiter)))),
	)
	mux.Handle("POST /api/v1/auth/passwordless/verify",
		middleware.Recover(middleware.RequestID(plessVerifyIPLimit(handlers.PlessVerifyHandler(plessVerifySvc, limiter, secureCookies)))),
	)
	mux.Handle("GET /api/v1/auth/passwordless",
		middleware.Recover(middleware.RequestID(plessVerifyIPLimit(handlers.PlessVerifyHandler(plessVerifySvc, limiter, secureCookies)))),
	)
	// CU-CRED-01: reset sin contraseña (emisor de correos: 10/hora/IP).
	pwdResetStartIPLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:pwdreset:start:ip:" + verifyClientIP(r)
	}, 10, time.Hour, blockThreshold, blocks)
	pwdResetConfirmIPLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:pwdreset:confirm:ip:" + verifyClientIP(r)
	}, 20, time.Minute, blockThreshold, blocks)
	mux.Handle("POST /api/v1/auth/password/reset/start",
		middleware.Recover(middleware.RequestID(pwdResetStartIPLimit(handlers.PwdResetStartHandler(pwdResetStartSvc, limiter)))),
	)
	mux.Handle("POST /api/v1/auth/password/reset/confirm",
		middleware.Recover(middleware.RequestID(pwdResetConfirmIPLimit(handlers.PwdResetConfirmHandler(pwdResetConfirmSvc, limiter)))),
	)
	mux.Handle("GET /api/v1/auth/password/reset",
		middleware.Recover(middleware.RequestID(pwdResetConfirmIPLimit(handlers.PwdResetConfirmHandler(pwdResetConfirmSvc, limiter)))),
	)
	fedAuthzLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:fed_authz:ip:" + verifyClientIP(r)
	}, 20, time.Minute, blockThreshold, blocks)
	fedCbLimit := middleware.RateLimitProgressive(limiter, func(r *http.Request) string {
		return "rl:fed_cb:ip:" + verifyClientIP(r)
	}, 10, time.Minute, blockThreshold, blocks)
	fedChain := func(h http.Handler) http.Handler {
		return middleware.Recover(middleware.RequestID(
			middleware.ProviderAllowlist(allowedProviders)(h)))
	}
	mux.Handle("GET /api/v1/auth/federated/{provider}/authorize",
		fedChain(fedAuthzLimit(handlers.FederatedAuthorizeHandler(fedSvc, secureCookies))))
	mux.Handle("GET /api/v1/auth/federated/{provider}/callback",
		fedChain(fedCbLimit(handlers.FederatedCallbackHandler(fedSvc, limiter, secureCookies))))
	// CU-REG-05: lectura pública de versiones (cacheable 1h, 60/min/IP).
	legalLimit := middleware.RateLimitKey(limiter, func(r *http.Request) string {
		return "rl:legal:ip:" + verifyClientIP(r)
	}, 60, time.Minute)
	mux.Handle("GET /api/v1/legal/active",
		middleware.Recover(middleware.RequestID(legalLimit(handlers.LegalActiveHandler(legalProvider)))))

	// CU-REG-06: vinculación (auth + Step-Up; Bearer o cookie access_token).
	linkMetrics := adapterhttp.NewPrometheusLinkMetrics()
	linkStates := redisadapter.NewRedisLinkStateStore(rdb)
	apiBase := mustEnv("API_PUBLIC_BASE", "http://localhost:8080")
	linkSvc := service.NewLinkService(googleClient, linkStore, linkStates, repo, hasher,
		repo, throttle, idem, audit, linkMetrics, adapterhttp.NewOtelTracer(),
		apiBase+"/api/v1/auth/federated/google/link/callback", 5, 5*time.Minute)
	unlinkSvc := service.NewUnlinkService(linkStore, repo, hasher, idem, audit,
		linkMetrics, adapterhttp.NewOtelTracer(), 5*time.Minute)
	authMw := middleware.RequireAuth(hybridVerifier)
	linkUserKey := func(suffix string, limit int, window time.Duration) func(http.Handler) http.Handler {
		return middleware.RateLimitKey(limiter, func(r *http.Request) string {
			if uid, _, ok := middleware.AuthUserFromContext(r.Context()); ok {
				return "rl:link:" + suffix + ":" + uid
			}
			return "rl:link:" + suffix + ":anon"
		}, limit, window)
	}
	// CU-AUTH-06: guard scopeado (fast-pass O X-Step-Up-Token). scope "" = solo auth.
	linkChain := func(h http.Handler, rl func(http.Handler) http.Handler, scope auth.StepUpScope) http.Handler {
		inner := middleware.ProviderAllowlist(allowedProviders)(rl(h))
		if scope != "" {
			inner = middleware.RequireStepUp(scope, stepUpSvc, enforceStepUp)(inner)
		}
		return middleware.Recover(middleware.RequestID(authMw(inner)))
	}
	mux.Handle("POST /api/v1/auth/federated/{provider}/link",
		linkChain(handlers.LinkInitiateHandler(linkSvc, limiter), linkUserKey("init", 10, time.Hour), auth.ScopeFederatedLink))
	mux.Handle("GET /api/v1/auth/federated/{provider}/link/callback",
		linkChain(handlers.LinkCallbackHandler(linkSvc, limiter), middleware.RateLimitKey(limiter, func(r *http.Request) string {
			return "rl:link:cb:ip:" + verifyClientIP(r)
		}, 10, time.Minute), auth.ScopeFederatedLink))
	mux.Handle("DELETE /api/v1/auth/federated/{provider}",
		linkChain(handlers.UnlinkHandler(unlinkSvc, limiter), linkUserKey("unlink", 10, time.Hour), auth.ScopeFederatedUnlink))
	mux.Handle("POST /api/v1/auth/federated/{provider}/unlink",
		linkChain(handlers.UnlinkHandler(unlinkSvc, limiter), linkUserKey("unlink", 10, time.Hour), auth.ScopeFederatedUnlink))
	mux.Handle("GET /api/v1/auth/federated/linked",
		linkChain(handlers.LinkedListHandler(unlinkSvc, limiter), linkUserKey("list", 60, time.Minute), ""))
	// CU-AUTH-02: MFA TOTP (setup/enable/disable con Step-Up; verify con pre-token).
	mfaSetupLimit := middleware.RateLimitKey(limiter, func(r *http.Request) string {
		if uid, _, ok := middleware.AuthUserFromContext(r.Context()); ok {
			return "rl:mfa:setup:" + uid
		}
		return "rl:mfa:setup:anon"
	}, 10, time.Hour)
	mfaVerifyIPLimit := middleware.RateLimitKey(limiter, func(r *http.Request) string {
		return "rl:mfa:verify:ip:" + verifyClientIP(r)
	}, 20, time.Minute)
	mux.Handle("POST /api/v1/auth/mfa/totp/setup",
		linkChain(handlers.MFASetupHandler(mfaSvc, limiter), mfaSetupLimit, auth.ScopeMFARotate))
	mux.Handle("POST /api/v1/auth/mfa/totp/enable",
		linkChain(handlers.MFAEnableHandler(mfaSvc), mfaSetupLimit, auth.ScopeMFARotate))
	mux.Handle("POST /api/v1/auth/mfa/verify",
		middleware.Recover(middleware.RequestID(mfaVerifyIPLimit(handlers.MFAVerifyHandler(mfaSvc, limiter, secureCookies)))))
	mux.Handle("DELETE /api/v1/auth/mfa/totp",
		linkChain(handlers.MFADisableHandler(mfaSvc), mfaSetupLimit, auth.ScopeMFADisable))
	mux.Handle("GET /api/v1/auth/mfa/status",
		linkChain(handlers.MFAStatusHandler(mfaSvc), linkUserKey("mfastatus", 60, time.Minute), ""))
	// CU-AUTH-03: regenerate con Step-Up (10/hora/user).
	regenLimit := middleware.RateLimitKey(limiter, func(r *http.Request) string {
		if uid, _, ok := middleware.AuthUserFromContext(r.Context()); ok {
			return "rl:backup:regen:" + uid
		}
		return "rl:backup:regen:anon"
	}, 10, time.Hour)
	mux.Handle("POST /api/v1/auth/mfa/backup-codes/regenerate",
		linkChain(handlers.MFARegenerateHandler(mfaSvc, limiter), regenLimit, auth.ScopeBackupRegen))
	// CU-AUTH-06: challenge Step-Up (auth + IP 30/min; usuario 10/min en handler).
	stepUpChallengeIPLimit := middleware.RateLimitKey(limiter, func(r *http.Request) string {
		return "rl:step-up:ip:" + verifyClientIP(r)
	}, 30, time.Minute)
	mux.Handle("POST /api/v1/auth/step-up/challenge",
		middleware.Recover(middleware.RequestID(authMw(stepUpChallengeIPLimit(
			handlers.StepUpChallengeHandler(stepUpSvc, limiter))))))
	// CU-CRED-02: cambio con sesión (Bearer + rate 5/h por usuario en handler;
	// federated-set además X-Step-Up-Token, verificado en el servicio).
	mux.Handle("POST /api/v1/auth/password/change",
		middleware.Recover(middleware.RequestID(authMw(handlers.ChangePasswordHandler(changeSvc, limiter)))),
	)
	// CU-CRED-03: cambio de email (Step-Up verificado en el servicio).
	// Start: auth + usuario 3/h + IP 20/h. Confirm/GET: anónimo + IP 20/min.
	emailChangeUserLimit := middleware.RateLimitKey(limiter, func(r *http.Request) string {
		if uid, _, ok := middleware.AuthUserFromContext(r.Context()); ok {
			return "rl:emailchange:user:" + uid
		}
		return "rl:emailchange:user:anon"
	}, 3, time.Hour)
	emailChangeStartIPLimit := middleware.RateLimitKey(limiter, func(r *http.Request) string {
		return "rl:emailchange:start:ip:" + verifyClientIP(r)
	}, 20, time.Hour)
	emailChangeConfirmIPLimit := middleware.RateLimitKey(limiter, func(r *http.Request) string {
		return "rl:emailchange:confirm:ip:" + verifyClientIP(r)
	}, 20, time.Minute)
	mux.Handle("POST /api/v1/auth/email/change/start",
		middleware.Recover(middleware.RequestID(authMw(emailChangeUserLimit(emailChangeStartIPLimit(
			handlers.EmailChangeStartHandler(emailChangeStartSvc, limiter)))))),
	)
	mux.Handle("POST /api/v1/auth/email/change/confirm",
		middleware.Recover(middleware.RequestID(emailChangeConfirmIPLimit(
			handlers.EmailChangeConfirmHandler(emailChangeConfirmSvc, hybridVerifier)))),
	)
	mux.Handle("GET /api/v1/auth/email/change",
		middleware.Recover(middleware.RequestID(emailChangeConfirmIPLimit(
			handlers.EmailChangeConfirmHandler(emailChangeConfirmSvc, hybridVerifier)))),
	)
	// CU-SES-01: logout individual (abre Módulo 4).
	// Sin RequireAuth estricto: el handler acepta Bearer o {refresh_token}
	// alternativo; el servicio verifica firma aunque el jti esté denylisteado
	// (idempotencia) y exige exp futuro. Rate en el servicio
	// (logout:user 30/min + logout:ip 60/min vía limiter).
	// Env: LOGOUT_RATE=30/min (const auth.LogoutUserLimit).
	logoutCache := redisadapter.NewLogoutCache(rdb)
	logoutRevoker := postgres.NewSessionRevoker(pool, logoutCache,
		func(reason string) { log.Warn("logout redis fallback", slog.String("reason", reason)) })
	logoutMetrics := adapterhttp.NewPrometheusLogoutMetrics()
	logoutSvc := service.NewLogoutService(edSigner, logoutRevoker, limiter, idem,
		logoutMetrics, adapterhttp.NewOtelTracer())
	mux.Handle("POST /api/v1/auth/logout",
		middleware.Recover(middleware.RequestID(handlers.LogoutHandler(logoutSvc, secureCookies))),
	)
	// CU-SES-02: corte global (cierra Módulo 4 de sesiones).
	// Sin RequireAuth estricto: entra con Bearer de cualquier edad aunque el
	// llamante esté denylisteado o con valid_after viejo (el corte no espera).
	// Rate en el servicio (logout-global:user 5/hora + :ip 20/hora vía limiter).
	// Env: LOGOUT_GLOBAL_RATE=5/h (const auth.LogoutGlobalUserLimit).
	globalSweep := redisadapter.NewGlobalSweep(rdb)
	globalRevoker := postgres.NewGlobalRevoker(pool, globalSweep,
		func(reason string) { log.Warn("logout-global redis fallback", slog.String("reason", reason)) })
	globalMetrics := adapterhttp.NewPrometheusGlobalMetrics()
	globalSvc := service.NewLogoutGlobalService(edSigner, globalRevoker, limiter, idem,
		globalMetrics, adapterhttp.NewOtelTracer())
	mux.Handle("POST /api/v1/auth/logout-global",
		middleware.Recover(middleware.RequestID(handlers.LogoutGlobalHandler(globalSvc, secureCookies))),
	)
	// CU-SES-03: inventario + bisturí de sesiones propias (cierra Módulo 4).
	// Sin RequireAuth estricto (tolerante a denylisteado, igual SES-01/02);
	// rate en los servicios (list 60/min user+IP, revoke-one 20/hora user).
	// Touch best-effort con debounce 5min/sid (supuesto Q5).
	// Env: SESSIONS_RATE=* (consts auth.ListUserLimit/RevokeOneUserLimit).
	sessionLister := postgres.NewSessionLister(pool, redisadapter.NewSessionListCache(rdb),
		func(reason string) { log.Warn("sessions redis fallback", slog.String("reason", reason)) })
	sessionsMetrics := adapterhttp.NewPrometheusSessionsMetrics()
	listSvc := service.NewListSessionsService(edSigner, sessionLister, limiter, audit,
		sessionsMetrics, adapterhttp.NewOtelTracer())
	revokeOneSvc := service.NewRevokeSessionService(edSigner, sessionLister, limiter,
		sessionsMetrics, adapterhttp.NewOtelTracer())
	touchMw := middleware.SessionTouch(edSigner, sessionLister)
	mux.Handle("GET /api/v1/auth/sessions",
		middleware.Recover(middleware.RequestID(touchMw(handlers.SessionsListHandler(listSvc)))),
	)
	mux.Handle("DELETE /api/v1/auth/sessions/{sid}",
		middleware.Recover(middleware.RequestID(touchMw(handlers.RevokeOneHandler(revokeOneSvc)))),
	)
	// CU-SES-04: renovación por Refresh (cierra Módulo 4). Sin auth clásica:
	// el Refresh presentado manda (el Access expirado no bloquea renovar).
	// Rate en el servicio (refresh:ip 30/min + refresh:fam 10/min).
	// Env: ROTATE_GRACE=10s (const auth.GraceWindow).
	rotationCache := redisadapter.NewRotationCache(rdb)
	rotationStore := postgres.NewCombinedRotationStore(pool, rotationCache, globalRevoker,
		func(reason string) { log.Warn("rotation redis fallback", slog.String("reason", reason)) })
	rotationMetrics := adapterhttp.NewPrometheusRotationMetrics()
	rotateSvc := service.NewRotateService(rotationStore, edSigner, security.NewRefreshGenerator(),
		limiter, idem, audit, rotationMetrics, adapterhttp.NewOtelTracer())
	mux.Handle("POST /api/v1/auth/refresh",
		middleware.Recover(middleware.RequestID(handlers.RefreshHandler(rotateSvc, secureCookies))),
	)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		// CU-AUTH-04: chequea clave de firma cargada (fail-fast ya garantizado).
		if edSigner == nil || edSigner.ActiveKID() == "" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("no_signing_key"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.Handler())

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Info("api listening", slog.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("listen failed", slog.String("error", err.Error()))
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func verifyClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	return r.RemoteAddr
}

func redisAddr(url string) string {
	s := strings.TrimPrefix(url, "redis://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "localhost:6379"
	}
	return s
}
