# Plan de Implementación Técnica: CU-REG-01

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/user/` (entidad principal) + `internal/domain/auth/` (credenciales) + `internal/domain/shared/` (eventos).
* **Entidades / Value Objects:**
  * `internal/domain/user/user.go`:
    ```go
    type Status string // PENDING_VERIFICATION, ACTIVE, LOCKED, SOFT_DELETED
    type User struct {
      ID UUIDv7; EmailNormalized string; EmailOriginal string
      PasswordHash string // PHC $argon2id$v=19$...
      PasswordAlgo string // "argon2id"
      Status Status; TermsVersion string; PrivacyVersion string
      TermsAcceptedAt time.Time; CreatedAt time.Time; UpdatedAt time.Time
    }
    func NewUser(emailOriginal, emailNormalized, hash, termsV, privacyV string) (*User, error) // invariantes: email ≤254, hash non-empty, terms non-empty, status inicial PENDING
    func (u *User) CanAuthenticate() bool // solo ACTIVE
    ```
  * `internal/domain/user/email.go` (VO): `Normalize(raw string) (normalized, original string, err error)` — trim, lowercase folding, punycode IDN, regex `^[^\s@]+@[^\s@]+\.[^\s@]{2,}$`, rechaza control/null, máx 254 ASCII.
  * `internal/domain/auth/password.go` (VO): `Validate(plain, emailLocal string, breachedChecker) error` — 12..128 runas, clases may/min/dígito/símbolo, NFKC, no 4+ repetidos, no igual a local-part, HIBP vía interfaz.
  * `internal/domain/auth/verification_token.go`: `type VerificationToken struct { UserID string; TokenHash string; ExpiresAt time.Time; Attempts int; MaxAttempts=3; Consumed bool }`
* **Puertos de Salida (Interfaces del Dominio):**
  * `internal/domain/user/repository.go`:
    ```go
    type UserRepository interface {
      FindByEmailNormalized(ctx context.Context, email string) (*User, error) // ErrNotFound si no existe
      CreateWithOutbox(ctx context.Context, u *User, outboxEvents []shared.OutboxEvent) error // tx atómica, UNIQUE(email_normalized)
      FindByID(ctx context.Context, id string) (*User, error)
    }
    ```
    Fix email inicial (2026-10-07): las firmas reales vigentes
    `CreateWithOutbox(ctx, u, outbox, tokenHash, requestID)` y
    `CreateWithConsents(ctx, u, outbox, tokenHash, reg)` crecen con
    `mail *VerificationMail` final (nil = sin email, preserva llamadas viejas):
    ```go
    // internal/domain/user/verification_mail.go (nuevo, puro, sin infra)
    // Planos SOLO en memoria del request; el adapter persiste AMBOS hashes
    // (token + OTP en verification_tokens, si no el OTP del email inicial
    // no verificaría) y encola el email en la MISMA Tx.
    type VerificationMail struct {
      TokenPlain, TokenHash string
      OTPPlain, OTPHash     string
    }
    CreateWithOutbox(ctx, u, outbox, tokenHash, requestID string, mail *VerificationMail) error
    CreateWithConsents(ctx, u, outbox, tokenHash string, reg RegistrationContext, mail *VerificationMail) error
    ```
    El adapter persiste hashes + `INSERT email_queue` (link `frontURL/verify?token=` + OTP, plantilla idéntica al resend) en la MISMA Tx; si el INSERT falla → rollback total (fail-closed Q1). `NewUserRepository` gana `frontURL` (wiring en `cmd/api/main.go`, igual que el verification store).
  * `internal/domain/auth/hasher.go`:
    ```go
    type PasswordHasher interface { Hash(ctx context.Context, plain string) (string, error); Verify(ctx context.Context, plain, encodedHash string) (bool, error) }
    type BreachChecker interface { IsCompromised(ctx context.Context, password string) (bool, error) } // HIBP k-anonymity, timeout 800ms
    type VerificationTokenIssuer interface { Generate() (plainToken string, tokenHash string, err error); HashToken(plain string) string } // CSPRNG 32B, SHA-256 hex
    ```
  * `internal/domain/shared/events.go`:
    ```go
    type EventPublisher interface { Publish(ctx context.Context, e Event) error }
    type Event struct { EventID string; EventType string; OccurredAt time.Time; Key string; Payload any }
    type OutboxEvent struct { EventID, EventType, AggregateID, Topic string; PayloadJSON []byte; CreatedAt time.Time }
    type AuditLogger interface { Log(ctx context.Context, action string, fields map[string]string) }
    ```

### Capa de Aplicación (`internal/service/`)
* **Servicio / Caso de Uso:** `internal/service/register_user.go`
  * `type RegisterUserInput struct { EmailRaw, Password, TermsVersion, PrivacyVersion, RequestID, IP, UserAgent string; TermsAccepted bool }`
  * `type RegisterUserService struct { Users user.UserRepository; Hasher auth.PasswordHasher; Breach auth.BreachChecker; Tokens auth.VerificationTokenIssuer; Outbox OutboxStore(shared); Metrics MetricsPort; Tracer TracerPort }`
  * Inyección por constructor `NewRegisterUserService(...)` solo con interfaces de dominio. Sin imports a pgx, redis, kafka, gin/chi.
* **Flujo de Ejecución Orquestado:**
  1. Valida `RequestID` UUIDv4, `TermsAccepted==true`, delega a VO `email.Normalize` + `password.Validate` (si falla → `domain.ErrValidation`).
  2. Chequea idempotencia: `IdempotencyStore.Get(RequestID)` si hit → retorna respuesta cacheada (status + body hash) sin re-ejecutar.
  3. Intenta `Users.FindByEmailNormalized`. `found=true/false` se guarda pero NO ramifica respuesta; ambas ramas ejecutan `Hasher.Hash(dummyOrReal)` + `sleep jitter 80-120ms`.
  4. Si `found==true` → construye `OutboxEvent{auth.security.registration_attempted.v1}` (email seguridad) + retorna `Output{Status: Pending, IsShadowDuplicate: true}` (handler mapea a mismo 201).
  5. Si `found==false` → `Hasher.Hash(real)`, `Tokens.GeneratePair()` (token+OTP; el campo `Tokens` cambia de `auth.VerificationTokenIssuer` a `VerificationPairIssuer` service-local — el mismo `security.TokenIssuer` ya lo implementa, solo cambia el wiring de tipo en `main.go`; el `Generate()` solo-token cuyo plano se descartaba era la causa raíz del gap), `user.NewUser(...)`, `Users.CreateWithOutbox(user + [user.registered, email.verification_requested, audit], mail{TokenPlain, OTPPlain, ExpiresAt})` en tx (email_queue link+OTP en la misma Tx; fail-closed). Si `UniqueViolation` por carrera → trata como `found==true` (shadow). Rama shadow: sin email, con hash dummy + jitter (timing indistinguible; delta del INSERT solo en creación real, ≪ jitter — verificado en test).
  6. Instrumenta métrica + span + audit en todos los caminos + `initial_verification_email_total{queued|error}` (puerto `MetricsPort.IncInitialEmail`; distingue onboarding de resends). Nunca retorna `user_id` real al handler (solo `status`); el handler no distingue shadow.
  7. Errores tipados dominio: `ErrValidation`, `ErrRateLimited` (lanzado por middleware, no servicio), `ErrInfra` → handler mapea a HTTP.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler: `internal/adapter/http/handlers/register.go` — `func RegisterHandler(svc *service.RegisterUserService) http.HandlerFunc`: parse JSON (límite 32KB `http.MaxBytesReader`), valida `Content-Type`, exige `X-Request-ID`, llama servicio con `ctx = with trace_id`, mapea `ErrValidation→400`, `ErrRateLimited→429`, resto `→500` genérico. Siempre `Content-Type: application/json`.
  * DTO: `internal/adapter/http/dto/register_dto.go` — `RegisterRequest{Email string `+"`json:\"email\"`"+`, Password string `+"`json:\"password\"`"+`, TermsAccepted bool `+"`json:\"terms_accepted\"`"+`, TermsVersion string `+"`json:\"terms_version\"`"+`, PrivacyVersion string `+"`json:\"privacy_version\"`"+`}`, `RegisterResponse{Success bool, Data{Status string, Message string}}`, `ErrorResponse{Success false, Error{Code, Message, Details[]}}`.
  * Middleware: `internal/adapter/http/middleware/rate_limit.go` (Redis token bucket: `register:ip` 10/min, `register:email_hash` 3/hora, fail-open local), `request_id.go` (genera/valida UUIDv4, propaga a ctx), `recover.go` (panic→500 sin stack), `body_limit.go`.
  * Errors: `internal/adapter/http/errors/map.go` — `MapDomainError(err) (status int, code string)`.
  * Rutas: `cmd/api/main.go` → `POST /api/v1/auth/register` con cadena `recover → requestID → bodyLimit → rateLimit → handler`.
* **Salida (Persistencia):**
  * Postgres: `internal/adapter/persistencia/postgres/user_repository.go` (pgx/v5 + pgxpool): `FindByEmailNormalized` (`SELECT ... WHERE email_normalized=$1`), `CreateWithOutbox` (tx: `INSERT users + INSERT outbox + INSERT verification_tokens(hashed) + INSERT idempotency_keys`; `ON CONFLICT(email_normalized) DO NOTHING` → mapea a `ErrDuplicateShadow`).
  * Redis: `internal/adapter/persistencia/redis/rate_limiter.go` (go-redis, Lua sliding window, keys `rl:reg:ip:<ip>`, `rl:reg:email:<sha256>` con TTL). No guarda PII.
* **Salida (Mensajería):**
  * Kafka: `internal/adapter/colas/kafka/user_producer.go` (franz-go o sarama): lee outbox (`SELECT ... WHERE status='pending' FOR UPDATE SKIP LOCKED LIMIT 100`), publica a `auth.user.registered.v1` (key=user_id), `auth.email.verification_requested.v1`, `auth.audit.v1`, marca `sent`. Reintentos backoff + DLQ `auth.dlq.v1`. Consumido por worker `cmd/worker/main.go`.
* **Salida (Seguridad):**
  * `internal/adapter/security/argon2_hasher.go` (`golang.org/x/crypto/argon2`): `Hash` con `m=65536,t=3,p=4,salt 16B, out 32B, PHC`; `Verify` con `ConstantTimeCompare`. `hibp_breach_checker.go` (net/http, SHA-1, k-anonymity, timeout 800ms, cache negativa 1h en Redis). `token_issuer.go` (crypto/rand 32B + SHA-256 hex).
  * `internal/adapter/identity/` no se usa en este CU.

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `user_registration_total{status}` Counter; `user_registration_duration_seconds` Histogram; `hibp_fallback_total`; `outbox_lag_seconds` Gauge (worker); `argon2_hash_duration_seconds`. Declaradas en `internal/adapter/http/handlers/register.go` (o wrapper metrics) + `internal/service/register_user.go` vía `MetricsPort` (para testear sin Prometheus). Labels solo `status, route=/api/v1/auth/register`, nunca email/ip.
* **Tracing (OpenTelemetry):** Raíz `UseCase.RegisterUser` (service). Hijos: `domain.validate` (atributos `email.domain` solo dominio, no completo), `crypto.argon2id.hash`, `crypto.hibp.check`, `db.user.select`, `db.user.insert+outbox` (una tx), `cache.ratelimit.check`. Worker crea `Worker.PublishOutbox → kafka.produce(topic)`. Propaga W3C TraceContext + `X-Request-ID` como `request.id`.
* **Logs Estructurados:** `pkg/logger/` (slog JSON): claves obligatorias `trace_id, request_id, use_case=RegisterUser, action, duration_ms, status, ip_hash (SHA-256 /24), email_domain`. `INFO` éxito/shadow (sin distinguir en mensaje: `"registration accepted"`), `WARN` validation/rate-limit/hibp-fallback, `ERROR` db/outbox con `error.code=DB_UNAVAILABLE`. Prohibido `email` completo en INFO salvo `DEBUG` local; prohibido `password/hash/token` siempre. Muestreo: `password` nunca.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_001_create_users_outbox.up.sql` (+ `.down.sql` con DROP en orden inverso).
* **Definición de tablas, índices y restricciones:**
  ```sql
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
  CREATE TABLE users (
    id UUID PRIMARY KEY,
    email_normalized CITEXT NOT NULL UNIQUE,
    email_original TEXT NOT NULL,
    password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    password_algo TEXT NOT NULL DEFAULT 'argon2id',
    status TEXT NOT NULL CHECK (status IN ('PENDING_VERIFICATION','ACTIVE','LOCKED','SOFT_DELETED')) DEFAULT 'PENDING_VERIFICATION',
    terms_version TEXT NOT NULL, privacy_version TEXT NOT NULL,
    terms_accepted_at TIMESTAMPTZ NOT NULL, ip_hash TEXT, user_agent_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_users_status ON users(status);
  CREATE TABLE verification_tokens (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL,
    attempts INT NOT NULL DEFAULT 0, max_attempts INT NOT NULL DEFAULT 3,
    consumed BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, token_hash)
  );
  CREATE TABLE outbox (
    event_id UUID PRIMARY KEY, event_type TEXT NOT NULL, aggregate_id UUID NOT NULL,
    topic TEXT NOT NULL, payload JSONB NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), sent_at TIMESTAMPTZ
  );
  CREATE INDEX idx_outbox_status_created ON outbox(status, created_at) WHERE status='pending';
  CREATE TABLE idempotency_keys (
    request_id UUID PRIMARY KEY, response_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours'
  );
  ```
  Down: `DROP TABLE idempotency_keys, outbox, verification_tokens, users;`
  Datos: sin seed; `terms_version` validado en app contra tabla `legal_versions` (si existe) o constante `v2026.10`.

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** Dominio: `email_normalize_test.go` (casing, trim, IDN, >254, control), `password_validate_test.go` (12 clases, HIBP mock, local-part), `user_new_test.go` (invariantes). Servicio: `register_user_test.go` table-driven con mocks (gomock/mockery) para `UserRepository(always found/not-found/unique-race)`, `Hasher(dummy timing)`, `BreachChecker(timeout→fallback)`; asserts: shadow-duplicate mismo output que éxito, outbox con 2-3 eventos, `CanAuthenticate()==false`, idempotencia mismo RequestID no duplica. Cobertura objetivo ≥85% en `domain` + `service`.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/register_smoke.js`: 200 VUs, 5min, `POST /register` emails únicos + 10% duplicados; SLO p95 <500ms (incluye Argon2 64MB; si excede, bajar a `t=2` o escalar CPU), p99 <900ms, error rate <0.1% (excluye 429 esperados), chequeo timing: `|p50(success)-p50(duplicate)| <80ms`. Vegeta alternativo para unicidad concurrente (5 req mismo email, 1 fila). Redis/Kafka chaos: matar Kafka 2min → p95 HTTP intacto + outbox lag recupera <60s.
