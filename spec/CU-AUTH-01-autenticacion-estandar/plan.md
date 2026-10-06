# Plan de Implementación Técnica: CU-AUTH-01

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (login) + `internal/domain/user/` (estado) + `internal/domain/shared/` (sesión abstracta).
* **Entidades / Value Objects:**
  * Reuso `User.CanAuthenticate()` (solo ACTIVE), `Email.Normalize`, `PasswordHasher.Verify` (CU-REG-01), `FederatedIdentity` (para `hasPassword = password_hash non-null`).
  * Nuevo `internal/domain/auth/login.go`:
    ```go
    const (
      LoginIPLimit=10; LoginIPWindow=time.Minute
      LoginAcctLimit=5; LoginAcctWindow=time.Minute
      MaxFails=5; FailWindow=15*time.Minute; LockBase=15*time.Minute // x1,x2,x4
      PreTokenTTL=5*time.Minute; DummyPassword="Dummy-Login-12ch!"
    )
    type LoginOutcome string // Success | MFARequired | Invalid (opaco)
    type Device struct { IPHash, UAHash string }
    func DecideLogin(found, verifyOK, locked bool, status user.Status, mfa bool) LoginOutcome
    func ShouldLock(fails int) bool // >=5
    func LockDuration(lockCount int) time.Duration // 15,30,60...
    ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/authenticator.go
  type CredentialStore interface { FindForLogin(ctx context.Context, normalizedEmail string) (*user.User, error) } // adapta UserRepository + ErrNotFound→opaco
  type AttemptTracker interface {
    CheckLimits(ctx context.Context, ip, acctHash string) error // ErrRateLimited (429) si ip/account por minuto
    IsLocked(ctx context.Context, key string) (locked bool, err error)
    RecordFail(ctx context.Context, key, emailHash, userID string) (lockedNow bool, err error) // INCR + lock exponencial + email-throttle flag
    ResetOnSuccess(ctx context.Context, key string) error // DEL fails/lock
  }
  type SessionIssuer interface { Issue(ctx context.Context, u *user.User, d Device) (cookies map[string]string, err error) } // CU-AUTH-04 implementa
  type MFAPreTokenIssuer interface { IssueChallenge(ctx context.Context, u *user.User) (token string, challengeID string, err error) } // aud=mfa-challenge 5min
  ```
  Reuso `PasswordHasher`, `EventPublisher/OutboxStore/AuditLogger`.

### Capa de Aplicación (`internal/service/`)
* **Servicio / Caso de Uso:** `internal/service/login.go`
  * `type LoginInput struct { EmailRaw, Password, RequestID, IP, UserAgent string }`
  * `type LoginService struct { Creds CredentialStore; Hasher auth.PasswordHasher; Tracker AttemptTracker; Sessions SessionIssuer; MFA MFAPreTokenIssuer; Outbox OutboxStore; Metrics/Tracer }`
* **Flujo de Ejecución Orquestado:**
  1. Normaliza email (VO; malforma → `ErrValidation`). Idempotencia RequestID (replay misma respuesta sin duplicar fails/outbox — `IdempotencyStore` 24h).
  2. `Tracker.CheckLimits(ip, acctHash)` (Redis; excede → `ErrRateLimited`, sin DB/hash).
  3. `Creds.FindForLogin` (miss → `found=false, user=nil`; hit → `user`). `lockKey = user.ID o acct:<hash>`; `Tracker.IsLocked` (Redis miss/error → `false` fail-open + `WARN`).
  4. `Verify`: si `found && hash non-null` → `Hasher.Verify(real)`; sino `Hasher.Hash(Dummy)` descartado. `SleepJitter(80,120)` SIEMPRE en camino secreto/estado (no en `400/429`).
  5. `DecideLogin(...)`: `ok = found && verify && !locked && status==ACTIVE`. Si `!ok` → `Tracker.RecordFail` (INCR/posible lock+email flag) + `ErrInvalidCredentials` opaco + audit `failed(reason_internal)` + métrica `invalid` (el servicio NO revela reason al handler).
  6. Si `ok`: `Tracker.ResetOnSuccess` + si `!mfa` → `Sessions.Issue` → `Output{Status:active, Cookies}`; si `mfa` → `MFA.IssueChallenge` → `Output{Status:mfa_required, Token}`. Outbox `login.success|mfa_challenged` + audit. Nunca ambos.
  7. Errores tipados: `ErrValidation→400`, `ErrRateLimited→429`, `ErrInvalidCredentials→401` (único), `ErrInfra→500`.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler `handlers/login.go` (`POST /api/v1/auth/login`, `MaxBytes 32KB`, exige `X-Request-ID` laxo, `Cache-Control: no-store`, mapea solo 400/401/429/500 — veta `403/404/409/422/423` con assert test).
  * DTO `dto/login_dto.go` (`LoginRequest{email,password}`, `LoginSuccessResponse{status:active}`, `MFARequiredResponse{status:mfa_required,mfa_token,methods:[totp],expires_in:300}`, `ErrorResponse` estándar).
  * Middleware reuso `rate_limit` (+buckets `login:ip`, `login:account`), `request_id`, `recover`, `body_limit`.
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/login` con cadena estándar.
* **Salida (Persistencia):**
  * Postgres: reuso `user_repository.go` (`SELECT ... WHERE email_normalized=$1`, `statement_timeout 2s`).
  * Redis: `persistencia/redis/login_tracker.go` (Lua sliding `login:ip:<ip>` 10/min, `login:account:<sha256>` 5/min; `INCR fails:<key> EX 900`, a 5 → `SET lock:<key> {until} EX 900/1800/3600` por `lock_count:<key>` + `SET notify:lock:<key> NX EX 3600` para email 1/h; fail-open memoria 2x si down).
* **Salida (Mensajería):** reuso `kafka/user_producer.go` + tipos `login.success|mfa_challenged|login.failed|login.locked` → `auth.login.v1` + `auth.audit.v1 {action:login.attempt}`; email `security.login_lock` vía worker SMTP (throttle 1/h).
* **Salida (Seguridad):** reuso `argon2_hasher` (Verify/Hash dummy mismos `m/t/p` + pepper) + nuevo `security/mfa_pretoken_issuer.go` (JWT `aud=mfa-challenge`, `sub, challenge_id, methods`, `exp 5min`, firmado `sessions-key`; validado SOLO en CU-AUTH-02, rechazado en middleware negocio por `aud`). `SessionIssuer` lo implementa CU-AUTH-04 (aquí solo puerto + fake en tests).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `login_total{result=success|mfa_required|invalid|rate_limited|error}` + `login_duration_seconds` + `login_failures_total{reason_internal}` (privada) + `login_locks_total` + `login_lock_emails_total{throttled}`. Vía MetricsPort (servicio) + middleware (429).
* **Tracing (OpenTelemetry):** Raíz `UseCase.Login` (hijos `ratelimit.check`, `db.user.select_by_email`, `lock.check`, `crypto.argon2.verify|dummy`, `lock.record|reset`, `mfa.branch`, `session.issue|mfa.issue`, `outbox.insert`). Atributos `email.domain, mfa_enabled`, nunca password.
* **Logs Estructurados:** `pkg/logger`: `INFO login success|mfa_challenged` (con `user_id, email_domain`), `WARN invalid_credentials (email_hash, reason_internal solo interno), rate_limited, lock_created`, `ERROR db_unavailable`. Sin password/hash/tokens.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_007_login_mfa_flag.up.sql` (+ down):
  ```sql
  ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
  -- secreto TOTP real vive en tabla CU-AUTH-02 (aquí solo flag denormalizado para bifurcar sin JOIN):
  -- CREATE TABLE IF NOT EXISTS mfa_totp_secrets (...) se crea en 008; este script solo añade flag + índice parcial:
  CREATE INDEX IF NOT EXISTS idx_users_mfa ON users(id) WHERE mfa_enabled;
  ```
  Down: `DROP INDEX ...; ALTER TABLE users DROP COLUMN mfa_enabled;`. Redis claves `login:ip:<ip>`, `login:account:<sha256>`, `fails:<user|acct>`, `lock:<key>`, `lock_count:<key>`, `notify:lock:<key>` (todas TTL, sin migración).
  `mfa_enabled` se setea en CU-AUTH-02 (aquí default false; backfill 0 filas).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** Dominio `login_test.go` (Decide/ShouldLock/LockDuration matriz, PENDING/LOCKED→Invalid, federated-null→Invalid). Servicio `login_test.go` table-driven con fakes (éxito→Issue, mfa→Challenge, 4 malos→mismo ErrInvalid, lock→sigue Invalid, replay RequestID no duplica fails, RedisDown fail-open). `go test -race` verde, cobertura ≥85%.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/login_smoke.js`: 150 VUs 4min (70% buenas sin-MFA, 20% malas, 10% MFA) + timing-suite (100×nonexist vs 100×wrong vs 100×pending → `|p50|<80ms` bloqueante); p95 <500ms (Argon2), p99 <900ms; abuse-suite (6 malas/15min → lock opaco + 7ª buena 401; 11/min/IP → 429). Chaos Redis-down/Kafka-down → 200/202/401 intactos + métricas fallback; PG-down → 100% 500 sin side-effects.
