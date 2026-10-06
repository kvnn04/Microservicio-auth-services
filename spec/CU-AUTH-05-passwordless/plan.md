# Plan de Implementación Técnica: CU-AUTH-05

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`passwordless.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    PlessTTL=10*time.Minute; PlessTokenBytes=32; PlessOTPLen=8; PlessMaxAttempts=3
    PlessCooldown=60*time.Second; PlessMaxDay=5
  )
  type PlessContext struct { IPHash24, UAHash string }
  type PasswordlessRecord struct { UserID, TokenHash, OTPHash string; ExpiresAt time.Time; Attempts int; Consumed, Burned bool; Ctx PlessContext }
  func (r *PasswordlessRecord) Alive(now time.Time) bool
  func ParsePlessToken(raw string) (hash string, err error) // b64url 32B → sha256
  func ParsePlessOTP(raw string) (hash string, err error)   // 8d → sha256
  func RiskOf(emit, consume PlessContext) string // low|high (/16 + ua familia)
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/passwordless_ports.go
  type PasswordlessStore interface {
    Eligible(ctx context.Context, normalizedEmail string) (userID string, eligible bool, err error) // ACTIVE+verified (adapta UserRepository)
    Issue(ctx context.Context, rec *PasswordlessRecord) error // dual-write + supersede + quotas (ErrThrottled→202 genérico interno)
    FindAlive(ctx context.Context, hash string) (*PasswordlessRecord, error) // Redis→PG read-through; ErrNotFound
    ConsumeTx(ctx context.Context, userID, hash, challengeNote string) (risk string, err error) // Tx PG + DEL Redis + outbox; ErrInvalid|Burned
  }
  ```
  Reuso `SessionIssuer`, `MFAPreTokenIssuer` (rama MFA), `EventPublisher/Outbox`, `PasswordHasher` no.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/passwordless_start.go` + `passwordless_verify.go`
  * `Start(emailRaw, ip, ua, reqID)`: normaliza (malforma→`ErrValidation`) → `CheckLimits(start:ip/email)` (`ErrRateLimited`) → `Eligible` (guarda bool, no ramifica respuesta) → dummy+jitter 60-100ms siempre → si `eligible && quotas OK` → `Issue(nuevo par + ctx + supersede)` + outbox `requested` (si throttled/no-eligible → solo audit `not_sent`) → `Output{Sent:true}` genérico (el handler siempre `202`).
  * `Verify(tokenOrCode, ip, ua)`: parse (malforma→`ErrValidation`) → `CheckLimits(verify)` → `FindAlive` (miss→`ErrInvalid` + delay 40-80) → `ConstantTime` → `ConsumeTx` (quema 1 uso; 3º fail→burned) → `RiskOf` → si `mfa_enabled` → `MFA.IssueChallenge` → `mfa_required`; sino `Sessions.Issue(method=passwordless_email, amr=[email-otp])` → `active` (+ outbox `consumed` + `context_mismatch` si high). Idempotencia RequestID (replay mismo → mismo output sin re-emitir).
* **Flujo Orquestado:** forma→rate→lookup→dummy→(issue|noop)→202; forma→rate→find→compare→consume→risk→Issue/MFA→200/202. Nunca distingue elegibilidad en respuestas.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/passwordless_start.go` (`POST /passwordless/start` ≤2KB → `202 {if_exists_sent}`) + `passwordless_verify.go` (`POST /passwordless/verify {token|code}` + `GET /passwordless?token=` alias idempotente → `200/202` o `400 INVALID_OR_EXPIRED`).
  * DTO `dto/passwordless_dto.go`; middleware reuso rate (`pless:start:ip 10/h, :email 3/h, verify:ip 20/min, :tok 5/min`), `request_id`, `body_limit`, `no-store`.
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/passwordless/start|/verify`, `GET /passwordless`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/passwordless_store.go` (`passwordless_tokens(token_hash PK, otp_hash UNIQUE, user_id FK, expires_at, attempts, consumed, superseded, ctx_ip_hash, ctx_ua_hash, created_at)`, `Eligible` (`JOIN users ACTIVE+verified`), `Issue` Tx (supersede + INSERT + outbox), `ConsumeTx` Tx (`UPDATE consumed` + `UPDATE users last_login` + outbox `consumed+mismatch?`)).
  * Redis: `persistencia/redis/passwordless_store.go` (`pless:t/o/active/sent/count` EX 600/3600/86400, Lua consume DEL, quotas `SET NX`; down → PG + `pless_redis_fallback_total`).
* **Salida (Mensajería):** reuso `kafka` (`passwordless.requested|consumed` → `auth.passwordless.v1`, `security.context_mismatch` → `auth.security.*`, + audit); worker SMTP plantilla link+OTP 10min + aviso `si no fuiste tú` (+ alerta high-risk con IP/UA/hora).
* **Salida (Seguridad):** reuso `token_issuer` (32B+8d, SHA-256) + `RiskOf` helper (`ip/16` + `ua familia` via `ua-parser` ligero o prefijo, documentado heurístico no bloqueante).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `passwordless_total{op=start|verify, result=sent|throttled|not_eligible|success|mfa_required|invalid|rate_limited|error}` + duración + `pless_context_mismatch_total{risk=high}` + `pless_redis_fallback_total`. Vía MetricsPort + middleware.
* **Tracing (OpenTelemetry):** Raíces `UseCase.PasswordlessStart/Verify` (hijos `ratelimit`, `db.user.lookup`, `crypto.rand`, `cache+db.save|lookup|consume`, `ctx.compare`, `session|mfa.issue`, `outbox.insert`). Atributos `risk, ctx_match`, nunca secreto.
* **Logs Estructurados:** `pkg/logger`: `INFO pless sent/verify ok` (con `risk`), `WARN invalid/throttled/mismatch/fallback`, `ERROR db`. Sin `token/code/email` (hashes).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_011_passwordless.up.sql` (+ down):
  ```sql
  CREATE TABLE passwordless_tokens (
    token_hash TEXT PRIMARY KEY, otp_hash TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL, attempts INT NOT NULL DEFAULT 0,
    consumed BOOLEAN NOT NULL DEFAULT FALSE, superseded BOOLEAN NOT NULL DEFAULT FALSE,
    ctx_ip_hash TEXT NOT NULL, ctx_ua_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_pless_user_active ON passwordless_tokens(user_id) WHERE NOT consumed;
  CREATE INDEX idx_pless_otp ON passwordless_tokens(otp_hash) WHERE NOT consumed;
  ```
  Down: `DROP TABLE passwordless_tokens;`. Redis `pless:* EX600/3600/86400` (sin migración).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `passwordless_test.go` (parse 32B/8d, Alive TTL/burned, RiskOf /16+UA matriz, quotas) + servicio `passwordless_test.go` table-driven con fakes (eligible→sent+Mailhog, no-eligible/PENDING→202 sin correo idéntico, throttled cooldown/quota→202, verify ok→active/MFA, expirado/consumido/aleatorio→400 idénticos, 3º burn, replay RequestID, high-risk→email+mismatch). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/pless_smoke.js`: 50 VUs start (elegible/no-elegible 50/50, `|p50|<40ms`, `202` 100%) + 80 VUs verify (válidos/inválidos/replay, p95 <300ms hit / <700ms fallback, `400` idénticos) + quotas (2×30s→2º throttled, 6×24h simulado→6º throttled) + high-risk inyectado (IP-B) → `200` + `mismatch_total` +1. Chaos Redis/Kafka-down → `202/200` intactos; PG-down → `500` sin side-effects.
