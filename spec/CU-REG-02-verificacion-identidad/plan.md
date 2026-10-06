# Plan de Implementación Técnica: CU-REG-02

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (secretos) + `internal/domain/user/` (transición estado) + `internal/domain/shared/` (eventos). Reutiliza `User` de CU-REG-01 sin modificar su schema público (solo añade método).
* **Entidades / Value Objects:**
  * `internal/domain/user/user.go` (+método): `func (u *User) Activate() error // solo si Status==PENDING_VERIFICATION, sino ErrInvalidTransition`
  * `internal/domain/auth/verification.go` (nuevo):
    ```go
    const TokenBytes=32; const OTPLen=8; const TTL=15*time.Minute; const MaxAttempts=3
    type VerificationRecord struct { UserID, TokenHash, OTPHash string; ExpiresAt time.Time; Attempts int; Consumed bool; ActivatedBy *string }
    func (v *VerificationRecord) IsAlive(now time.Time) bool // !Consumed && Attempts<3 && now.Before(ExpiresAt)
    func (v *VerificationRecord) CanAttempt() bool
    func ParseTokenInput(raw string) (hash string, typ string, err error) // base64url 32B -> sha256hex, type=link
    func ParseOTPInput(raw string) (hash string, err error) // ^[0-9]{8}$ -> sha256hex
    ```
  * Puertos (aditivos a CU-REG-01, sin romper):
    ```go
    // internal/domain/auth/verifier.go
    type VerificationStore interface {
      FindAlive(ctx context.Context, hash string) (*VerificationRecord, error) // ErrNotFound si no hay vigente
      ConsumeAtomically(ctx context.Context, userID, hash string, method string) (*User, error) // Tx: users->ACTIVE + tokens consumed + supersede + outbox. ErrAlreadyConsumed/ErrExpired/ErrBurned
      Register(ctx context.Context, rec *VerificationRecord, supersedeUserID string) error // dual-write + supersede anterior
      IncrementAttempts(ctx context.Context, hash string) (left int, burned bool, err error)
      ResendQuotaCheck(ctx context.Context, userID string) (allowed bool, retryAfter int, err error)
    }
    ```
    Reutiliza de CU-REG-01: `user.UserRepository.FindByID`, `shared.OutboxStore`, `shared.AuditLogger`.

### Capa de Aplicación (`internal/service/`)
* **Servicio / Caso de Uso:** `internal/service/verify_email.go` + `internal/service/resend_verification.go`
  * `type VerifyEmailInput struct { TokenOrCode, RequestID, IP string; Method string }` — el handler resuelve si es `link` u `otp` por forma, el servicio recibe `hash + method`.
  * `type VerifyEmailService struct { Store auth.VerificationStore; Users user.UserRepository; Metrics MetricsPort; Tracer TracerPort }`
  * `type ResendService struct { Users user.UserRepository; Store auth.VerificationStore; Mailer OutboxStore; }`
* **Flujo de Ejecución Orquestado (verify):**
  1. Valida forma (VO Parse). Si malforma → `ErrValidation` (único `400` distinto).
  2. Idempotencia: `IdempotencyStore.Get(RequestID)` hit → replay misma respuesta.
  3. `Store.FindAlive(hash)`: adapta Redis-verdad + Postgres-backup (ver adaptadores). Si `ErrNotFound` → chequea idempotencia de activador: `Store.WasActivatedBy(hash)` si true y user ACTIVE → `Output{AlreadyVerified:true}`; sino `ErrInvalidOrExpired` + delay 40-80ms + métrica `invalid_or_expired`.
  4. `ConstantTimeCompare` (defensa, aunque el lookup ya filtró) → si mismatch (solo posible en path `user_id+code` o HMAC) → `IncrementAttempts`, si burned → `ErrInvalidOrExpired` + `attempts_burned_total`.
  5. `ConsumeAtomically(userID, hash, method)`: Tx Postgres + invalidación Redis Lua en el adapter (el servicio solo llama al puerto; la atomicidad cross-store la garantiza el adapter con patrón write-through + compensación: primero Tx Postgres `WHERE consumed=false`, si 0 filas → `ErrInvalidOrExpired`; si 1 fila → `DEL` Redis, si Redis DEL falla → log WARN + job reconciliador, NO revierte Tx).
  6. Retorna `Output{Status: active|already_verified}`. Instrumenta span + métrica + audit (sin secreto).
  7. (resend): `FindByEmailNormalized` (reutiliza CU-REG-01, respuesta siempre genérica) → si PENDING + quota OK → `Register(nuevo par + supersede)` + outbox `verification_requested`; si ACTIVE/inexistente/cooldown/cuota → no-op + `202` genérico + `resend_throttled_total` si throttled.
* **Errores tipados dominio:** `ErrValidation`, `ErrInvalidOrExpired` (→400 genérico), `ErrRateLimited` (middleware), `ErrInfra` (→500). Prohibido `ErrExpiredDistintoDeInvalid` hacia el handler (el servicio nunca distingue).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler: `internal/adapter/http/handlers/verify_email.go` — `POST /api/v1/auth/verify-email` (`{token? , code?}` exactamente uno) + `GET /api/v1/auth/verify-email?token=` alias (misma lógica, `Cache-Control: no-store`, sin cache). `dto/verify_dto.go`: `VerifyRequest{Token *string, Code *string}`, `VerifyResponse{Status: active|already_verified}`, `ResendRequest{Email}`, `ResendResponse{status:if_exists_verification_sent}`. `handlers/resend_verification.go` para `POST /api/v1/auth/resend-verification`.
  * Middleware: reutiliza `rate_limit.go` con buckets nuevos `verify:ip` 10/min + `verify:tok` 5/min (Redis Lua, fail-open local 2x) + `request_id.go` + `body_limit.go` (4KB verify, 2KB resend).
  * Errors: `errors/map.go` añade `ErrInvalidOrExpired→400 INVALID_OR_EXPIRED` (mensaje fijo spec), `AlreadyVerified→200` (no error).
  * Rutas `cmd/api/main.go`: `POST /verify-email`, `GET /verify-email`, `POST /resend-verification` en grupo `/api/v1/auth`.
* **Salida (Persistencia) — decisión Q5 Redis-como-verdad + Postgres-backup:**
  * Redis: `internal/adapter/persistencia/redis/verification_store.go` (go-redis + Lua):
    * Escritura (dual-write, llamada desde `Register`): `SET verify:t:<token_hash> {user_id, otp_hash, exp} EX 900 NX` + `SET verify:o:<otp_hash> <token_hash> EX 900 NX` + `SET verify:active:<user_id> <token_hash> EX 900` (sobrescribe, el viejo se DEL explícito supersede) + `SET verify:sent:<user_id> now EX 86400` + `INCR verify:resends:<user_id_day>` para cuota.
    * Lectura fast-path: `GET verify:t/o`; si hit y no expirado (TTL>0) → retorna record (hidrata `Attempts` desde `verify:att:<hash>` o Postgres si falta).
    * Consumo: script Lua `consume.lua`: `if GET==expected then DEL t/o/active/att else return 0` (atómico).
    * Contadores: `INCR verify:att:<hash> EX 900`, a 3 → marca quemado (publica a Postgres vía `IncrementAttempts` sync o reconciliador 1s).
    * Caída/evicción: cualquier `RedisDown` o `nil` → `verify_redis_fallback_total` + delega a Postgres (failover, no `400` directo).
  * Postgres: `internal/adapter/persistencia/postgres/verification_repository.go` (pgxpool):
    * `verification_tokens(token_hash PK, otp_hash UNIQUE, user_id FK, expires_at, attempts, max_attempts=3, consumed, superseded, activated_by, created_at)` — creada en CU-REG-01, aquí se añade columna `otp_hash` vía migración 002 + índice `idx_vtokens_otp`.
    * `FindAlive`: `SELECT ... WHERE (token_hash=$1 OR otp_hash=$1) AND consumed=false AND expires_at>now() AND attempts<3 FOR UPDATE` (en Tx de consumo) o `SELECT` simple en lectura.
    * `ConsumeAtomically`: Tx `SERIALIZABLE`: `UPDATE users SET status='ACTIVE' WHERE id=$1 AND status='PENDING_VERIFICATION'` (si 0 filas y user ya ACTIVE → chequea `activated_by` para idempotencia) + `UPDATE verification_tokens SET consumed=true WHERE ... AND consumed=false` (si 0 → `ErrInvalidOrExpired`, maneja carrera) + `UPDATE ... SET superseded=true WHERE user_id=$1 AND consumed=false AND token_hash<>$1` + `INSERT outbox x2`. `RETURNING` para confirmar.
    * Implementación `VerificationStore` combina ambos: `FindAlive` = Redis-hit? Redis : Postgres-read-through-rehidrata; `ConsumeAtomically` = Postgres-Tx-primero + Redis-DEL-después (write-through con reconciliación por worker cada 10s que re-DEL huérfanos y rehidrata misses).
* **Salida (Mensajería):**
  * Kafka: reutiliza `colas/kafka/user_producer.go` (sin cambios de API): nuevos `event_type` `user.activated`, `user.verify_failed`, `user.verification_resent` a tópicos `auth.user.activated.v1` + `auth.audit.v1`. Worker `cmd/worker` ya los drena (añade handler SMTP para `verification_requested` con plantilla link+OTP).
* **Salida (Seguridad):**
  * Reutiliza `security/token_issuer.go` (+ `GeneratePair() (tokenPlain b64url, tokenHash, otpPlain 8d, otpHash, err)`) — `crypto/rand` 32B + `crypto/rand` Int 1e8. Comparación `subtle.ConstantTimeCompare` en adapter (defensa en profundidad aunque el servicio también).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `email_verification_total{result}` (success, already_verified, invalid_or_expired, validation_failed, rate_limited, error), `email_verification_duration_seconds`, `verification_resends_total{outcome=queued|throttled}`, `verification_attempts_burned_total`, `verify_redis_fallback_total{reason=miss|down}`. Puerto `MetricsPort` en servicio; `rate-limit 429` contado en middleware. Labels sin PII (solo `result, method=link|otp`).
* **Tracing (OpenTelemetry):** Raíz `UseCase.VerifyEmail` / `UseCase.ResendVerification`. Hijos: `cache.verify.lookup (redis.hit|miss|down)`, `db.token.select`, `db.token.consume (tx)`, `crypto.compare`, `cache.verify.invalidate`, `outbox.insert`, `kafka.produce` (worker). Propaga `trace_id` + `X-Request-ID`. Atributo `token.type` sí, secreto nunca.
* **Logs Estructurados:** `pkg/logger` slog JSON: `trace_id, request_id, use_case=VerifyEmail, method, result, duration_ms, attempts_left?, redis_path=hit|fallback`. `INFO` success/already_verified/resend_queued (genérico), `WARN` invalid_or_expired/rate_limited/throttled/fallback, `ERROR` db-tx/outbox. Prohibido `token/code/email/token_hash?` — `token_hash/otp_hash` permitidos solo en `DEBUG` local, nunca en `INFO` prod; `email` solo hash.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_002_verify_otp.up.sql` (+ down):
  ```sql
  ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS otp_hash TEXT UNIQUE;
  ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS superseded BOOLEAN NOT NULL DEFAULT FALSE;
  ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS burned_reason TEXT;
  ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS activated_by TEXT;
  ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;
  CREATE INDEX IF NOT EXISTS idx_vtokens_otp ON verification_tokens(otp_hash) WHERE consumed=false;
  CREATE INDEX IF NOT EXISTS idx_vtokens_user_active ON verification_tokens(user_id) WHERE consumed=false;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS activated_method TEXT CHECK (activated_method IN ('link','otp', NULL));
  ```
  Down: `DROP INDEX ...; ALTER TABLE ... DROP COLUMN ...;` (sin tocar datos CU-REG-01).
  Redis: sin migración (claves efímeras TTL 900s + 86400s resends). Documenta `verify:t:<sha256hex>`, `verify:o:<sha256hex>`, `verify:active:<uuid>`, `verify:att:<sha256hex>`, `verify:sent:<uuid>`, `verify:resends:<uuid>:<yyyy-mm-dd>`.
* **Backfill CU-REG-01:** tokens creados solo con `token_hash` (sin `otp_hash`) siguen válidos 15min: el worker de reconciliación les asigna OTP bajo demanda en reenvío, o se aceptan solo por link hasta expirar (documentado, sin backfill masivo).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** Dominio `verification_test.go` (Parse link 32B OK / 31B reject / OTP 7 vs 8 dígitos, IsAlive TTL/burned/consumed, Activate transición PENDING→ACTIVE vs ACTIVE→error). Servicio `verify_email_test.go` table-driven con mocks `VerificationStore`: link OK activa + supersede, OTP OK quema link, expirado/consumido/inexistente → mismo `ErrInvalidOrExpired`, carrera (Consume 0 filas → ErrInvalidOrExpired), idempotencia RequestID replay, resend cooldown/cuota/supersede. `go test ./internal/domain/... ./internal/service/... -race` verde, cobertura ≥85%.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/verify_smoke.js`: 100 VUs 3min mixto 70% link válido, 20% inválido aleatorio, 10% reuso (idempotencia); SLO p95 <300ms (Redis hit) / <800ms (fallback Postgres), p99 <600ms/<1200ms, `|p50(valid)-p50(invalid)|<40ms` (anti-oráculo), error `invalid_or_expired` esperado no cuenta como SLO fail. Chaos: `redis-cli DEBUG sleep` / matar Redis 60s → 100% `200` válidos vía fallback + `verify_redis_fallback_total` sube; matar Kafka 2min → `200` intacto + lag recupera <60s.
