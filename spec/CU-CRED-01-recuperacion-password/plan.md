# Plan de Implementación Técnica: CU-CRED-01

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`password_reset.go`) + `internal/domain/user/` (cambio + revocación).
* **Entidades / Value Objects:**
  ```go
  const (
    PwdResetTTL=15*time.Minute; PwdResetTokenBytes=32; PwdResetMaxAttempts=3
    PwdResetCooldown=60*time.Second; PwdResetMaxDay=5
  )
  type PasswordResetRecord struct { UserID, TokenHash string; ExpiresAt time.Time; Attempts int; Consumed, Burned bool; Ctx PlessContext } // reuso tipo ctx passwordless
  func (r *PasswordResetRecord) Alive(now time.Time) bool
  func ParseResetToken(raw string) (hash string, err error) // b64url 32B → sha256
  ```
  Reuso `Password.Validate` + `PasswordHasher` (CU-REG-01) + `PlessContext/RiskOf` (CU-AUTH-05).
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/password_reset_ports.go
  type PasswordResetStore interface {
    EligibleForReset(ctx context.Context, normalizedEmail string) (userID string, eligible bool, federatedHint bool, err error) // ACTIVE+hash? eligible : federated-only ACTIVE? hint
    QuotaCheck(ctx context.Context, key string) (allowed bool, retry time.Duration, err error) // 60s/5-24h por uid o anon:hash
    Issue(ctx context.Context, rec *PasswordResetRecord) error // dual-write + supersede + quotas (ErrThrottled→202 interno)
    IssueHint(ctx context.Context, userID, email string) error // aviso federated-only sin link
    FindAlive(ctx context.Context, hash string) (*PasswordResetRecord, *user.User, error) // Redis→PG read-through (+usuario para policy/hash)
    ConsumeTx(ctx context.Context, userID, hash, newHash, risk, curIPHash, curUAHash, requestID string) error // Tx: users(hash+valid_after)+token consumed+supersede+revoke sessions/families+outbox; ErrInvalid|Burned
    IncrementAttempts(ctx context.Context, hash string) (burned bool, err error) // abuso; al 3º quema
  }
  ```
  `newHash` lo calcula el servicio (Argon2id) antes de Tx. Contra TOCTOU (cambio
  concurrente entre lectura y escritura) la Tx usa `UPDATE … WHERE consumed=FALSE
  AND superseded=FALSE …` atómico: un consumo o supersedeo intermedio deja
  0 filas → `ErrInvalid`, y el re-chequeo `≠old` ya ocurrió pre-Tx en el
  servicio (ver `spec.md` §8 D-02). No viaja el plano a la Tx.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/password_reset_start.go` + `password_reset_confirm.go`
  * `Start(emailRaw, ip, ua, reqID)`: normaliza → `EligibleForReset` (guarda `eligible/hint`, no ramifica respuesta) → dummy+jitter → si `eligible && quotas` → `Issue` + outbox `requested` (+SMTP link); si `hint` → outbox `federated_hint` (email alternativo); sino solo audit → `Output{Sent:true}` genérico. (El rate por IP/email vive en handler/middleware.)
  * `Confirm(token, newPassword, confirmOpt, ip, ua)`: valida token forma + `confirm` match → `FindAlive` (miss→`ErrInvalid`+delay) → `ConstantTime` → policy (`Password.Validate` con parte local real + HIBP; policy-fail → `ErrPolicy` con details, SIN quemar token) → idempotencia → pre-chequeo `Verify(new, oldHash)` (si `true` → `ErrReused`, cuenta abuso sin quemar este intento) → `Hasher.Hash(new)` (Argon2id) → `ConsumeTx(newHash, risk, requestID)` (`UPDATE` condicional atómico + `tokens_valid_after=now` + revoke + outbox `changed+revoked_all+mismatch?` + email) → `Output{Changed:true}` (sin `Issue` sesión). El rate (`confirm:ip`, `:tok`) vive en handler/middleware; el orden forma→find→policy permite `EQUALS_EMAIL` (ver `spec.md` §8 D-01).
* **Flujo Orquestado:** forma→lookup→dummy→(issue|hint|noop)→202; forma→find→policy→idem→reused-check→hash→Tx consume+revoke→200. Idempotencia RequestID 24h (start no re-emite; confirm replay mismo RequestID → mismo `200` si ese RequestID consumió, sino `400`).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/password_reset_start.go` (`POST /password/reset/start` ≤2KB → `202`) + `password_reset_confirm.go` (`POST /password/reset/confirm {token,new_password[,confirm]}` ≤8KB → `200/400` + `GET /password/reset?token=` form siempre-`200`-si-formato (no consume, no revela)).
  * DTO `dto/password_reset_dto.go`; middleware reuso rate (`pwdreset:start:ip 10/h, :email 3/h, confirm:ip 20/min, :tok 5/min`), `request_id`, `body_limit`, `no-store`.
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/password/reset/start|/confirm`, `GET /password/reset`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/password_reset_store.go` (`password_reset_tokens(token_hash PK, user_id FK, expires_at, attempts, consumed, superseded, ctx_ip/ua, created_at)`, `EligibleForReset` (`ACTIVE && hash?` vs federated-hint), `Issue` Tx (supersede+INSERT+outbox), `ConsumeTx` Tx (`SELECT users FOR UPDATE` + re-Verify≠old + `UPDATE users(hash, valid_after)` + `UPDATE token consumed` + `UPDATE families revoked + DELETE sessions` + outbox `changed+revoked_all`)).
  * Redis: `persistencia/redis/password_reset_store.go` (`pwdreset:t/active/sent/count` EX 900/3600/86400, Lua DEL, quotas NX; down → PG + fallback).
* **Salida (Mensajería):** reuso `kafka` (`password.reset_requested|changed`, `session.revoked_all`, `security.context_mismatch?`, `federated_hint`, + audit); worker SMTP reset-link 15min + `password_changed` + `federated-hint` + `mismatch` (sin nueva clave en emails).
* **Salida (Seguridad):** reuso `argon2_hasher` (hash nuevo + Verify reused-check, pepper) + `hibp_checker` (policy) + `token_issuer` (32B) + `RiskOf`.

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `password_reset_total{op=start|confirm, result=sent|throttled|not_eligible|federated_hint|success|invalid|reused|policy_failed|rate_limited|error}` + duración + `pwdreset_mismatch_total` + `pwdreset_redis_fallback_total`. Vía MetricsPort + middleware.
* **Tracing (OpenTelemetry):** Raíces `UseCase.PasswordResetStart/Confirm` (hijos `ratelimit`, `db.user.lookup`, `crypto.rand`, `cache+db.save|lookup|consume`, `crypto.policy+hibp`, `crypto.argon2.hash`, `db.password.update+revoke`, `ctx.compare`, `outbox.insert`). Atributos `risk`, nunca token/clave.
* **Logs Estructurados:** `pkg/logger`: `INFO reset sent/changed` (con `risk`), `WARN invalid/reused/throttled/mismatch/fallback`, `ERROR db`. Sin `token/password/email` (hashes).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_013_password_reset.up.sql` (+ down):
  ```sql
  CREATE TABLE password_reset_tokens (
    token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL, attempts INT NOT NULL DEFAULT 0,
    consumed BOOLEAN NOT NULL DEFAULT FALSE, superseded BOOLEAN NOT NULL DEFAULT FALSE,
    ctx_ip_hash TEXT NOT NULL, ctx_ua_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_pwdreset_user_active ON password_reset_tokens(user_id) WHERE NOT consumed;
  ```
  Down: `DROP TABLE password_reset_tokens;`. Redis `pwdreset:*` (sin migración). Reuso `users.tokens_valid_after` (010) + `sessions/families` (010) para revoke (sin tablas nuevas de sesión).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `password_reset_test.go` (parse 32B, Alive, quotas) + servicio table-driven con fakes (eligible sent, no-eligible/PENDING/federated-hint 202 iguales, throttled, confirm ok+revoke, expirado/consumido/aleatorio 400 iguales, policy-fail sin quemar, reused sin quemar, 3º abuso burn, replay RequestID, high-risk mismatch). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/pwdreset_smoke.js`: 50 VUs start (4 grupos, `|p50|<40ms`, `202` 100%, Mailhog 1/4 grupos) + 80 VUs confirm (válidos/débiles/reusados/inválidos, policy no quema, p95 <500ms con Argon2, `400` idénticos) + revoke-verificación (viejos Access 401 por `valid_after`) + Redis/Kafka-down `202/200` intactos, PG-down `500` sin cambios.
