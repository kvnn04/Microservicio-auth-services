# Plan de Implementación Técnica: CU-SEC-01

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`brute_force.go` — política central, sin I/O).
* **Entidades / Value Objects:**
  ```go
  const (
    MaxFails=5; FailWindow=15*time.Minute
    LockBase=15*time.Minute; LockCap=120*time.Minute; LockCountWindow=24*time.Hour
    NotifyThrottle=1*time.Hour
  )
  func Backoff(lockCount int) time.Duration // 15<<n cap 120
  func ShouldLock(fails int) bool // >=5
  func AccountKey(userID, emailHash string) string // user:<uuid> o acct:<sha256>
  ```
* **Puertos de Salida:** Reuso `AttemptTracker` (CU-AUTH-01: `CheckLimits` aquí SOLO cuenta (no rate IP — eso es SEC-02), `IsLocked`, `RecordFail→(lockedNow, backoff)`, `ResetOnSuccess`) + nuevo:
  ```go
  // internal/domain/auth/brute_policy.go
  type BruteNotifier interface { NotifyLock(ctx context.Context, userID, ipHash string, until time.Time) (throttled bool, err error) }
  ```
  (Implementado con `EventPublisher` + throttle Redis; inexistente → noop + audit.)

### Capa de Aplicación (`internal/service/`)
* **Servicio:** Sin servicio nuevo. `internal/service/brute_guard.go` (helper puro inyectado en `login`, `mfa_verify` (+backup), `step_up_challenge`, `change_password current`):
  * `PreCheck(tracker, accountKey) → locked bool` (1 GET; SIEMPRE sigue a verify/dummy homogéneo).
  * `PostFail(tracker, notifier, accountKey, userID?, flow)` → `RecordFail` (+ backoff/lock/email-throttle/outbox `brute.locked` + audit) → retorna `nil` (el llamador mapea a su `401` opaco).
  * `PostSuccess(tracker, accountKey)` → `ResetOnSuccess` (DEL fails/lock, conserva count día).
  * `OnRegisterCleanup(accountKey)` (llamado en CU-REG-01 éxito: `DEL fails/lock/count/notify` del `acct:hash` ciego).
* **Flujo Orquestado (en cada llamador):** forma→SEC-02-rate→`PreCheck`→verify/dummy+jitter→(`ok&&!locked`? `PostSuccess`+sigue : `PostFail`+`401` opaco). Nunca `423`, nunca `Retry-After` por lock.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):** Sin rutas nuevas (transversal). Cambios: inyectar `BruteGuard` en los 4 handlers/servicios + test `no-423` (assert que ningún flujo cubierto mapea lock a `423/429`) + `errors/map` (sin códigos nuevos salvo `BRUTE_LOCKED` INTERNO nunca al cliente).
* **Salida (Persistencia):**
  * Redis: `persistencia/redis/attempt_tracker.go` (formaliza CU-AUTH-01: `INCR fails:<key> EX 900` fixed-window + `GET lock:<key>` + `SET lock EX=backoff` + `INCR lock_count EX 86400` + `SET notify NX EX 3600`; Lua `record_fail.lua` atómica: INCR→check→SET lock+count+notify-flag en 1 round-trip; `accountKey` por `user_id` o `acct:sha256`; IP paralela `fails:ip` solo señal).
  * Postgres: sin tablas (solo audit vía outbox existente; `brute.locked` → `auth.security.*` + `auth.audit.v1`).
* **Salida (Mensajería):** `kafka` tipos `brute.locked` + audit `brute.check`; worker SMTP `brute_lock` (1er+throttle, con `hasta HH:MM` + IP/UA/hora + links) solo si `user_id` conocido.
* **Salida (Seguridad):** sin cripto nueva (reuso Argon2/TOTP dummies de cada flujo).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `failed_attempts_total{flow,locked}` + `brute_locks_total{flow_first}` + `brute_lock_duration_seconds` + `brute_redis_fallback_total` + `lock_notify_emails_total{throttled}`. Vía MetricsPort en `BruteGuard` + `AttemptTracker` adapter.
* **Tracing (OpenTelemetry):** Hijo `Defense.BruteCheck` (hijos `lock.check`, `fails.record|reset`, `notify.check`) en los 4 `UseCase.*`. Atributos `fails, backoff, locked`, nunca secreto/email.
* **Logs Estructurados:** `pkg/logger`: `WARN brute fail (flow, fails), lock_created (backoff)`, `INFO lock reset on success / register cleanup`, `ERROR redis-fallback`. Sin `password/code/email` (hashes).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_020_brute_noop.up.sql` (+ down):
  ```sql
  -- CU-SEC-01: sin tablas (Redis TTL + audit outbox). Verifica índice para limpieza por email_hash si se audita en PG:
  -- (sin-op; documenta fixed-window EX 900 y backoff 15-120 en comentarios para DBA)
  SELECT 1;
  ```
  Down: `SELECT 1;`. Redis keys `fails:<user|acct|ip> EX900`, `lock:<key> EX=backoff`, `lock_count:<key> EX86400`, `notify:<key> EX3600` (sin migración).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `brute_force_test.go` (Backoff 15/30/60/120/cap, ShouldLock borde 4/5, AccountKey) + `brute_guard_test.go` table-driven con fakes (5º bloquea+email 1, 6º igual 401, buena-en-lock 401, éxito resetea fails conserva count, multi-flujo suma, inexistente ciego sin email, register-cleanup). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/brute_smoke.js`: 50 VUs login-malas misma cuenta (5º lock, 6º+ `401` idénticos p50±40ms, 0 `423/429` por lock) + multi-flujo (2+2+1 → lock) + flood 100/min/IP (eso es SEC-02 `429`, no lock-cuenta) + Redis-down 60s (0 locks injustos + `WARN`) + backoff medido (15→30→60 tras re-locks simulados con `lock_count` pre-seed).
