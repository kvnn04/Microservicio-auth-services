# Plan de Implementación Técnica: CU-AUTH-06

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`step_up.go`).
* **Entidades / Value Objects:**
  ```go
  const StepUpMaxAge=5*time.Minute; const StepUpTokenTTL=5*time.Minute
  type StepUpScope string // cred:change-password, cred:change-email, mfa:disable, mfa:rotate, federated:link, federated:unlink, backup:regenerate, apikeys:write, account:delete, roles:change
  func (s StepUpScope) Valid() bool // lista cerrada
  type StepUpDecision string // FastPass | RequireChallenge | RequireRelogin
  func DecideStepUp(authTime time.Time, now time.Time, hasLocalFactors bool) StepUpDecision
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/stepup_ports.go
  type StepUpChallenger interface { CheckPassword(ctx context.Context, userID, password string) (bool, error); CheckSecondFactor(ctx context.Context, userID, code string) (bool, error) } // adapta Hasher+TOTP/Backup
  type StepUpIssuer interface { Issue(ctx context.Context, userID string, scope StepUpScope, amr []string) (token, jti string, err error) } // JWT aud=step-up 5min
  type StepUpVerifier interface { VerifyFor(ctx context.Context, bearerUserID, scope string, token string) error } // firma+aud+scope+sub+jti-single-use; ErrRequired|Invalid|Reused|Relogin
  ```
  Reuso `AttemptTracker` (fails/locks CU-AUTH-01), `EventPublisher/Outbox`, `AccessSigner` (firma con `aud` distinto).

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/step_up.go` (Challenge + Guard)
  * `Challenge(userID, authTime, scope, passwordOpt, codeOpt)`: `scope.Valid` (si no → `ErrUnknownScope`) → rate `step-up:challenge` (`ErrRateLimited`) → `DecideStepUp` (fresco? No emite aquí — el guard del op hace fast-pass; challenge con fresco igual emite si lo piden explícito? No: si fresco el front no debe llamar; si llama con fresco y desafíos OK emite igual (idempotente útil)) → valida factores exigidos (password si `hasPassword`, 2º si `mfa`, re-login si ninguno y stale → `ErrRelogin`) con dummy+jitter en fail + `RecordFail` (lock reuso) → `Issue` (jti+Redis `stepup:jti EX 300` + `ResetFails`) → `Output{token}`.
  * `Guard(callerUserID, bearerAuthTime, scope, headerToken)`: si `fresh` → `fast_pass` (sin Redis, offline); si no si `token==""` → `ErrRequired`; sino `VerifyFor` (firma+aud+scope+sub+jti-GET+DEL; reuso → `ErrReused`) → `token_ok`. Las ops llaman `Guard` al inicio (antes de su Tx).
  * Migración viejos: `RequireFreshAuth(5min)` en REG-06/MFA/backup se reemplaza por `Guard` (acepta fast-pass O token; flag `ENFORCE_STEP_UP_TOKEN` decide si fast-pass basta o token obligatorio por op — default fast-pass basta en MVP).
* **Flujo Orquestado:** scope→rate→factores→sign→single-use→output; guard→fresh?pass:verify+burn→ejecuta op. Idempotencia RequestID 60s en challenge (mismo scope+RequestID → mismo token si no usado).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler `handlers/step_up_challenge.go` (`POST /api/v1/auth/step-up/challenge {scope,password?,code?}` auth → `200 {step_up_token,scope,expires_in:300}` o `400/401/429/500`) + `middleware/require_step_up.go` (`Guard(scope)` genérico: lee `X-Step-Up-Token`, permite fast-pass, inyecta `step_up=fast_pass|token` en ctx, mapea `STEP_UP_REQUIRED/INVALID/REUSED/RELOGIN`) aplicado a las 8 ops (en este CU se cablea el middleware; las ops futuras lo declaran; las existentes REG-06/MFA/backup se recablean a él).
  * DTO `dto/step_up_dto.go`; `errors/map` (+`STEP_UP_REQUIRED/INVALID_STEP_UP/STEP_UP_REUSED/STEP_UP_REQUIRES_RELOGIN/UNKNOWN_SCOPE/STEP_UP_UNAVAILABLE`).
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/step-up/challenge` (auth+rate) + recableo guards.
* **Salida (Persistencia):**
  * Redis: `persistencia/redis/stepup_store.go` (`SET stepup:jti:<jti> {sub,scope} NX EX 300`, Lua `GET+DEL` en Verify, `step-up:challenge:<user>` sliding 10/min + `step-up:ip` 30/min; down → `ErrUnavailable` fail-closed (challenge/verify con token), fast-pass sigue sin Redis).
  * Postgres: reuso `users/mfa/backup` lecturas (sin tablas nuevas; `stepup_challenges` NO se crea — el jti vive en Redis + denylist 5min; si se exige DB-fallback se usa `mfa_challenges`-like efímera documentada opcional, no MVP).
* **Salida (Mensajería):** reuso `kafka` (`stepup.passed|failed|reused` → `auth.stepup.v1` + audit); sin SMTP propio (las ops envían sus avisos).
* **Salida (Seguridad):** reuso `ed25519_signer` con `aud=step-up` (mismo `kid`, distinto `aud`; verificación exige `aud` exacto en ambos mundos) + `argon2/totp/backup` verifiers (inyectados como `StepUpChallenger`).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `step_up_total{op, result=fast_pass|issued|used|required|invalid|reused|relogin|rate_limited|error}` + `step_up_duration_seconds` + `step_up_reuse_blocked_total`. Vía MetricsPort (servicio+guard).
* **Tracing (OpenTelemetry):** Raíces `UseCase.StepUpChallenge`, `Guard.StepUpCheck` (hijos `auth.freshness`, `ratelimit`, `crypto.verify(+totp)`, `lock.record|reset`, `crypto.sign`, `cache.jti.save|burn`, `outbox.insert`). Atributos `scope`, nunca secretos/token.
* **Logs Estructurados:** `pkg/logger`: `INFO stepup fast_pass/issued/used` (con `scope,jti`), `WARN required/invalid/reused/relogin/rate_limited`, `ERROR db/redis-unavailable`. Sin `password/code/token`.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_012_stepup_noop.up.sql` (+ down):
  ```sql
  -- CU-AUTH-06: sin tablas nuevas (jti en Redis EX 300; scopes son enum en código).
  -- Guarda de compatibilidad para ENFORCE_STEP_UP_TOKEN futuro:
  -- ALTER TABLE users ADD COLUMN IF NOT EXISTS stepup_enforced BOOLEAN NOT NULL DEFAULT FALSE;
  SELECT 1;
  ```
  Down: `SELECT 1;`. Redis `stepup:jti:* EX300`, `step-up:challenge:*` buckets (sin migración). Documenta recableo guards (código, no DB).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `step_up_test.go` (Decide fresco 4:59/5:01, scopes cerrados, sub/scope/jti mismatch) + servicio `step_up_test.go` table-driven con fakes (fresco→fast_pass sin token, stale+doble-ok→token 1 scope, password-mala→401 igual TOTP-mala, federated-stale→relogin, replay→reused, otra-op→invalid, RedisDown→unavailable pero fast-pass ok). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/stepup_smoke.js`: 50 VUs challenge (doble-ok/fallos, p95 <400ms con Argon2) + 100 VUs guards (fast-pass p95 <10ms offline, token-verify p95 <50ms Redis-hit), replay 100% `REUSED`, cross-scope 100% `INVALID`, Redis-down challenge/token `500` + fast-pass `200`, lock 5/15min → `401` hasta expirar. Chaos PG-down → `500` sin tokens.
