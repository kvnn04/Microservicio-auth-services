# Plan de Implementación Técnica: CU-REG-03

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/user/` (reuso) + `internal/domain/shared/` (eventos). Sin entidades nuevas.
* **Entidades / Value Objects:** Reuso total CU-REG-01: `User`, `Email.Normalize`, `Password.Validate`. Nuevo VO ligero `internal/domain/user/uniqueness.go`:
  ```go
  type ProbeOutcome string // Unique | ShadowDuplicate | ThrottledNotify
  type UniquenessResult struct { NormalizedEmail, EmailHash, Domain string; Found bool; NotifyAllowed bool }
  func DecideProbe(found bool, notifyAllowed bool) ProbeOutcome
  ```
  Invariante: el dominio NUNCA decide mensajes HTTP (solo `Found` + `NotifyAllowed`); el handler mapea a genérico.
* **Puertos de Salida (Interfaces del Dominio):**
  ```go
  // internal/domain/user/uniqueness.go (aditivo, sin romper UserRepository)
  type UniquenessChecker interface {
    Probe(ctx context.Context, normalizedEmail string) (found bool, userID *string, err error) // SELECT id,status; ErrInfra si DB cae
  }
  type NotifyThrottle interface {
    AllowOwnerNotify(ctx context.Context, emailHash string) (allowed bool, err error) // 1/hora + 3/día; fail-open true si store cae
  }
  ```
  Implementación por defecto adapta `UserRepository.FindByEmailNormalized` (found = err!=ErrNotFound) + `EventPublisher.Publish(security.registration_attempted)` vía `shared`. Sin imports infra.

### Capa de Aplicación (`internal/service/`)
* **Servicio / Caso de Uso:** Sin servicio nuevo. Se integra como paso en `internal/service/register_user.go` (CU-REG-01) y `resend_verification.go` (CU-REG-02):
  ```go
  // dentro de RegisterUserService.Execute, tras Validate + RateLimit:
  found, ownerID := s.Uniqueness.Probe(ctx, normalized) // o Users.FindByEmailNormalized adaptado
  s.Crypto.DummyHash(ctx) // Argon2id real sobre dummy 12ch, SIEMPRE
  SleepJitter(80,120)     // SIEMPRE, ambas ramas
  if found { s.Throttle.AllowOwnerNotify + s.Outbox.Enqueue(security.registration_attempted + audit) ; return Output{PendingShadow:true} }
  // else continúa creación normal
  ```
  `internal/service/uniqueness_policy.go` (nuevo, testeable): `func ShouldNotify(found, throttleAllowed bool) bool`, `func GenericRegisterOutput() Output`, cómputo `EmailHash=sha256hex`, `IPHash`.
* **Flujo de Ejecución Orquestado:** validar forma → rate-limit (middleware) → `Probe` (PG) → `DummyHash + jitter` (siempre) → ramifica solo internamente (outbox notify si found+throttle) → retorna output genérico idéntico. `resend` idéntico con `202`. Errores: `ErrValidation` (forma) →400; `ErrInfra` (PG) →500; nunca `ErrDuplicate` al exterior.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):** SIN rutas nuevas. Cambios en existentes:
  * `handlers/register.go` + `handlers/resend_verification.go`: garantizan mismo schema/headers (audita con `diff` test que `unique_body == shadow_body` salvo RequestID), `Cache-Control: no-store`, sin `user_id/email` en respuesta.
  * `middleware/rate_limit.go` (+buckets): `register:ip:<ip>` 10/min, `register:email:<sha256>` 3/hora, `resend:ip` 10/hora (Lua sliding window, `go-redis`), progresivo `announcer:ip` (cuenta 429, a 50/15min → `SET blocked:ip:<ip> EX 900`), `blocked` chequeado primero (→429 largo). Fail-open local 2x si Redis down (token bucket memoria por instancia + `WARN`).
  * `errors/map.go`: veta mapear cualquier error a `409/422` en estos flujos (assert en test).
* **Salida (Persistencia):**
  * Postgres: reuso `persistencia/postgres/user_repository.go` (`SELECT id,status WHERE email_normalized=$1`, usa `UNIQUE` existente, `statement_timeout=2s`). Sin migración de negocio: `scripts/migrations/20261005_003_uniqueness_noop.up.sql` con comentario + (opcional, si se elige forense) `CREATE TABLE uniqueness_probes (...)` — por defecto NO se crea (decisión Q6 reuso); el archivo documenta por qué es noop.
  * Redis: `persistencia/redis/notify_throttle.go` (`SET notify:email_hash:<sha256> NX EX 3600` + `INCR notify:day:<sha256>:<yyyy-mm-dd> EX 86400`, permite si `hour_missing && day_count<=3`) + contadores rate-limit + `blocked:ip`. Fail-open: si `RedisDown` → `AllowOwnerNotify=true` (una vez) + `WARN` + métrica fallback.
* **Salida (Mensajería):**
  * Kafka: reuso `colas/kafka/user_producer.go`: nuevo `event_type` `security.registration_attempted` a tópico `auth.security.registration_attempted.v1` (key=`email_hash`) + `auth.audit.v1` (`action=uniqueness.probe`). Worker SMTP plantilla `security_attempted.html` (asunto/cuerpo 5. RN, links login/forgot, sin token). Backoff + DLQ heredados.
* **Salida (Seguridad):** reuso `security/argon2_hasher.go` para dummy (`Hash("Dummy-Probe-12ch!")` con mismos `m/t/p`, resultado descartado pero tiempo real).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `uniqueness_probes_total{outcome=unique|shadow_duplicate|throttled_notify|error}` (servicio vía `MetricsPort`), `notify_owner_enqueued_total{throttled}`, `ip_blocks_total`, `uniqueness_redis_fallback_total{reason}`. NUNCA exponer `found` al cliente; dashboard privado + alerta `rate(shadow_duplicate[1m])>100 por /24` → pager/Slack. Labels sin email/IP (solo outcome).
* **Tracing (OpenTelemetry):** Hijo `Domain.CheckUniqueness` de `UseCase.RegisterUser/ResendVerification` con hijos `db.user.select_by_email`, `crypto.argon2id.dummy_hash`, `cache.throttle.check`, `outbox.insert?`. Atributo `email.domain` sí, `email_hash` en `DEBUG` solo, `found` solo interno.
* **Logs Estructurados:** `pkg/logger` slog: `INFO "registration accepted"` idéntico ambas ramas (sin `found`), `WARN duplicate_shadow` (interno, con `email_hash, ip_hash`), `WARN resend_throttled/rate_limited/blocked_ip`, `ERROR db_unavailable`. Prohibido email plano en `INFO` prod.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_003_uniqueness_noop.up.sql` (+ down):
  ```sql
  -- CU-REG-03: sin cambios de negocio. La unicidad usa UNIQUE(email_normalized) de 001.
  -- Verifica índice (idempotente):
  CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_normalized ON users(email_normalized);
  -- Tabla forense OPCIONAL (desactivada por defecto Q6/Q7-forense-total no elegido):
  -- CREATE TABLE IF NOT EXISTS uniqueness_probes (id BIGSERIAL PK, email_hash TEXT, ip_hash TEXT, found BOOL, created_at TIMESTAMPTZ DEFAULT now());
  SELECT 1;
  ```
  Down: `DROP INDEX IF EXISTS uq_users_email_normalized;` (solo si lo creó este script; documenta no tocar 001). Justificación: evita drift y deja rastro auditable de que CU-REG-03 se evaluó y se decidió reuso.

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `uniqueness_policy_test.go` (DecideProbe matriz found×throttle), `register_user_shadow_test.go` (mock Probe true/false → mismo `Output` genérico, outbox solo si found+allowed, throttled solo audit), `notify_throttle_test.go` (1º/hora true, 2º false, día 4º false, RedisDown → true fail-open). `go test ./internal/... -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/uniqueness_timing.js`: 2 escenarios (100×unique + 100×shadow, mismas VUs) mide `p50/p95` y aserta `|p50u-p50s|<80ms`, `p95<600ms` (con Argon2), `429` excluidos; segundo script `harvest_abuse.js` (60 mails/2min/IP → espera `429` desde 11º y `blocked` tras 50). Chaos Redis-down/Kafka-down → `201/202` intactos + fallback metrics. Resultado bloqueante para `READY_FOR_DEV→COMPLETED`.
