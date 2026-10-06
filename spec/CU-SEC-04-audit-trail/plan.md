# Plan de Implementación Técnica: CU-SEC-04

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/shared/` (`audit.go` — envelope + chain + sanitize, puro).
* **Entidades / Value Objects:**
  ```go
  type AuditAction string // user.register, login.attempt, session.rotate, ...
  type AuditEvent struct { EventID string; OccurredAt time.Time; ActorUserID, DeviceHash string; Action AuditAction; Result string; TraceID, RequestID string; Data map[string]any; PrevHash, Hash string }
  func CanonicalJSON(e AuditEvent) []byte // sin Hash (para hashear), keys ordenadas
  func ChainHash(prev string, body []byte) string // hex(sha256(prev+body))
  func (e AuditEvent) Validate() error // action/result/trace/request presentes, Data sin denylist (regex por clave)
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/shared/audit_ports.go
  type AuditSanitizer interface { Check(e AuditEvent) error } // ErrAuditUnsafe + paths violados
  type AuditStore interface {
    AppendTx(ctx context.Context, tx any, e *AuditEvent, strict bool) error // strict: SELECT prev FOR UPDATE + INSERT + outbox; eventual: INSERT con prev='' + worker cose
    QueryMe(ctx context.Context, userID, cursor string, limit int) ([]AuditEvent, string, error) // cursor (occurred_at,id), masked
  }
  ```
  Reuso `EventPublisher/Outbox` (el `AppendTx` escribe ambos en la Tx del llamador).

### Capa de Aplicación (`internal/service/`)
* **Servicios:** Sin servicio nuevo. `internal/service/audit_helper.go`:
  * `Build(action, result, userID, trace, req, data) AuditEvent` (UUIDv7 + `clock_timestamp` se pone en adapter PG `now()`? No: el dominio pone `time.Now().UTC()` y PG lo respeta (documentado skew); `prev/hash` los pone `AuditStore.AppendTx`).
  * `MustAppendTx(...)` (valida con Sanitizer → `ErrAuditUnsafe` fail-closed; `AppendTx strict` para register/login/password/session, `eventual` para rate/travel-normal/list).
  * `QueryMe` (paginación cursor, `limit` clamp 1..100, masked por `AuditMasker`).
  * Migración CUs previos: sus `AuditLogger.Log` pasan a `MustAppendTx` con envelope `v:2` (compat: el worker traduce `v1→v2` si llega viejo durante 1 release).
* **Flujo Orquestado (en cada llamador):** construye evento → `Sanitizer.Check` → `AppendTx(strict|eventual)` en SU Tx → commit → outbox→Kafka (worker) → `GET /me` lee `AuditStore`.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler `handlers/audit_me.go` (`GET /api/v1/auth/audit/me?cursor=&limit=` auth → `200 {events:[masked], next_cursor}` o `400 cursor`, rate `audit:me 60/min/user`, `no-store`).
  * DTO `dto/audit_dto.go` (envelope público masked); `errors/map` (+`AUDIT_UNSAFE→500` interno, nunca al cliente con detalle; al cliente `INTERNAL_ERROR`).
  * Rutas `cmd/api/main.go`: `GET /api/v1/auth/audit/me`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/audit_store.go` (`audit_log(event_id PK UUIDv7, occurred_at, actor_user, device_hash, action, result, trace_id, request_id, data JSONB, prev_hash, hash, month GENERATED)` + partición por rango mensual `audit_log_yyyy_mm` + `REVOKE UPDATE,DELETE FROM app_role` + `SELECT prev FOR UPDATE` en strict + `INSERT outbox(auth.audit.v1)` en la Tx recibida (cast pgx.Tx); `QueryMe` con `WHERE actor_user=$1 AND (occurred_at,id)>(cursor) ORDER BY occurred_at,id LIMIT n` + máscara lectura).
  * Worker `cmd/worker`: `audit_drain` (outbox→Kafka `auth.audit.v1` retention 1a) + `audit_verify` nightly (recorre mes, verifica chain, `audit_chain_break_total`/P1, congela purga) + `audit_purge` mensual (DROP particiones >2a sin hold) + `audit_partition` (crea mes+1 día 25).
* **Salida (Mensajería):** `kafka` tópico `auth.audit.v1` (envelope `v2`, retención 1a) + DLQ; satélites archivan (fuera).
* **Salida (Seguridad):** `security/audit_sanitize.go` (denylist regex por clave + allowlist `audit_allowlist.yaml` por `action`; scanner CI `scripts/audit_pii_scan.sh` recorre `spec/*/contracts.md` ejemplos + `*_test.go` payloads y falla si hay secreto).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `audit_appended_total{action}` + `audit_lag_seconds` (occurred→sent) + `audit_dropped_total` (SLO 0) + `audit_chain_break_total` + `audit_unsafe_total` (SLO 0) + `audit_verify_duration_seconds` + `audit_purged_total`. Vía MetricsPort en Helper/Store/Worker.
* **Tracing (OpenTelemetry):** Sin span por evento (ruido); el `trace_id` del request viaja DENTRO del evento + span `Audit.VerifyChain` nightly + `Outbox.Drain` existente.
* **Logs Estructurados:** `pkg/logger`: `WARN audit_unsafe (paths)`, `ERROR chain_break (month, event_id)`, `INFO purged/verified`. Sin `data` completa en logs (solo `action/event_id`).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_023_audit_log.up.sql` (+ down):
  ```sql
  CREATE TABLE audit_log (
    event_id UUID PRIMARY KEY, occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    actor_user UUID, device_hash TEXT, action TEXT NOT NULL, result TEXT NOT NULL,
    trace_id TEXT NOT NULL, request_id UUID NOT NULL, data JSONB NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL, month TEXT GENERATED ALWAYS AS (to_char(occurred_at,'YYYY-MM')) STORED
  ) PARTITION BY LIST (month);
  CREATE TABLE audit_log_2026_10 PARTITION OF audit_log FOR VALUES IN ('2026-10');
  CREATE INDEX idx_audit_user_cursor ON audit_log (actor_user, occurred_at, event_id);
  CREATE INDEX idx_audit_action ON audit_log (action, occurred_at);
  REVOKE UPDATE, DELETE ON audit_log FROM app_role; GRANT SELECT, INSERT ON audit_log TO app_role;
  ```
  Down: `DROP TABLE audit_log;`. Particiones futuras por worker (no migraciones mensuales). Kafka retención 1a (`retention.ms=31536000000` en `compose.yml`/terraform, documentado).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `audit_test.go` (CanonicalJSON estable, ChainHash vector, Validate denylist por clave + allowlist por acción, cursor encode/decode) + `audit_helper_test.go` (strict/eventual, unsafe fail-closed sin Tx, QueryMe paginación sin duplicados con inserts concurrentes simulados) + scanner `audit_pii_scan.sh` en CI (falla con fixture `password` en evento). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/audit_smoke.js`: 100 VUs login (cada uno audita en Tx, p95 overhead audit <20ms) + `GET /me` 50 VUs paginando (3 páginas estables, p95 <150ms) + kill-Kafka 60s (0 drops, lag recupera <60s) + chain-verify nightly en dataset 100k (p95 <60s) + PG-audit-down (mutaciones `500`, `me` `500`, 0 negocio sin audit).
