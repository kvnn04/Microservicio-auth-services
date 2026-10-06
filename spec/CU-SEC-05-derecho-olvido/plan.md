# Plan de Implementación Técnica: CU-SEC-05

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/user/` (`deletion.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    DeletionGrace=30*24*time.Hour; DeletionCancelTTL=15*time.Minute
    RetentionYearsDefault=7
  )
  type DeletionStatus string // Active | DeletionRequested | Anonymized
  func ConfirmDeletion(confirmEmail, actualNormalized string, accepted bool) error // ErrConfirmRequired
  func AnonID(userID, salt string) string // anon:<sha256(user+salt)[:16]>
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/user/deletion_ports.go
  type DeletionStore interface {
    RequestTx(ctx context.Context, userID string) (effectiveAt time.Time, err error) // ACTIVE→REQUESTED + valid_after + revoke-all + mfa-off + outbox; ErrAlready|ErrState
    CancelStart(ctx context.Context, emailNormalized string) error // opaco: si REQUESTED → issue link (ErrNone visible); sino noop (mismo 202)
    CancelConfirmTx(ctx context.Context, tokenHash string) error // link→ ACTIVE + clear deletion_* (mantiene valid_after) + mfa-reactivate + outbox; ErrInvalid
    ExecuteDue(ctx context.Context, limit int) ([]string, error) // worker: ids vencidos FOR UPDATE SKIP LOCKED
    ExecuteOneTx(ctx context.Context, userID, anonSalt string) (anonID string, err error) // destroy PII + anon + retention? + outbox erased
  }
  ```
  Reuso `StepUpVerifier` (request), `EventPublisher/Outbox`, `GlobalSessionRevoker` (corte).

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/deletion_request.go` + `deletion_cancel.go` + `deletion_execute.go` (worker)
  * `Request`: `Guard(account:delete)` + `ConfirmDeletion` + rate `3/día` → `RequestTx` + email solicitud + `Output{effective_at}` (`202`).
  * `CancelStart/CancelConfirm`: opacos (`202`/`200|400` igual reset-pattern) + `CancelConfirmTx` restaura (sin resucitar sesiones/backups: `valid_after` queda, backups exigen regenerate, TOTP secreto conservado se re-activa).
  * `ExecuteDue/One` (worker diario): por vencido `ExecuteOneTx` (destruye PII + `retention_ledger?` + `ANONYMIZED` + `user.erased` + audit) + recordatorio día-25 (mismo worker, `deletion:reminder:<uid>` NX).
* **Flujo Orquestado:** Step-Up→confirm→Tx corte→202+email; link-cancel→Tx restaura→200; cron→Tx hard→erased. Idempotencia RequestID (request mismo RequestID 24h no duplica; confirm replay mismo RequestID → mismo `200`).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/deletion_request.go` (`POST /account/deletion/request` auth+Step-Up → `202/400/401/409/429`) + `deletion_cancel_start.go` (`POST /cancel/start {email}` anónimo opaco → `202`) + `deletion_cancel_confirm.go` (`POST /cancel/confirm {token}` → `200/400|410`) + login-mapeo (`DELETION_REQUESTED` en login → `401` opaco, NO `403`; el `403` solo en endpoints con posesión probada — implementado en `errors/map` con flag `internalOnly`).
  * DTO `dto/deletion_dto.go`; middleware `require_step_up(account:delete)` en request + rate (`deletion:user 3/día`, cancel-start IP 10/hora).
  * Rutas `cmd/api/main.go`: 3 rutas deletion.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/deletion_store.go` (`RequestTx`: `UPDATE users status/valid_after` + revoke-all (reuso global_revoker en misma Tx) + `mfa off` + `backup burn` + outbox; `CancelConfirmTx`: `UPDATE ACTIVE + clear deletion_*` (mantiene `valid_after`) + `mfa reactivate TOTP` + outbox; `ExecuteOneTx`: `UPDATE PII→deleted` + `DELETE secrets/tokens/sessions/families/geo/device/backup` + `INSERT retention_ledger?` + `UPDATE ANONYMIZED+anon_id` + `UPDATE audit anonymize-view-map` + outbox `erased`; tablas `deletion_cancel_tokens(hash PK, user FK, exp, consumed)` + `retention_ledger(id, user_anon, ref, payload_enc, until, created)` cifrada).
  * Redis: sweep `sess/fam/challenges` (reuso) + `deletion:reminder` + quotas; down → PG + `WARN`.
* **Salida (Mensajería):** `kafka` (`deletion.requested|cancelled`, `user.erased.v1{user_id,anon_id}`, `session.revoked_all{reason:deletion}`, + audit); worker SMTP solicitud/recordatorio-25 (sin mail post-hard) + downstream `erased` con reintento 24h + DLQ.
* **Salida (Seguridad):** reuso `StepUpVerifier`, `token_issuer` (cancel-link 15min), `secret_box` (retention cifrada `RETENTION_KEY`), `AnonID` (`DELETION_ANON_SALT`).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `deletion_total{op,result}` + `deletion_pending_gauge` + `deletion_executed_total` + `retention_purged_total` + `erased_lag_seconds`.
* **Tracing (OpenTelemetry):** Raíces `UseCase.DeletionRequest/Cancel/Execute` (hijos `stepup.check`, `db.deletion.*`, `cache.sweep`, `crypto.anon`, `outbox.insert`). Atributos `effective_at, anon_id`, nunca email.
* **Logs Estructurados:** `pkg/logger`: `INFO deletion requested/cancelled/executed (anon)`, `WARN confirm-fail/taken/rate/throttled`, `ERROR db`. Sin `email/token` (hash/mask).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_024_deletion_olvido.up.sql` (+ down):
  ```sql
  ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('PENDING_VERIFICATION','ACTIVE','LOCKED','SOFT_DELETED','DELETION_REQUESTED','ANONYMIZED'));
  ALTER TABLE users ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS deletion_effective_at TIMESTAMPTZ;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS anon_id TEXT;
  CREATE TABLE deletion_cancel_tokens (token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL, consumed BOOLEAN NOT NULL DEFAULT FALSE);
  CREATE TABLE retention_ledger (id UUID PRIMARY KEY, user_anon TEXT NOT NULL, ref TEXT NOT NULL, payload_enc BYTEA NOT NULL, until TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
  CREATE INDEX idx_users_deletion_due ON users(deletion_effective_at) WHERE status='DELETION_REQUESTED';
  REVOKE UPDATE, DELETE ON retention_ledger FROM app_role; -- inserta vía SECURITY DEFINER, purga auditor_role
  ```
  Down: `DROP TABLE ...; ALTER TABLE users DROP COLUMN ...;` (con guarda si hay ANONYMIZED: la down documenta pérdida). `status` amplía el enum previo (migración idempotente con `DROP CONSTRAINT`+`ADD` si existía CHECK viejo — documentado).
  Redis `deletion:reminder:*` (efímeras).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `deletion_test.go` (Confirm, AnonID estable, estados) + servicio table-driven con fakes (request corte+403-no-401-opaco-login? (login `401`), re-request 409, cancel-start opaco + confirm restaura sin resucitar sesiones, execute destroy+anon+erased+retention?, email-liberado re-registrable). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/deletion_smoke.js`: 20 VUs request/cancel (p95 <400ms sin Argon2 extra salvo Step-Up), executor 10k vencidos (p95 <5min lote, `SKIP LOCKED` sin dobles), re-registro post-hard `201`, login-viejo `401`, PG/Redis/Kafka-down (`500`/`WARN`+PG/`202`+pendiente). Chaos fiscal (con/sin fila retention).
