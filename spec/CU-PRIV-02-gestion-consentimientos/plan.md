# Plan de Implementación Técnica: CU-PRIV-02

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/shared/` (extiende `legal.go` CU-REG-05).
* **Entidades / Value Objects:**
  ```go
  type Purpose string // PurposeTerms, PurposePrivacy, PurposeOperational, PurposeAnalytics, PurposeMarketing, PurposeProfiling
  func (p Purpose) Essential() bool // terms|privacy|operational
  func (p Purpose) Default() string // esenciales granted; opcionales revoked
  ```
* **Puertos de Salida:** Extiende `ConsentLedger` (CU-REG-05):
  ```go
  // SetStatus inserta fila (no UPDATE); History lista trail; Current mapea última por propósito
  type ConsentLedger interface {
    RecordTx(ctx context.Context, tx any, recs []ConsentRecord) error // reuso REG-05
    SetStatus(ctx context.Context, userID string, purpose Purpose, status string) (version string, err error) // ErrEssential|Unknown
    History(ctx context.Context, userID string) ([]ConsentRecord, error)
    Current(ctx context.Context, userID string) (map[Purpose]ConsentRecord, error)
  }
  ```
  (`ConsentRecord` gana `status` — migración 033 lo añade con default `granted` para filas REG-05.)

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/consent_panel.go` (Get + Set)
  * `Get(userID)`: `Current` + catálogo (esencial/toggles, `revocable`, `text_url` por propósito) → `Output{consents}` (sin Step-Up).
  * `Set(userID, purpose, status)`: valida `purpose` (`ErrUnknown`) + rate → si esencial y `revoked` → `ErrEssential` (con `deletion_url`) → si igual-actual → `Output{already:true}` (sin fila) → `SetStatus` (sella versión activa) + outbox `consent.changed` + (si `profiling` revocado → email informativo 1 vez + flag `profiling_off`) → `Output{version}`.
* **Flujo Orquestado:** auth→rate→essential-guard→idempotencia→Tx insert+outbox→200. Sin Step-Up, sin Transacción distribuida (satélites eventual).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/consents_{get,set}.go` (`GET /privacy/consents` → `200` + `PUT /consent/:purpose` → `200/400/404/429`) auth-simple + rate (`consents:user 30/min`) + `no-store`.
  * DTO `dto/consents_dto.go`; `errors/map` (+`UNKNOWN_PURPOSE→404`, `ESSENTIAL_CONSENT→400` con `deletion_url`).
  * Rutas `cmd/api/main.go`: 2 rutas privacy.
* **Salida (Persistencia):**
  * Postgres: extiende `legal_repository.go` (`SetStatus`: `SELECT versión activa del propósito` + `INSERT` + outbox misma Tx; `History/Current` (`DISTINCT ON (purpose) ORDER BY at DESC`); migración 033: `purposes` catálogo + `consent_records.status` + seed textos opcionales).
  * Redis: solo rate (`consents:user`) + `profiling:off:<uid>` flag cache (para que travel/device hagan skip sin JOIN; TTL 1h + invalidada por evento propio; down → PG verdad).
* **Salida (Mensajería):** `kafka` (`consent.changed.v1` + audit `consent.set`); worker SMTP informativo `profiling_off` (1 vez por revoke, no por cada login sin profiling).
* **Salida (Seguridad):** sin cripto nueva (reuso hashes/mask).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `consent_changes_total{purpose,status}` + `consent_essential_blocked_total` + `consent_sat_lag_seconds` (muestreado).
* **Tracing (OpenTelemetry):** Raíces `UseCase.ConsentGet/Set` (hijos `db.consent.*`, `outbox.insert`). Atributos `purpose, status`.
* **Logs Estructurados:** `pkg/logger`: `INFO consent set (purpose, status, version)`, `WARN essential-blocked/unknown/rate`, `ERROR db`. Sin texto legal (versión+url).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_033_consent_purposes.up.sql` (+ down):
  ```sql
  ALTER TABLE legal_versions DROP CONSTRAINT IF EXISTS legal_versions_doc_type_check;
  -- nuevos doc_types (CHECK ampliado):
  ALTER TABLE legal_versions ADD CONSTRAINT legal_versions_doc_type_check
    CHECK (doc_type IN ('terms','privacy','operational_email','analytics','marketing','security_profiling'));
  ALTER TABLE consent_records ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'granted'
    CHECK (status IN ('granted','revoked'));
  INSERT INTO legal_versions(doc_type,version,content_hash,url,effective_from,is_active) VALUES
   ('operational_email','v2026.10','<sha256>','https://legal.example.com/operational/v2026.10',now(),true),
   ('analytics','v2026.10','<sha256>','https://legal.example.com/analytics/v2026.10',now(),true),
   ('marketing','v2026.10','<sha256>','https://legal.example.com/marketing/v2026.10',now(),true),
   ('security_profiling','v2026.10','<sha256>','https://legal.example.com/profiling/v2026.10',now(),true)
  ON CONFLICT DO NOTHING;
  -- defaults opcionales revoked al registrar (el servicio los inserta; backfill existentes):
  INSERT INTO consent_records(id, user_id, doc_type, version, status)
  SELECT gen_random_uuid(), u.id, p, 'v2026.10', 'revoked' FROM users u CROSS JOIN
   (VALUES ('analytics'),('marketing'),('security_profiling')) AS t(p)
   WHERE u.status='ACTIVE' AND NOT EXISTS (SELECT 1 FROM consent_records c WHERE c.user_id=u.id AND c.doc_type=t.p)
  ON CONFLICT DO NOTHING;
  CREATE INDEX IF NOT EXISTS idx_consent_user_purpose_at ON consent_records(user_id, doc_type, accepted_at DESC);
  ```
  Down: `DELETE nuevos doc_types + DROP COLUMN status + DROP INDEX;` (con guarda si hay filas opcionales: la down las conserva documentando pérdida de filtro). Redis `profiling:off:*` (flags).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `consents_test.go` (Essential/Default matriz, server-stamped, idempotente-igual) + servicio table-driven con fakes (toggle+historial+satélite-flag, esencial-400, igual-already, unknown-404, profiling-off skip). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/consents_smoke.js`: 50 VUs get/set (p95 <150ms, idempotentes sin filas nuevas) + flood 40/min→429 + Kafka-down (200 + pendiente) + PG-down (500 0 filas) + backfill-033 (existentes reciben revoked sin duplicar).
