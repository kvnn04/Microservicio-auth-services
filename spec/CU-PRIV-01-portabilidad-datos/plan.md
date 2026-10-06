# Plan de Implementación Técnica: CU-PRIV-01

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/shared/` (`privacy_export.go` — allowlist + shape, sin I/O).
* **Entidades / Value Objects:**
  ```go
  const (
    ExportCooldown=30*24*time.Hour; ExportTTL=24*time.Hour; ExportMaxAudit=10000
  )
  type ExportBundle struct { Version string; Profile, Emails, Federated, Sessions, Devices, Consents, Audit, MFA map[string]any }
  func (b ExportBundle) Sanitize() error // denylist: password_hash, secret_enc, backup, token, ip, lat/lon (falla cerrado)
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/shared/export_ports.go
  type ExportStore interface {
    Request(ctx context.Context, userID string) (exportID string, err error) // 30d-check + INSERT processing + outbox; ErrTooSoon{Next}
    MarkReady(ctx context.Context, exportID string, blobEnc, keyEnc []byte, bytes int) error // + exp=ready+24h + outbox ready+mail
    GetForDownload(ctx context.Context, userID, exportID string) (blobEnc, keyEnc []byte, err error) // owner-check; ErrNotFound|Expired
    DestroyDue(ctx context.Context, limit int) error // worker: exp<=now → purge + destroyed
  }
  type BundleCollector interface { Collect(ctx context.Context, userID string) (ExportBundle, error) } // read-only multi-fuente
  ```
  Reuso `StepUpVerifier` (request), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/export_request.go` + `export_build.go` (worker) + `export_download.go`
  * `Request`: `Guard(privacy:export)` + `ExportStore.Request` (30d; fallido-infra previo no bloquea: `WHERE status IN (ready,processing)` — `failed/superseded` no cuentan) → `202` + encola job (outbox `export.requested` dispara worker, no Kafka-dependiente: el worker pollea `processing`).
  * `Build(exportID)` (worker): `BundleCollector.Collect` (snapshot `REPEATABLE READ`, audit `LIMIT 10k` + `truncated` flag) → `Sanitize` (viola → `failed` + P1, sin guardar) → `Encrypt(AES-GCM efímera, AAD=user)` + `KEK-wrap` → `MarkReady` + email listo.
  * `Download`: `GetForDownload` (owner/expiry) → descifra streaming (`AES-GCM` + `KEK-unwrap`) → ZIP (`export.json` + `sessions.csv`) → `Output{stream}` + audit `downloaded` (cada una).
* **Flujo Orquestado:** Step-Up→30d→processing→202; worker collect→sanitize→encrypt→ready+mail; owner-download (24h, N veces)→purge.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/export_{request,status,download}.go` (`POST /privacy/export` Step-Up → `202/401/429`; `GET /export/status?` o `GET /export/:id` → `processing|ready|failed|destroyed`; `GET /export/:id/download` owner → ZIP/`404/410`) + `require_step_up(privacy:export)` (14º scope) + rate (`export:user 1/30d lógico + export:ip 10/hora` middleware).
  * DTO `dto/export_dto.go`; `errors/map` (+`EXPORT_TOO_SOON→429` con `next_available`, `EXPORT_EXPIRED→410`).
  * Rutas `cmd/api/main.go`: 3 rutas privacy.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/export_store.go` (`exports(id PK, owner FK, status, key_enc BYTEA, blob_enc BYTEA (o path si >10MB: blob_path), bytes, truncated, created, ready_at, exp)` + `Request` (30d-check + INSERT + outbox) + `MarkReady` + `GetForDownload` + `DestroyDue` + `DELETE` voluntario).
  * Storage: volumen `exports/` (si blob_path; `0600`, `noexec`) o BYTEA (default <10MB); documentado umbral + GC huérfanos (job semanal `blob sin exports`).
* **Salida (Mensajería):** `kafka` (`export.requested|ready|downloaded|destroyed|failed` + audit); worker SMTP `export_ready` (24h, sin adjunto) + procesador `export_build` (poll `processing`, no solo Kafka — reanuda tras caída).
* **Salida (Seguridad):** `security/export_box.go` (`AES-256-GCM`, efímera 32B CSPRNG + `KEK EXPORT_KEK` env/KMS wrap, `AAD=user_id`, fail-fast sin KEK) + `privacy_schema.json` (CI valida bundles ejemplo + scanner denylist).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `export_total{op,result}` + `export_build_duration_seconds` + `export_size_bytes` + `export_expired_total`.
* **Tracing (OpenTelemetry):** Raíces `UseCase.ExportRequest/Build/Download` (hijos `stepup.check`, `db.collect×N`, `crypto.encrypt`, `storage.save`, `mail.notify`). Atributos `export_id, bytes`, nunca contenido.
* **Logs Estructurados:** `pkg/logger`: `INFO export requested/ready/downloaded/destroyed (bytes)`, `WARN too_soon/failed/sanitize-fail`, `ERROR db/kek`. Sin `email/contenido` (hash).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_032_privacy_export.up.sql` (+ down):
  ```sql
  CREATE TABLE exports (
    id UUID PRIMARY KEY, owner UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('processing','ready','failed','destroyed','superseded')),
    key_enc BYTEA, blob_enc BYTEA, blob_path TEXT, bytes INT NOT NULL DEFAULT 0, truncated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), ready_at TIMESTAMPTZ, exp TIMESTAMPTZ
  );
  CREATE INDEX idx_exports_owner_created ON exports(owner, created_at DESC);
  ```
  Down: `DROP TABLE exports;`. Volumen `exports/` (0600) si blob_path.

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `privacy_export_test.go` (Sanitize denylist por clave, shape schema, 30d-check, truncated) + servicio table-driven con fakes (request 202/429-con-fecha, build ok+email, download owner/ajeno-404/expirado-410/multi-ok, destroy-purga, fallido-no-consume-cuota, KEK-fail 500). `go test -race` verde + `privacy_schema.json` valida fixtures.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/export_smoke.js`: 20 VUs request (2º <30d → 429) + build p95<60s (dataset medio) + download p95<5s (10MB) + 50k-audit truncado + KEK-down (500) + PG-down (500) + SMTP-down (ready sin mail). Chaos worker-kill mid-build (re-pickup sin duplicar: `processing` con lease `worker_id+heartbeat`).
