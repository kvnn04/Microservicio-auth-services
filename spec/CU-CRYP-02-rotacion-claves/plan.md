# Plan de Implementación Técnica: CU-CRYP-02

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`key_rotation.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    RotationPeriod=90*24*time.Hour; OverlapWindow=1*time.Hour
    RotationWarnBefore=7*24*time.Hour; PrivDestroyAfter=7*24*time.Hour
    JWKSMaxAgeNormal=600; JWKSMaxAgeOverlap=60
  )
  func NextKid(now time.Time, seq string) string // 2026-10-b
  func OverlapActive(now, overlapUntil time.Time) bool
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/rotation_ports.go
  type KeyGenerator interface { Generate(ctx context.Context) (priv, pub []byte, err error) } // ed25519 CSPRNG
  type PrivateCustody interface { Store(ctx context.Context, kid string, priv []byte) (ref string, err error); Destroy(ctx context.Context, kid string) error } // KMS-or-file
  type SigningKeyStore interface {
    BeginRotationTx(ctx context.Context, kid, pubB64, privRef string) (oldKid string, err error) // INSERT nueva + overlap_until vieja + next_rotation + outbox; ErrInProgress (mutex)
    RetireTx(ctx context.Context, kid string) error // retired_at + archive + outbox
  }
  type KeyRotator interface { Rotate(ctx context.Context, trigger string) (oldKid, newKid string, err error); RetireDue(ctx context.Context) error }
  ```
  Reuso `KeyDirectory` (recarga), `AccessSigner` (`UseKid`), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/key_rotation.go`
  * `Rotate(trigger)`: `mutex(rotate:mutex EX 300 NX)` (falla → `ErrInProgress`) → `Generator.Generate` → smoke-test firma/verifica en memoria → `Custody.Store` (falla → `ErrCustody` + aborta sin INSERT) → `SigningKeyStore.BeginRotationTx` (INSERT + overlap + outbox `rotated`) → post-commit `Signer.UseKid + Directory.Reload + JWKS-overlap-mode + pub/sub` → programa `RetireDue` (+1h, worker delayed-job o cron horario) → `Output{old,new}`.
  * `RetireDue`: `SELECT ... WHERE overlap_until<=now AND retired_at IS NULL` → por cada: `RetireTx` (retired + archive + outbox `retired`) → `Reload + modo-600s` + email + (a +7d `Custody.Destroy` job).
  * `CheckDue` (cron diario): si `now ≥ next_rotation - 7d` → `WARN`/email `rotation_due`; si `≥ next_rotation` → `Rotate(cron)`.
* **Flujo Orquestado:** mutex→generate→smoke→custody→Tx→post-commit(broadcast+reload)→overlap→retire→archive→(priv-destroy +7d). Idempotencia: `kid` determinista por intento? No: cada `Rotate` genera kid nuevo (doble `Rotate` = 2 kids). La idempotencia es el mutex (1 rotate a la vez), no RequestID.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler `handlers/keys_rotate.go` (`POST /api/v1/auth/admin/keys/rotate {reason?}` auth-admin + Step-Up `crypto:rotate` → `202 {old_kid,new_kid,overlap_until}` (async <30s) o `400/401/409/429/500`) + rate `5/hora/admin`.
  * DTO `dto/keys_dto.go`; `errors/map` (+`ROTATION_IN_PROGRESS→409`, `KEY_CUSTODY_UNAVAILABLE→500`, `crypto:rotate` en `require_step_up`).
  * Rutas `cmd/api/main.go`: `POST /admin/keys/rotate` (+ `GET /admin/keys` lista kids/estados para el panel, auth-admin, `200 [{kid,alg,created,overlap_until,retired_at}]` sin pubs? Con pubs (públicas) — documentado).
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/signing_key_store.go` (`BeginRotationTx`: `INSERT nueva` + `UPDATE vieja overlap_until + next_rotation` + outbox; `RetireTx`: `UPDATE retired + INSERT key_archive(pub)` + outbox; `CheckDue` queries) + migración 030 (`next_rotation_at, overlap_until, key_archive`).
  * Redis: `rotate:mutex EX 300 NX` + `PUBLISH keys.rotated|retired` (multi-instancia) + `jwks:mode overlap|normal` (para header dinámico `max-age`).
* **Salida (Mensajería):** `kafka` (`keys.rotated|retired|extended` + audit `keys.*`); worker SMTP técnico (due-7d, rotated, retired) + cron `02:00 check-due + horario retire-due + 7d priv-destroy`.
* **Salida (Seguridad):** `security/ed25519_generator.go` (`crypto/ed25519` + `crypto/rand`, smoke-test) + `security/kms_custody.go` (interfaz KMS: `awskms|gcp|file0600` por env `KMS_PROVIDER`; file con `0600` + `fsync`, path `keys/`) + reuso `ed25519_signer.UseKid` (atómico `atomic.Pointer`).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `key_rotation_total{result,trigger}` + `keys_count{state}` + `overlap_gauge` + `jwks_max_age` + `kid_unknown_401_total` (gateway-reportada vía endpoint interno `POST /internal/kid-unknown` o log-scrape — documentado) + `custody_failures_total`.
* **Tracing (OpenTelemetry):** Raíces `UseCase.RotateKeys/RetireKeys/CheckDue` (hijos `crypto.generate`, `kms.store`, `db.keys.*`, `directory.reload`, `pubsub.broadcast`, `jwks.cache_mode`). Atributos `old_kid,new_kid`.
* **Logs Estructurados:** `pkg/logger`: `INFO rotation started/overlap/retired (kids)`, `WARN rotation_due/custody-retry/extended`, `ERROR custody/no_keys`. Sin material (solo `kid`s).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_030_rotation_state.up.sql` (+ down):
  ```sql
  ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS overlap_until TIMESTAMPTZ;
  ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS next_rotation_at TIMESTAMPTZ NOT NULL DEFAULT now()+INTERVAL '90 days';
  CREATE TABLE IF NOT EXISTS key_archive (kid TEXT PRIMARY KEY, pub_b64 TEXT NOT NULL, alg TEXT NOT NULL DEFAULT 'EdDSA', retired_at TIMESTAMPTZ NOT NULL, archived_at TIMESTAMPTZ NOT NULL DEFAULT now());
  ```
  Down: `DROP TABLE key_archive; ALTER TABLE signing_keys DROP COLUMN ...;`. KMS/file fuera de PG.

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `key_rotation_test.go` (NextKid seq, OverlapActive bordes, cadencia 90d) + servicio table-driven con fakes (generate→custody→Tx→broadcast→overlap→retire→archive; custody-fail aborta sin INSERT; doble-rotate 2º 409; smoke-fail aborta; kid-unknown-alto extiende 1 vez). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/rotation_smoke.js`: rotate en staging con 50 VUs Issue concurrente (0 `500` firma, p95 Issue <300ms durante switch `UseKid` atómico) + JWKS `[B,A]` en overlap + `[B]` tras retiro + viejos verifican + nuevos refetch + flood manual 6/hora→429 + KMS-down (500 + reintento) + cron-due (aviso 7d + auto-rotate día 0).
