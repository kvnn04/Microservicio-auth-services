# Plan de Implementación Técnica: CU-CRYP-03

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`emergency.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    EmergencyRatePerHour=1; EmergencySweepBatch=1000
    JWKSEmergencyMaxAge=0; KillSwitchFlag="EMERGENCY_ENABLED"
  )
  func ConfirmPhrase(kid string) string // "REVOKE <kid>" exacto
  func EmergencyKey(kid string) string  // validación formato kid
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/emergency_ports.go
  type EmergencyRevoker interface {
    RevokeKidTx(ctx context.Context, kid string) error // retired_at=now(emergency) + outbox; ErrNotFound|AlreadyRetired
    BumpEpochTx(ctx context.Context) (epoch time.Time, err error) // system_flags.crypto_epoch=now + outbox
    SweepBatch(ctx context.Context, limit int) (done, total int, err error) // families revoked + sessions DELETE SKIP LOCKED
    IssueSuccessor(ctx context.Context) (newKid string, err error) // reuso KeyRotator.Generate (sin overlap: activa ya)
  }
  type EmergencyGate interface { Active(ctx context.Context) (bool, error) } // EMERGENCY_ENABLED + emergency_active flag
  ```
  Reuso `KeyGenerator/PrivateCustody/SigningKeyStore(destroy)`, `KeyDirectory/AccessSigner`, `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/emergency_revoke.go` + `emergency_sweep.go` (worker)
  * `EmergencyRevoke(adminID, kid, confirm, dryRun)`:
    1. `Gate.Active` (`false` → `ErrDisabled` 503) + rate global (`emergency:fire EX 3600 NX` → existe → `ErrRateDoubleFire` 429+P1) + triple (Step-Up `crypto:emergency` verificado fuera + `confirm==REVOKE kid` exacto).
    2. Si `dryRun` → recorre (counts sin DELETE, kid efímero sin custodiar) → `Output{drill:true}` + audit `drill` (sin commit de cambios: Tx rollback).
    3. Fase1 `RevokeKidTx` + `Directory.Reload` + `PUBLISH keys.emergency` + JWKS-emergency-mode (`SET emergency:active EX 3600`) + `Custody.Destroy(kid-viejo)` YA.
    4. Fase2 `BumpEpochTx` + `PUBLISH crypto.epoch` (gateways: `epoch` cache 10s + pub/sub).
    5. Encola `SweepBatch` loop (worker async, no bloquea el `200`: el endpoint retorna `202 accepted{epoch}` tras fases 1-2 (<5s SLO) y el sweep corre detrás con progreso).
    6. Fase4 `IssueSuccessor` (si falla → P1 + reintento 1min ×60 en worker, Issue `500` mientras tanto) + broadcast `keys.emergency` + bulk-mail enqueue (10k/min) + outbox.
* **Flujo Orquestado:** gate→rate→triple→(drill? rollback) →purge-Tx→epoch-Tx→sweep-async→successor→broadcast+bulk→`202`. Orden purga→epoch→sweep→sucesora (contención antes que continuidad). Idempotencia: NO idempotente por RequestID (cada fuego es epoch nueva); el rate global 1/hora es el freno.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/keys_emergency.go` (`POST /admin/keys/emergency-revoke {kid,confirm,reason,dry_run?}` auth-admin + Step-Up `crypto:emergency` → `202 {epoch,kids}` / `400/401/404/409/429/503`) + `keys_emergency_status.go` (`GET /admin/keys/emergency/status` → `{epoch, active, sweep{done,total}}`).
  * DTO `dto/keys_emergency_dto.go`; `errors/map` (+`EMERGENCY_*`: `CONFIRM_MISMATCH→400`, `ALREADY_RETIRED→409`, `DOUBLE_FIRE→429`, `DISABLED→503`, `EMERGENCY_RELOGIN→401` (verificadores, no este endpoint)).
  * Rutas `cmd/api/main.go`: 2 rutas emergency + recableo verificadores (`iat<epoch → 401 EMERGENCY_RELOGIN` en `ed25519_verifier` + gateways-doc).
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/emergency_store.go` (`RevokeKidTx` + `BumpEpochTx(system_flags crypto_epoch)` + `SweepBatch(SKIP LOCKED families+sessions)` + `IssueSuccessor` (reuso rotation Tx sin overlap) + `key_archive(forensics=true)`).
  * Redis: `emergency:active EX 3600` (JWKS `no-store` mode) + `emergency:fire EX 3600 NX` (rate global) + `PUBLISH keys.emergency|crypto.epoch` + `emergency:sweep:cursor` (reanudable); down → PG + poll-10s gateways + `WARN` (sin pub/sub instantáneo, ventana 10s).
* **Salida (Mensajería):** `kafka` (`keys.emergency.v1` crítico + `crypto.epoch_bumped` + `session.revoked_all{reason:key_compromise}` batched + audit P1 `keys.emergency_revoke|drill`); worker SMTP bulk (`emergency_relogin`, 10k/min, `mail_lag`) + pager P1 (fuego, doble-fuego, custodia-fail, chain? No).
* **Salida (Seguridad):** reuso `ed25519_generator/kms_custody(destroy-YA)` + `AccessSigner/Verifier` (+`epoch` check `iat` en TODA JWT local, cualquier `aud`) + `Directory` (purge+reload).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `emergency_total{result,trigger}` + `emergency_revoke_progress{done,total}` + `crypto_epoch` + `jwks_emergency_mode` + `emergency_mail_lag_seconds` + `kid_unknown_401_total` (pico esperado) + `custody_failures_total`.
* **Tracing (OpenTelemetry):** Raíz `UseCase.EmergencyRevoke` (hijos `stepup.check`, `db.keys.retire`, `custody.destroy`, `epoch.bump`, `directory.reload`, `pubsub.broadcast`, `batches.sweep`, `successor.issue`, `outbox.insert`, `bulk.enqueue`). Atributos `kid, epoch`.
* **Logs Estructurados:** `pkg/logger`: `CRITICAL emergency fire (kid, epoch, admin)` + `WARN double-fire/drill/disabled/custody-retry` + `INFO sweep-progress/successor/bulk`. Sin material (solo `kid`s).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_031_emergency_epoch.up.sql` (+ down):
  ```sql
  INSERT INTO system_flags(k,v) VALUES ('crypto_epoch','1970-01-01T00:00:00Z') ON CONFLICT DO NOTHING;
  ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS emergency_retired BOOLEAN NOT NULL DEFAULT FALSE;
  -- sweep-cursor en Redis (no PG); key_archive ya existe (030) + columna forensics:
  ALTER TABLE key_archive ADD COLUMN IF NOT EXISTS forensics BOOLEAN NOT NULL DEFAULT FALSE;
  ```
  Down: `UPDATE system_flags ...; ALTER TABLE ... DROP COLUMN ...;`. Redis `emergency:*` (efímeros).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `emergency_test.go` (ConfirmPhrase exacta, epoch-monótona, batch-cursor reanudable) + servicio table-driven con fakes (triple-ok → purge+epoch+sweep+sucesora+broadcast+bulk; frase-mal → 0 cambios; drill → rollback + audit-drill; doble-fuego → 429; kid-no-activo → 404 sin epoch; custodia-fail → contención OK + sucesora-retry). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/emergency_smoke.js` (staging aislado): fuego con 1k sesiones (purga <5s fases1-2, sweep 100% reanudable, JWKS sin kid + `no-store`, viejos `401 EMERGENCY`, nuevos `200` post-sucesora, bulk encolado 10k/min sin bloquear `202` p95<5s) + drill trimestral (0 cambios) + PG-down (500 fail-closed) + custodia-down (contención + Issue-500 + retry) + doble-fuego 429.
