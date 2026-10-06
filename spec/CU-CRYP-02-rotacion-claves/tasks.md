# Tareas de Implementación: CU-CRYP-02

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `key_rotation.go` (consts 90d/1h/7d/600-60, NextKid, OverlapActive). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/rotation_ports.go` (KeyGenerator, PrivateCustody, SigningKeyStore, KeyRotator + errores InProgress/Custody). `go vet` sin ed25519/kms.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `key_rotation_test.go` (kids, overlaps, cadencia). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `key_rotation.go` (mutex→generate→smoke→custody→Tx→broadcast→overlap→retire→archive→priv-destroy+7d + CheckDue diario + auto-extensión kid-unknown). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `key_rotation_total` + counts + overlap + max_age + kid-unknown + custody vía MetricsPort; spans Rotate/Retire/CheckDue. Fake metrics + gateway-report mock.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `key_rotation_test.go` (ok overlap/retiro, custody-fail aborta, doble 409, smoke-fail aborta, extensión 1 vez, cron-due). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_030_rotation_state.up/down.sql` (overlap/next/archive). `migrate up/down/up` PG16 + verifica due-query usa idx + archive inserta en retire.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/signing_key_store.go` (BeginRotationTx + RetireTx + CheckDue + archive) + `redis` mutex/PUBLISH/mode-overlap (down→líder local + `WARN`, sin doble-rotate cruzado documentado) + file0600/KMS custody. Tests testcontainers (PG+Redis) incl. doble-rotate y KMS-mock-down.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + custodia en `security/`. `security/ed25519_generator.go` + `kms_custody.go` (awskms|gcp|file0600 por env, smoke-test) + `kafka` tipos `keys.rotated|retired|extended` + audit; worker SMTP técnico + crons (02:00 due, horario retire, +7d destroy). Test KMS-down → 500 + reintento.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/keys_dto.go` + `handlers/keys_rotate.go` (POST admin+Step-Up `crypto:rotate` 202-async/409/429/500 + `GET /admin/keys` lista) + `require_step_up(crypto:rotate)` (12º scope, extiende matriz) + buckets. httptest: sin-Step-Up 401, ok 202+overlap, doble 409, flood 429, JWKS [B,A]→[B] + max-age 60→600.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go` + worker crons. Rutas admin + wiring Generator+Custody+Store → service (+Signer/Directory); env `ROTATION_PERIOD=90d, OVERLAP=1h, KMS_PROVIDER, STEP_UP crypto:rotate`; `/metrics` nuevas. `go build ./...` + smoke (rotate→overlap→retiro con tokens vivos sin 401) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose + gateway-mock: rotate (viejos+nuevos verifican) → overlap 1h (JWKS doble, max-age 60) → retiro (simple, 600, viejos expirados naturalmente) + manual sin/doble/KMS-down + extensión kid-unknown + archivo verifica-offline + priv-destroy +7d. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `rotation_smoke.js` Issue-concurrente p95<300ms + JWKS + flood + chaos KMS/cron. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: privada jamás PG/logs/bus (solo kid/pub/ref + smoke en memoria), mutex anti-doble, smoke-antes-publicar, overlap≥TTLmáx+cache (sin 401 prematuro), cache-60 overlap, archivo eterno pubs + destroy privs +7d, Step-Up manual (12º scope), `no-store` en admin. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
