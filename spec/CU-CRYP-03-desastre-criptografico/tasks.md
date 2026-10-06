# Tareas de Implementación: CU-CRYP-03

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `emergency.go` (consts rate-1h/batch-1000/no-store/kill-switch, ConfirmPhrase, EmergencyKey). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/emergency_ports.go` (EmergencyRevoker: RevokeKid/BumpEpoch/Sweep/IssueSuccessor + EmergencyGate + errores Confirm/Already/DoubleFire/Disabled). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `emergency_test.go` (frase exacta, epoch, cursor). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `emergency_revoke.go` (gate→rate-global→triple→drill-rollback|purge→epoch→sweep-async→sucesora→broadcast+bulk→202) + `emergency_sweep.go` (batches reanudables). Solo puertos + reuso Rotation/Custody/Directory.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `emergency_total` + progreso + epoch + emergency-mode + mail-lag + kid-unknown vía MetricsPort; span + 9 hijos. Fake metrics + pager mock P1.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `emergency_revoke_test.go` (triple-ok, frase-mal 0-cambios, drill rollback, doble 429, kid-muerto 404, custodia-fail contención+retry). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_031_emergency_epoch.up/down.sql` (crypto_epoch + emergency_retired + forensics). `migrate up/down/up` PG16 + verifica epoch lee gateways + sweep usa cursor.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/emergency_store.go` (RevokeKid + BumpEpoch + SweepBatch SKIP LOCKED + IssueSuccessor-sin-overlap + archive-forensics) + `redis` (active/fire-rate/pubsub/cursor; down→poll-10s) + `system_flags` epoch. Tests testcontainers (PG+Redis) incl. reanudable-tras-caída y doble-fuego.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + custodia en `security/`. Reuso generator/kms (destroy-YA) + `ed25519_verifier` (+epoch-check toda JWT) + `kafka` crítico (`keys.emergency` + `epoch_bumped` + `revoked_all{key_compromise}` + audit P1); worker bulk-mail 10k/min + pager P1 + crons (sweep, sucesora-retry 1min×60). Test custodia-down → contención + Issue-500.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/keys_emergency_dto.go` + `handlers/keys_emergency{,_status}.go` (POST triple-`202` + GET progreso / 400/401/404/409/429/503, `no-store`) + `require_step_up(crypto:emergency)` (13º scope) + recableo verificadores (`iat<epoch → 401 EMERGENCY_RELOGIN`, front-banner). httptest: triple-ok/drill/doble/frase/kid-muerto/disabled + JWKS-purge + banner.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go` + worker. 2 rutas emergency + guards; wiring Revoker → service; env `EMERGENCY_ENABLED, EMERGENCY_RATE=1/h`; `/metrics` + runbook `docs/key-emergency-runbook.md` (1 página: quién aprieta, frase, drill trimestral, post-mortem). `go build ./...` + drill en staging (0 cambios) + game-day anual. Cierra Módulo 7.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose (staging): fuego (purga<5s + epoch + sweep-100% + sucesora + broadcast + bulk + banner) + drill-0-cambios + doble-429 + frase-400 + kid-muerto-404 + disabled-503 + custodia-down (contención + Issue-500) + PG-down (500 fail-closed). Evidencia PR + post-mortem plantilla llena en seco.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `emergency_smoke.js` fases1-2 p95<5s + sweep + JWKS-purge + banner + bulk-sin-bloqueo + reanudable. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec + Game-Day (Security Gate + simulacro). Checklist: triple-rojo (13º scope + frase + 1/hora + P1), sin-overlap (purge+no-store), epoch-toda-JWT (cualquier aud) + batches reanudables, sucesora-ya + destroy-YA + archiva-pub, broadcast+bulk+banner (sin links sesión), drill-trimestral con mismo path, `EMERGENCY_ENABLED` kill-switch, post-mortem plantilla. Dictamen `seguridad.md` PASSED + acta game-day firmada.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra Módulo 7.
