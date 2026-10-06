# Tareas de Implementación: CU-PRIV-02

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/shared/`. `consents.go` (Purpose 6 valores + Essential/Default). Extiende `legal.go` sin romperlo. Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. Extiende `ConsentLedger` (SetStatus/History/Current + errores Essential/Unknown). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `consents_test.go` (matriz esencial/opcional/default/server-stamped). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `consent_panel.go` (Get catálogo+estados + Set: essential-guard→idempotente→Tx insert+outbox+profiling-flag). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `consent_changes_total{purpose,status}` + essential-blocked + sat-lag vía MetricsPort; spans Get/Set + 3 hijos. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `consent_panel_test.go` (toggle+historial, esencial-400, already-sin-fila, unknown-404, profiling-off). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_033_consent_purposes.up/down.sql` (CHECK ampliado + status + seed 4 textos + backfill revoked + idx). `migrate up/down/up` PG16 + verifica REG-05 intacto + backfill sin duplicar + `DISTINCT ON` usa idx.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. Extiende `postgres/legal_repository.go` (SetStatus sella-activa + History/Current + outbox misma Tx) + `redis` rate + `profiling:off` flag (down→PG). Tests testcontainers (PG+Redis) incl. re-toggle rápido y concurrently-sets (último gana, historia conserva ambos).
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/`. `kafka` tipos `consent.changed` + audit `consent.set`; worker SMTP `profiling_off` informativo (1 vez/revoke) + injerto travel/device skip (`profiling:off` check). Test Kafka-down → 200 + pendiente + satélite-mock aplica al recuperar.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/consents_dto.go` + `handlers/consents_{get,set}.go` (GET 200 catálogo + PUT 200/400/404/429, auth-simple, `no-store`) + buckets 30/min. httptest: panel 6 propósitos, toggles+historial, esencial-400+link, already, unknown, flood 429.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. 2 rutas privacy con auth→rate→handler; wiring Ledger → service (+travel/device leen flag); env `CONSENT_RATE=30/min`; `/metrics` nuevas. `go build ./...` + smoke (panel→toggle→historial→satélite-mock→profiling-skip) en compose. Cierra Módulo 8 y sistema (33/33).

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: panel 6 (3 locked-esenciales + 3 toggles) → grant/revoke marketing (satélite suspende/reanuda, login intacto) → terms-revoke 400 → already sin fila → profiling-off → travel-skip + 1 mail → Kafka-down 200+pendiente. Evidencia PR final.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `consents_smoke.js` p95<150ms + idempotentes + flood + chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: 6 propósitos versionados (sin libres), esencial-vía-borrado (sin bypass), append-only (sin UPDATE, historia intacta), server-stamped (sin OUTDATED-toggle), satélites eventual (sin 2PC, con DLQ), login/core ciegos a opcionales, `no-store`. Dictamen `seguridad.md` PASSED final + revisión SDD global (33 specs coherentes, sin contradicciones matriz/puertos).
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra sistema.
