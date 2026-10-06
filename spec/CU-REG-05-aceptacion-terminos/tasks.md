# Tareas de Implementación: CU-REG-05

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/shared/`. `legal.go` (DocType, LegalDocument+ValidateFormat, ConsentRecord+New, ValidateConsentInput → ErrTermsRequired/ErrInvalidFormat). Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `shared/legal_ports.go` (LegalVersionProvider.GetActive + ConsentLedger.RecordTx(tx any) + ErrTermsRequired/ErrTermsOutdated{Active}/ErrInfra). `go vet` confirma shared sin pgx/redis.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `legal_test.go` (matriz accepted×format×match, hash/url exigidos, UNIQUE conceptual user/doc/version). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `legal_consent.go` (CheckFast + CheckAgainstActive + injerto pre-Probe en `register_user.go`/`register_federated.go`/authorize-pre-302 + RecordTx dentro de Tx negocio con `ON CONFLICT DO NOTHING`). Sin I/O fuera de puertos.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `consent_recorded_total{doc,source}` + `consent_rejected_total{reason}` + `legal_active_version_info` vía MetricsPort; span `Legal.CheckConsent` + hijos fetch/validate/insert. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `legal_consent_test.go` (rechazo pre-Probe sin llamar Probe/Hasher, outdated trae activas, replay no duplica, federated source, PG-ErrInfra→500). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_005_legal_consent.up/down.sql` (legal_versions + consent_records + UNIQUEs + seed v2026.10 con hashes reales artefactos + REVOKE UPDATE/DELETE app_role). `migrate up/down/up` PG16 + verifica `UPDATE consent_records` como app_role → `permission denied` + FK a versión inexistente rechaza.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/legal_repository.go` (GetActive 2 filas, RecordTx con cast pgx.Tx, revalida DB aunque Redis diga hit) + `redis/legal_cache.go` (GET/SET EX 3600, purga por `pg_notify`/TTL, GET-handler tolera env-fallback pero register no). Tests testcontainers (PG+Redis) incl. Redis-down y PG-down fail-closed.
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/`. Reuso `kafka/user_producer.go` + tipo `legal.consent_recorded` → `auth.legal.v1` (array 2 consents) + audit `legal.consent`; sin SMTP. Test: Kafka down → 201 intacto + lag recupera, evento sin texto legal.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `handlers/legal_active.go` (GET 200+stale, `public max-age=3600`, 60/min/IP) + endurece `register/federated_authorize` (400 REQUIRED/OUTDATED+meta.active, sin user_id, falla pre-Probe) + `errors/map.go`. httptest: GET hit/miss/stale, POST sin-terms→400, vieja→400+meta, vigente→pasa, federado sin-terms→400 pre-302.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `GET /api/v1/legal/active` pública + wiring `LegalVersionProvider+ConsentLedger` en register/federated; env `LEGAL_FALLBACK_VERSIONS`, `LEGAL_CACHE_TTL=1h`; `/metrics` nuevas métricas. `go build ./...` + smoke curl (GET, register vigente/vieja/sin, federated authorize sin/con).

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose PG+Redis+Kafka: GET activas→register vigente 201+2 filas ledger+evento, vieja 400+meta+0 filas, sin-terms 400+0, federado sin-terms 400 pre-302, PG-down POST 500+0 huérfanos y GET stale 200, replay mismo RequestID 1 juego filas. Evidencia PR.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `legal_smoke.js`: GET 200VUs p95<50ms hit-rate>95%, POST-vieja 20% 100% 400 p95<60ms 0 inserts. Adjunta summary + verifica alerta outdated >10% con webhook mock.
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: sin POST consent standalone que duplique, bloqueo pre-Probe sin oráculo existencia, OUTDATED solo revela versiones públicas, ledger sin UPDATE/DELETE (GRANT test), sin texto legal/IP completa en logs/eventos, checkbox no pre-marcado (front, contrato), `no-store` en 400 auth + `public` solo en GET legal. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
