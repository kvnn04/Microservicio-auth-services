# Tareas de Implementación: CU-SEC-04

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/shared/`. `audit.go` (AuditAction, AuditEvent, CanonicalJSON, ChainHash, Validate denylist). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `shared/audit_ports.go` (AuditSanitizer.Check + AuditStore.AppendTx(strict/eventual)/QueryMe(cursor) + ErrAuditUnsafe). `go vet` sin pgx/kafka.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `audit_test.go` (canonical estable, chain vector, denylist por clave, cursor). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `audit_helper.go` (Build + MustAppendTx strict/eventual + QueryMe masked + migración v1→v2) usado por TODOS los llamadores (sin servicio propio). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `audit_appended_total{action}` + lag + dropped(0) + chain_break + unsafe(0) + verify-duration + purged vía MetricsPort; span `Audit.VerifyChain` nightly. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `audit_helper_test.go` (strict/eventual, unsafe fail-closed, QueryMe 20/20/10 estable con concurrentes, v1→v2 compat). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_023_audit_log.up/down.sql` (particionada mensual + idx + REVOKE U/D + GRANTs + partición 2026-10). `migrate up/down/up` PG16 + verifica app_role no puede UPDATE/DELETE + cursor usa idx.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/audit_store.go` (AppendTx strict FOR UPDATE + eventual + outbox misma Tx + QueryMe masked cursor) + workers `audit_drain/verify/purge/partition` en `cmd/worker` (drain→Kafka 1a, verify nightly chain+P1+congela-purga, purge >2a sin hold, crea mes+1 día 25). Tests testcontainers (PG+Kafka-mock) incl. chain-break detectado y partición auto.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + sanitize en `security/`. `security/audit_sanitize.go` (denylist + `audit_allowlist.yaml`) + `scripts/audit_pii_scan.sh` CI (contracts-ejemplos + tests, falla con secreto) + `kafka` tópico `auth.audit.v1` v2 (retención 1a) + DLQ. Test: fixture password → CI rojo + runtime 500 + unsafe+1.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/audit_dto.go` + `handlers/audit_me.go` (GET auth paginado cursor/limit, masked, `no-store`, 60/min) + `errors` (UNSAFE→500 genérico). httptest: 50 eventos → 20/20/10 estables + masked (sin PII) + cursor inválido 400 + PG-down 500-no-`[]`.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `GET /api/v1/auth/audit/me` con auth→rate→handler; wiring Sanitizer+Store → Helper → TODOS los services (migra sus Log a MustAppendTx v2); env `AUDIT_RETENTION=2a, KAFKA_AUDIT_RETENTION=1a`; `/metrics` nuevas. `go build ./...` + smoke (login→me lista masked→verify nightly ok) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose PG+Redis+Kafka: login→audit PG+Kafka<30s+me masked; kill-Kafka→200+pendiente+lag recupera; fixture-PII→500+unsafe; chain-break (superuser UPDATE test)→P1+purga congelada; purga hold; PG-audit-down→500 mutación + 500 me. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `audit_smoke.js` overhead p95<20ms + me p95<150ms + 0 drops + verify 100k p95<60s + chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: envelope único (migra v1), append-only GRANTs (UPDATE/DELETE denegados app_role), denylist+scanner CI (0 PII en ejemplos), masked me (sin IP/token/coords), fail-closed sin audit (sin mutación huérfana), chain nightly+P1, retención 2a + hold, `no-store`, SEC-05 gancho anonimización-vista (sin UPDATE). Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
