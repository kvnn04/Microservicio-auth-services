# Tareas de Implementación: CU-SEC-05

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/user/`. `deletion.go` (consts 30d/15min/7a, DeletionStatus, ConfirmDeletion email-tipado+accepted, AnonID). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `user/deletion_ports.go` (DeletionStore: RequestTx/CancelStart/CancelConfirmTx/ExecuteDue/ExecuteOneTx + errores Already/State/Invalid/Executed). `go vet` sin pgx/redis.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `deletion_test.go` (confirm matriz, anon estable, terminal ANONYMIZED). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `deletion_request.go` (Guard+confirm+rate→Tx corte→202+email) + `deletion_cancel.go` (opacos + restaura sin resucitar sesiones) + `deletion_execute.go` (cron due→hard+retention?+erased+reminder-25). Solo puertos + reuso GlobalRevoker/StepUp.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `deletion_total{op,result}` + pending/executed/retention vía MetricsPort; spans Request/Cancel/Execute + 5 hijos (anon, sin email). Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `deletion_test.go` (request corte+mail, re-request 409, cancel opaco+restaura, execute destroy+erased+libera-email, stale→401, PG-down 500). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_024_deletion_olvido.up/down.sql` (status enum ampliado + deletion_* + anon + cancel_tokens + retention_ledger + idx due + REVOKE retention). `migrate up/down/up` PG16 + verifica CHECK acepta 6 estados + app no UPDATE retention + executor usa idx.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/deletion_store.go` (RequestTx corte+revoke-all+mfa-off+outbox misma Tx; CancelConfirmTx restaura manteniendo valid_after; ExecuteOneTx destroy+anon+retention?+erased; ExecuteDue SKIP LOCKED) + `redis` sweep/quotas/reminder (down→PG). Tests testcontainers (PG+Redis) incl. cancel-tras-request y hard-irreversible (410).
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + cifrado en `security/`. Reuso `StepUp/token_issuer` + `secret_box` (retention AES-GCM `RETENTION_KEY`, auditor-only) + `kafka` tipos `deletion.requested|cancelled` + `user.erased` + `revoked_all{deletion}` + audit; worker SMTP solicitud/25 + executor diario + downstream reintento 24h+DLQ. Test Kafka-down → 202 + erased pendiente.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/deletion_dto.go` + 3 handlers (request auth+Step-Up 202/409/401/429, cancel-start opaco 202, cancel-confirm 200/400/410, `no-store`) + mapea login `DELETION_REQUESTED→401` opaco (NO 403; `403` solo posesión-probada) + rate deletion 3/día. httptest: triple-ok/corte+mail, fails 401/400/409, cancel-link restaura, login-viejo 401, re-registro post-hard 201.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go` + worker cron. 3 rutas deletion con auth(+Step-Up en request)→rate→handler; wiring Store+StepUp → services; cron `deletion-executor 04:00 + reminder-25`; env `DELETION_GRACE=30d, RETENTION_YEARS=7, ANON_SALT`. `go build ./...` + smoke (request→403?no→401→cancel→active→request→30d-fake→hard→erased→re-register) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose + Mailhog + satélite-mock: request→0 sesiones+mail→login 401 opaco→re-request 409→cancel-link→ACTIVE (TOTP on, backups off)→request→fake-30d→executor hard (PII muerta, anon, retention?, erased→satélite purga)→re-register 201→Redis/Kafka-down intactos. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `deletion_smoke.js` p95<400ms + executor 10k p95<5min sin dobles + re-registro + chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: triple-confirm (Step-Up+email+accepted), corte instantáneo (sesiones/MFA/backups), login-opaco en gracia (sin oráculo 403 anónimo), cancel-vía-buzón (no re-login 403), hard destroy+anon (chain intacta, vista SEC-04), retention mínima cifrada auditor-only, downstream fire-forget+DLQ, email-liberado limpio, `no-store`. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
