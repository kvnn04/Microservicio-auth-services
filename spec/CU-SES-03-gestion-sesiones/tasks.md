# Tareas de Implementación: CU-SES-03

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `sessions.go` (SessionView, MaskIP v4/v6, DeviceLabel). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/session_list_ports.go` (SessionLister: List/RevokeOne + errores UseLogout/NotFound). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `sessions_test.go` (máscaras, labels, orden). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `list_sessions.go` + `revoke_session.go` (List marca Current; RevokeOne valida ≠current + UUID + rate + Lister + email flag + jitter 404). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `sessions_listed_total` + `revoked_one_total` + duraciones vía MetricsPort; spans + 5 hijos sin tokens. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `sessions_test.go` (3 masked, actual flag, remote ok, actual→UseLogout, ajena/muerta→NotFound iguales, replay). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_018_session_labels.up/down.sql` (device_label/ip_masked/location + backfill doc). `migrate up/down/up` PG16 + verifica filas viejas muestran `unknown/migrated` sin romper lista.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/session_lister.go` (SELECT ordenado + RevokeOne Tx triple-capa + revoked_jtis target) + `redis/session_lister.go` (fast-path MGET + fallback PG, DEL+SET revoke, touch debounce EX300). Tests testcontainers (PG+Redis) incl. RedisDown y touch-debounce.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/`. `kafka` tipos `session.revoked_one` + audit (list solo audit, sin bus) + worker SMTP `session_closed_remotely` siempre (con device). Test Kafka-down → 200 + pendiente.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/sessions_dto.go` + `handlers/sessions_{list,revoke_one}.go` (GET 200+total / DELETE 200/400/404/429, `no-store`, jitter 404) + `middleware/session_touch.go` (debounce async) + buckets. httptest: A/B/C lista masked, revoke-C ok + A/B vivas, actual→400, ajena/muerta→404 iguales, PG-down 500-no-`[]`.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `GET /sessions + DELETE /sessions/:sid` con recover→requestID→auth→rateLimit→handler (+touch middleware global); wiring Lister → services; env `SESSIONS_RATE=*`. `go build ./...` + smoke (3→lista→revoca-C→lista-2→logout-A) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: A/B/C→lista 3 masked→revoca-C (mail)→lista 2→C-401→A/B-200→revoca-A→400→ajena-404→touch actualiza last_seen (debounce) →Redis-down 200→PG-down 500. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `sessions_smoke.js` list p95<120ms + revoke p95<200ms + floods 429 + chaos PG/Redis + touch-debounce medido. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: sin Step-Up justificado (defensa), solo-propias (sub en queries, sid aleatorio), actual-400 explícito, 404 único con jitter, masked (sin IP completa/tokens/jti/family), email siempre revoke, `no-store`, lista nunca solo-Redis-evictado. Dictamen `seguridad.md` PASSED + confirma Q4/Q5 supuestos o ajusta.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
