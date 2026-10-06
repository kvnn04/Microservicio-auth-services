# Tareas de Implementación: CU-SES-02

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `logout_global.go` (GlobalRevokeResult). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/session_global_ports.go` (GlobalSessionRevoker: RevokeAll + counts). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. Compilación + shape result. `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `logout_global.go` (rate→idempotencia RequestID/event_id→RevokeAll Tx+sweep/pub+best-effort challenges→Output+email). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `logout_global_total` + `sessions_revoked_count` + duración vía MetricsPort; span + 5 hijos. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `logout_global_test.go` (3→3/0, repeat 0 mismo 200, expirado 401, 6º 429, RedisDown 200, PGDown 500). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_017_global_revoke_noop.up/down.sql` (idx user). `migrate up/down/up` PG16 + `EXPLAIN` barrido por user usa índices.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/global_revoker.go` (Tx valid_after+revoke+delete+outbox) + `redis/global_revoker.go` (SMEMBERS by_user→DEL+PUBLISH+challenges best-effort, down→PG+reconcilia). Tests testcontainers (PG+Redis) incl. 20 sesiones y repeat-0.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/`. `kafka` tipos `session.revoked_all` + audit `logout_global`; worker SMTP global (N+hora/IP); gateways mock suscritos a PUBLISH (~1s) además de Kafka. Test Kafka-down → 200 + pub/sub compensa.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/logout_global_dto.go` + `handlers/logout_global.go` (POST auth-base → 200+counts+Clear-Cookie / 401/429/500, `no-store`) + buckets 5/hora+20/hora. httptest: A/B/C→global 3→todos 401+Refresh 401, repeat 0, expirado 401, flood 429, PG-down sin cookie.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /api/v1/auth/logout-global` con recover→requestID→auth-base→rateLimit→handler; wiring Revoker → service; env `LOGOUT_GLOBAL_RATE=5/h`. `go build ./...` + smoke (3 sesiones→global→0→relogin 1) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: A/B/C→global→0 vivas+email+Clear-Cookie→APIs 401 (≤1s pub/sub o ≤60s cache)+Refresh 401→repeat 0→rate 429→Redis-down 200→PG-down 500. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `logout_global_smoke.js` p95<300ms (20 sess), repeat/revoke counts, flood, gateway-ventana medida, chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: POST+Bearer (no GET), sin Step-Up justificado (defensa), Tx atómica (0 vivas), sin N-denylist (valid_after+revoked), idempotente, sin tokens en logs/eventos, Clear-Cookie, `no-store`, pre-token residual documentado ≤15min. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
