# Tareas de Implementación: CU-SEC-01

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `brute_force.go` (consts 5/15m/15-120/cap/24h/1h, Backoff/ShouldLock/AccountKey). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/brute_policy.go` (BruteNotifier + reuso AttemptTracker: PreCheck/PostFail/PostSuccess/OnRegisterCleanup + errores solo internos). `go vet` sin redis.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `brute_force_test.go` (backoff cap, bordes, keys user vs acct:hash). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `brute_guard.go` (PreCheck 1-GET + PostFail INCR/lock/email-throttle + PostSuccess DEL + OnRegisterCleanup DEL ciego) inyectado en login/mfa_verify/step_up/change-password (sin duplicar lógica). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `failed_attempts_total{flow,locked}` + `locks_total` + duración + fallback + notify vía MetricsPort; hijo `Defense.BruteCheck` + 3 hijos. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `brute_guard_test.go` (5º lock+email, 6º 401 igual, buena-en-lock 401, éxito reset, multi-flujo suma, ciego sin email, cleanup registro). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_020_brute_noop.up/down.sql` (SELECT 1 + comentarios DBA). `migrate up/down/up` PG16 OK.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `redis/attempt_tracker.go` formal (Lua record_fail atómica, fixed-window EX900, backoff EX, count EX86400, notify NX EX3600, fail-open memoria 2x + `WARN`). Tests testcontainers (Redis) incl. down-fail-open + race 5-paralelos (1 lock, sin doble-email por NX).
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/`. `kafka` tipos `brute.locked` + audit `brute.check`; worker SMTP `brute_lock` (hasta HH:MM + IP/UA/hora + links, throttle) solo user conocido. Test Kafka-down → 401 + pendiente + inexistente sin email.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. Sin rutas nuevas: inyecta guard en 4 handlers + test `no-423` (ningún lock mapea a 423/429; `Retry-After` solo SEC-02) + `errors/map` sin códigos cliente nuevos. httptest: 6×401 idénticos + timing, email 1, buena-en-lock 401, éxito-reset.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. Sin rutas; wiring Tracker+Notifier → BruteGuard → 4 services; env `BRUTE_MAX=5, WINDOW=15m, LOCK=15m, CAP=120m`; `/metrics` nuevas. `go build ./...` + smoke (5 malas→lock+mail→buena 401→espera→buena 200) en compose. Abre Módulo 5.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose PG+Redis+Kafka+Mailhog: login×5→lock+1 mail→6º 401 igual→buena-en-lock 401→MFA/step-up suman al mismo lock→inexistente ciego sin mail→registro limpia ciego→Redis-down 0-locks→Kafka-down 401+pendiente. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `brute_smoke.js` 5º-lock + 6º+ idénticos `|p50|<40ms` 0×423/429-por-lock + multi-flujo + flood-IP (429 SEC-02, no lock) + backoff 15→30→60 + Redis-down. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: 401 único (sin USER/LOCK hints), PreCheck 1-GET sin rama temporal, dummy+jitter por flujo intactos, sin email/IP completa en keys/logs (hash//24), lock≠revoke (sesiones vivas, SES-02 aparte), fail-open documentado, fixed-window borde aceptado, `no-store`. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
