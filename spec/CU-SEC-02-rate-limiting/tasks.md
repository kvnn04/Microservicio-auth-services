# Tareas de Implementación: CU-SEC-02

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/shared/`. `rate_limit.go` (Scope, Rule, Matrix vinculante §4.1, KeyFor, ResolveIP trusted/v6). Sin imports infra (solo net/netip).
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `shared/rate_ports.go` (RateLimiter: Allow + RetryAfter) + `rate_guard` errores RateLimited (con RetryAfter). `go vet` sin redis.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `rate_limit_test.go` (ResolveIP spoof/trusted, keys, Matrix sin rutas huérfanas, exentas). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `rate_guard.go` (Check: Allow→headers-info o 429+audit/métrica; exentos bypass+log) usado por middleware (no por casos). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `rate_limited_total{route,scope}` + allow 1% + fallback + config_version + ip_blocks vía MetricsPort; hijo `Defense.RateCheck` primero. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `rate_guard_test.go` (allow/deny, progresivo, exentos, config-inválida-conserva, spoof). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_021_ratelimit_noop.up/down.sql` (SELECT 1 + apéndice operativo). `migrate up/down/up` PG16 OK.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `redis/rate_limiter.go` (sliding_allow.lua con TIME Redis + ZSET + announcer/blocked + fallback memoria 2x + `WARN`) + `config/ratelimit.yaml` + hot-reload (env override, SIGHUP/poll, última-válida). Tests testcontainers (Redis) incl. down-fail-open + caballo-ventana determinista (mock TIME) + spoof.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/`. `kafka` audit `rate.limited` (10% flood) + `rate.ip_blocked` (siempre); sin SMTP. Test Kafka-down → 429 igual + pendiente.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. Middleware central `rate_limit.go` (primero, IETF headers siempre + 429 uniforme + exentos) + `ip_resolver.go` + `progressive_block.go`; recablea TODOS los handlers previos a usarlo (migra sus buckets inline a la matrix SIN cambiar valores; test `matrix-parity` compara viejos vs nuevos). httptest: 11º 429 + headers, caballo 429, exentos 200, spoof ignorado.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. Global antes de auth + allowlist healthz/metrics; wiring Limiter → Guard → middleware; env `TRUSTED_PROXIES, RL_*`; `/metrics` nuevas. `go build ./...` + smoke (login 11º 429, healthz 1000× 200) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: matrix por ruta (sensibles 10, lecturas 60, JWKS 100), progresivo 50→block, XFF tras proxy confiable vs spoof directo, Redis-down 0-500, healthz exento, `matrix-parity` verde. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `ratelimit_smoke.js` 429 correcto + headers + sliding-caballo + spoof + fallback + block. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: split 429-tráfico vs 401-lock intacto, sliding sin ráfaga, IETF headers (sin `route` en body), fail-open 2x (no barra-libre), XFF solo tras proxy (bypass cerrado), exentos mínimos, `no-store` en 429, config hot-reload validada. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
