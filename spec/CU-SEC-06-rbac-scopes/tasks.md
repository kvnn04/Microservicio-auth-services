# Tareas de Implementación: CU-SEC-06

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `rbac.go` (Role 3 valores + Valid, ResolveScopes+SCOPES_VER, IsLastAdmin). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/rbac_ports.go` (RoleStore: List/ChangeTx + ScopeResolver + errores Forbidden/Unknown/LastAdmin/NotFound/Stale). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `rbac_test.go` (scopes por rol, snapshot, last-admin). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `role_change.go` (autoriza admin+scope→rate→ChangeTx revoke-all+ver(+valid_after si force)→200+email) + `role_bootstrap.go` (opaco+link+único) + injertos Issue(snapshot)/Rotate(ver-check→403). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `role_changes_total` + stale + fallback + drift + bootstrap vía MetricsPort; spans Change/Bootstrap/Resolve/Check. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `role_change_test.go` (grant revoke-all, upgrade revoca, stale 403, support 403, unknown 400, inexistente 404, bootstrap 2º opaco, force valid_after). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_025_rbac.up/down.sql` (catalog+user_roles+roles_ver+bootstrap+flags+backfill user). `migrate up/down/up` PG16 + verifica backfill + FK catalog + ver default 1.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/role_store.go` (List + ChangeTx con revoke-all inline + outbox misma Tx + bootstrap_tokens + flags) + `redis` roles:ver cache/pub + sweep reuso (down→PG). Tests testcontainers (PG+Redis) incl. LAST_ADMIN concurrente (2 quits mismo último → 1×200+1×400 por Tx).
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + resolve en `security/`. `security/scope_resolve.go` (código vs DB, DB manda + drift metric) + `kafka` tipos `roles.changed` + `revoked_all{roles_changed}` + audit + bootstrap; worker SMTP `roles_changed` siempre + pub/sub ~1s. Test Kafka-down → 200 + pendiente (gateway ≤60s).
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/rbac_dto.go` + `handlers/roles_{change,bootstrap}.go` (POST admin 200/400/403/404/429 + bootstrap opaco, `no-store`) + `middleware/require_roles.go` (admin+scope + Rotate stale-check) + recableo Issue/Rotate. httptest: grant/revoke+email, upgrade revoca, stale 403, prohibiciones, bootstrap único, force.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. 3 rutas admin + guards; wiring Store+Resolver → services (+Issue/Rotate injertos); env `SEED_ADMIN_EMAIL, BOOTSTRAP_ENABLED, SCOPES_VER`; `/metrics` nuevas. `go build ./...` + smoke (seed→bootstrap→grant→login-snapshot→revoke→stale→relogin) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: bootstrap E→admin→grant U support→U relogin snapshot→gateway U/admin-ruta 403/200 según rol→revoke→U 403 stale→relogin user→último-admin protegido→support grant 403→Redis/Kafka-down intactos. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `rbac_smoke.js` p95<300ms + gateway-stale ≤1s/60s + rotate-stale + flood 429 + chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: sin auto-promoción (bootstrap-único+link+rate+disable), snapshot+ver (Rotate no escala), todo-cambio revoca (+force valid_after), emiten/enforzan (JWKS+ver-cache), M2M separado (sin roles), granted_by trazable, sin PII en JWT (códigos), `no-store`. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
