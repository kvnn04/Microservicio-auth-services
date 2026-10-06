# Tareas de Implementación: CU-REG-06

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/user/` y `internal/domain/auth/`. `link_policy.go` (MaxLinked 5, StepUp 5min, CountFactors, CanUnlink LAST_AUTH_FACTOR, RequireFreshAuth) reuso `FederatedIdentity/OIDClaims/User`. Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `federated_link.go` (FederatedLinkStore: LinkTx/UnlinkTx/ListByUser + errores Self/Collision/Taken/NotLinked/LastFactor, LinkStateStore Save/Consume + ErrNotFound) extendiendo `FederatedRepository` CU-REG-04. `go vet` sin pgx/redis/oauth.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `link_policy_test.go` (factores password+2fed, último inamovible, frescura 4:59 vs 5:01, provider tomado). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `link_federated.go` (Initiate con Step-Up+password + SaveState), `LinkCallback` (user-match→Exchange→Verify→LinkTx con mapeo already/collision/taken), `unlink_federated.go` (Step-Up→CanUnlink→UnlinkTx+aviso), `list_linked.go`. Idempotencia RequestID + reuso cliente OIDC abstracto.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `federated_link_total{provider,op,result}` + `unlink_last_factor_blocked_total` vía MetricsPort; spans Initiate/Callback/Unlink + hijos stepup/state/oauth/db/outbox. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `link_federated_test.go` (stale→401, pass mala→401, mismatch→400, libre→linked, self→already, ajeno→409+notify, taken→400, último→400, ok→email, PENDING→403). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_006_link_constraints.up/down.sql` (UNIQUE(provider,user_id)). `migrate up/down/up` PG16 + prueba doble-sub mismo provider mismo user → `unique_violation` mapeada a `PROVIDER_ALREADY_LINKED`.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/federated_link_store.go` (LinkTx INSERT+mapeo constraints, UnlinkTx DELETE RETURNING, ListByUser+hasPassword) + `redis/federated_link_state.go` (SET NX EX 600, Lua GET+DEL, down→500 fail-closed). Tests testcontainers (PG+Redis) incl. colisión concurrente determinista.
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + reuso identidad. Mismo `google_oidc_client` con callback link registrado + tipos `federated.linked/unlinked/link_collision` + audit; worker emails link/bienvenida-colisión/unlink-aviso (siempre avisa unlink). Test Kafka-down → 200 intacto.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/federated_link_dto.go` + 4 handlers (initiate 200-url, callback GET auth, unlink DELETE/POST, list GET) + `require_auth/require_fresh_auth` + buckets link + allowlist; mapea STEP_UP/INVALID/LINKED/TAKEN/LAST_FACTOR/NOT_LINKED/502. httptest: initiate stale 401, callback mismatch 400, link ok/already/409, unlink último 400/ok, list enmascara, replay 400.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. 5 rutas link bajo `/federated/:provider` + `/linked` con recover→requestID→auth→freshAuth(donde aplica)→providerAllow→rateLimit→handler; wiring LinkStore+LinkState+OIDC+Hasher → services; env `STEP_UP_MAX_AGE=300s, MAX_LINKED=5`. `go build ./...` + smoke curl (initiate→mock-IdP→callback, list, unlink) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose + fake-IdP + Mailhog: ACTIVE fresco link G999→linked+login-google OK, self→already, B mismo sub→409+2 mails, provider-taken→400, stale→401, PENDING→403, unlink único→400, unlink con 2 factores→200+mail, list enmascara. Evidencia PR.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `link_smoke.js` 30VUs link p95<500ms + colisión 2-users determinista + replay 400 + Redis-down 500 medido + IdP-5xx 502 sin filas + stale 100% 401. Adjunta summary.
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: state-user-match obligatorio, callbacks distintas anónima/link, Step-Up 5min + password confirm, último inamovible, sin mover subs entre cuentas, sin sub plano en lista/logs (hash), secret solo back, `no-store`, open-redirect cerrado. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra Módulo 1.
