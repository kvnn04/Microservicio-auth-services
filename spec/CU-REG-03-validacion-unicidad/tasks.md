# Tareas de Implementación: CU-REG-03

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/user/`. `uniqueness.go` (ProbeOutcome, UniquenessResult, DecideProbe ShouldNotify/GenericOutput helpers, EmailHash/IPHash sha256). Reuso `User/Email/Password` CU-REG-01 sin modificar. Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `user/uniqueness.go` (UniquenessChecker.Probe + NotifyThrottle.AllowOwnerNotify + ErrInfra) adaptando `UserRepository.FindByEmailNormalized` + `shared.EventPublisher`. `go vet` confirma `domain` sin pgx/redis/kafka.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `uniqueness_test.go` (matriz found×throttle, hash determinista, plus-tag preservado, IDN). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `uniqueness_policy.go` + injerto en `register_user.go`/`resend_verification.go` (Probe→DummyHash+jitter 80-120ms siempre→outbox notify si found+allowed→Output genérico idéntico). Sin rama que filtre `found` al handler.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `uniqueness_probes_total{outcome}` + `notify_owner_enqueued_total` + `ip_blocks_total` vía `MetricsPort`; span hijo `Domain.CheckUniqueness` + hijos db/dummy/throttle/outbox. Fake metrics en test.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `uniqueness_policy_test.go` + `register_shadow_test.go` (unique vs shadow mismo Output, throttled solo audit, RedisDown fail-open, PG err→ErrInfra). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_003_uniqueness_noop.up/down.sql` (verifica UNIQUE, sin tablas nuevas; documenta forense opcional desactivada). `migrate up/down/up` PG16 OK.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres` reuso SELECT existente (`statement_timeout 2s`, usa índice) + `redis/notify_throttle.go` (SET NX EX 3600 + INCR día EX 86400, fail-open true) + `redis/rate_limit.go` extendido (buckets register/resend + `blocked:ip` 50x429/15min EX 900). Tests testcontainers incl. RedisDown.
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/`. Reuso `kafka/user_producer.go` + tipos `security.registration_attempted` → `auth.security.registration_attempted.v1` (key email_hash) + audit `uniqueness.probe`; worker plantilla SMTP con links login/forgot (sin token) + throttle respeta. Test: Kafka down → HTTP 201 intacto + lag recupera.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. Sin rutas nuevas: endurece `handlers/register.go` + `resend` (mismo schema/headers, sin user_id, `no-store`, veto `409/422` con assert test) + test `shadow_equality_test.go` (bodies byte-idénticos salvo RequestID). Rate-limit middleware con progresivo + `Retry-After`.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. Sin rutas nuevas; wiring `UniquenessChecker+NotifyThrottle+DummyHasher` en `RegisterUser/Resend` services; env `NOTIFY_THROTTLE_H=1, NOTIFY_MAX_DAY=3, IP_BLOCK_THRESHOLD=50`; `/metrics` expone nuevas métricas (privadas). `go build ./...` + smoke curl (nuevo vs existente mismo 201 + Mailhog 1º sí/2º no).

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose PG+Redis+Kafka+Mailhog: nuevo→201+PENDING, existente→201 idéntico+0 filas+SMTP 1º sí/2º throttled, resend nuevo/existente→202 idénticos, Redis down→201s intactos, Kafka down→201s intactos. Evidencia PR.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `uniqueness_timing.js` (100 unique vs 100 shadow: `|p50 diff|<80ms` bloqueante, p95<600ms) + `harvest_abuse.js` (60 mails/2min→429 desde 11º, blocked tras 50). Adjunta summaries.
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: sin endpoint disponibilidad, sin `409/taken/exists` al cliente, bodies/headers idénticos, dummy Argon2 real+jitter, sin email/token en logs/audit (hashes), notify sin token + throttle anti-acoso, SQL parametrizado, `no-store`, progresivo efectivo. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
