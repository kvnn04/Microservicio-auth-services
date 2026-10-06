# Tareas de Implementación: CU-CRED-03

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/user/`. `email_change.go` (consts 15min/32B/3/3-h/60s/5-día, Record+Alive, Parse, MaskEmail, reuso Normalize). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `user/email_change_ports.go` (EmailChangeStore: Request(taken)/FindAlive/ConfirmTx(re-UNIQUE+revoke_all) + errores Taken/Invalid/StepUp). `go vet` sin pgx/redis.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `email_change_test.go` (mask, parse 32B, TTL, quotas, race-taken conceptual). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `email_change_start.go` (Guard Step-Up→norm→rate→Request taken/throttled→doble-mail→202/409) + `email_change_confirm.go` (forma→rate→Find→bearer-check→ConfirmTx update+verified+valid_after+revoke_all→200 sin Issue). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `email_change_total{op,result}` + duración + fallback vía MetricsPort; spans Start/Confirm + 7 hijos (mask). Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `email_change_test.go` (fresco sent, stale 401, taken 409, throttled 429, ok revoke_all, race 409+burn, inválidos 400 iguales, bearer-ajeno 400, replay). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_015_email_change.up/down.sql` (PK hash + idx req). `migrate up/down/up` PG16 + verifica supersede 1-activo y re-UNIQUE race en Tx.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/email_change_store.go` (Request taken/supersede+outbox, ConfirmTx FOR UPDATE + re-taken→burn + update verified+valid_after + revoke_all + outbox×2 misma Tx) + `redis/email_change_store.go` (t/active/sent/count, Lua DEL, quotas, down→PG). Tests testcontainers (PG+Redis) incl. race 1×200/1×409 y bearer-ajeno.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + reuso seguridad. Reuso `token_issuer/Normalize/StepUp/Mask` + `kafka` tipos `email.change_requested|changed` + `session.revoked_all{email_change}` + audit; worker doble-SMTP (nuevo link-15min, viejo aviso-mask, changed al nuevo). Test Kafka-down → HTTP intacto.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/email_change_dto.go` + `handlers/email_change_{start,confirm}.go` (start auth+Step-Up 202/409/401/429 ≤2KB, confirm ±Bearer 200/400/409 ≤4KB, GET form no-consume, `no-store`, delay) + `require_step_up(cred:change-email)` + buckets. httptest: fresco/tomado/stale/throttled, confirm ok/race/inválidos/bearer-ajeno, doble-mail Mailhog.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /email/change/start|/confirm + GET /email/change` con auth(+Step-Up en start)→rate→handler; wiring Store+StepUp → services; env `EMAILCHANGE_TTL=15m, RATE=3/h, QUOTA=60s/5`. `go build ./...` + smoke (start→2mails→confirm→relogin-nuevo→viejo-401) en compose. Cierra Módulo 3.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose + Mailhog: start libre→2 mails→confirm (sin Bearer) 200 + 0 sesiones + relogin-nuevo 200/viejo 401; tomado→409; stale→401; throttled→429; race→409+burn; inválidos→400 iguales; bearer-ajeno→400; federated sub intacto. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `emailchange_smoke.js` starts 409/401/429 correctos + confirms p95<400ms `400` idénticos + race 1×200/1×409 + doble-mail. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: Step-Up mandatorio start, 409 solo autenticado+rate+audit, link 32B + solo hashes + 1-uso-1-activo, confirm ligado requester (modelo amenaza documentado), corte global + relogin, doble-mail sin token al viejo + mask, sin PII en logs/eventos, `no-store`. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra Módulo 3.
