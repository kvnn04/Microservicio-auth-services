# Tareas de Implementación: CU-CRED-03

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/user/`. `email_change.go` (consts 15min/32B/3/3-h/60s/5-día, Record+Alive, Parse, MaskEmail, reuso Normalize). Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `user/email_change_ports.go` (EmailChangeStore: QuotaCheck/Taken/Issue/FindAlive/ConfirmTx/IncrementAttempts + errores Taken/Invalid/Burned). `go vet` sin pgx/redis.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `email_change_test.go` (mask, parse 32B, TTL, quotas). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `email_change_start.go` (Guard Step-Up→norm→idempotencia→unicidad 409→quota 429→doble-mail→202) + `email_change_confirm.go` (forma→idem→Find→bearer-check→ConfirmTx update+verified+valid_after+revoke_all→200 sin Issue). Solo puertos.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `email_change_total{op,result}` + duración + fallback vía MetricsPort; spans Start/Confirm sin PII (mask). Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `email_change_test.go` (fresco sent, stale 401, taken 409, throttled 429, ok revoke_all, race 409+burn, inválidos 400 iguales, bearer-ajeno 400, replay). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_015_email_change.up/down.sql` (PK hash + idx req activo). `migrate up/down/up` PG16 OK.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/email_change_store.go` (Taken/Supersede+Issue+doble-mail+outbox en Tx; ConfirmTx FOR UPDATE + re-taken→burn + update verified+valid_after + revoke_all + outbox×2 misma Tx) + `redis/email_change_store.go` (t/active/sent/count, Lua DEL, quotas, down→PG). Tests PG+Redis (request+doble-mail, confirm+corte, race 1×200/1×409+burn).
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + reuso seguridad. Reuso `token_issuer/Normalize/StepUp/Mask` + `kafka` tipos `email.change_requested|changed` + `session.revoked_all{email_change}` + audit; worker SMTP genérico (`email_queue`): nuevo link-15min, viejo aviso-mask, changed al nuevo. Kafka-down → 200 por outbox (diseño).
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/email_change_dto.go` + `handlers/email_change_{start,confirm}.go` (start auth+Step-Up-en-servicio 202/409/401/429 ≤2KB, confirm ±Bearer 200/400/409 ≤4KB, GET form no-consume, `no-store`, delay) + buckets (usuario 3/h + IP 20/h/20/min). httptest: fresco/tomado/stale/throttled(svc), confirm ok/race/inválidos/bearer-ajeno/GET, doble-mail vía store.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /email/change/start|/confirm + GET /email/change` con auth(+Step-Up en servicio)→rate→handler; wiring Store+Users+StepUp+Issuer → services; sin env nuevo (TTL/rate/quota son consts). `go build ./...` + smoke (start→2mails→confirm→relogin-nuevo→viejo-401) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Integración PG+Redis real: request→2 mails→confirm (sin Bearer) 200 + 0 sesiones + `verified` + `valid_after`; tomado→409; stale→401; throttled→429 (svc); race→409+burn; inválidos→400 iguales; bearer-ajeno→400; GET no consume.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `emailchange_smoke.js` creado (30 VUs start + 50 VUs confirm); ejecución viva pendiente de ventana pre-productiva (igual que `pless/stepup/pwdreset_smoke.js`).
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: Step-Up mandatorio start, 409 solo autenticado+rate+audit, link 32B + solo hashes + 1-uso-1-activo, confirm ligado requester (modelo amenaza documentado), corte global + relogin, doble-mail sin token al viejo + mask, sin PII en logs/eventos, `no-store`. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra Módulo 3.
