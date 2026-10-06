# Tareas de Implementación: CU-AUTH-06

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `step_up.go` (StepUpScope 10 valores + Valid, DecideStepUp fresco/relogin, consts 5min). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/stepup_ports.go` (StepUpChallenger CheckPassword/CheckSecondFactor, StepUpIssuer Issue, StepUpVerifier VerifyFor + errores Required/Invalid/Reused/Relogin/UnknownScope/Unavailable). `go vet` sin jwt/redis.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `step_up_test.go` (scopes, bordes 5min, sub/scope mismatch conceptual). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `step_up.go` (Challenge: scope→rate→doble-factor/dummy+jitter→Issue jti+Reset; Guard: fresh?fast_pass:VerifyFor+burn). Solo puertos + reuso AttemptTracker/Signer.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `step_up_total{op,result}` + duración + `reuse_blocked` vía MetricsPort; spans Challenge/Guard + 6 hijos sin secreto. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `step_up_test.go` (fast-pass, doble-ok token 1-scope, pass-mala==totp-mala 401, federated-stale relogin, replay reused, cross-scope invalid, RedisDown unavailable + fast-pass ok, idempotencia 60s). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_012_stepup_noop.up/down.sql` (SELECT 1 + comentario ENFORCE futuro). `migrate up/down/up` PG16 OK (sin tablas).
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `redis/stepup_store.go` (SET NX EX300, Lua GET+DEL, buckets 10/min/user + 30/min/ip, down→Unavailable fail-closed) + reuso PG users/mfa/backup lecturas. Tests testcontainers (Redis) incl. down + replay-determinista.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + firma en `security/`. Reuso `ed25519_signer` aud=step-up + `kafka` tipos `stepup.passed|failed|reused` + audit; sin SMTP. Test aud distingue scope/jti sin token + Redis-down 500 medido.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/step_up_dto.go` + `handlers/step_up_challenge.go` (POST 200-token/400/401/429/500) + `middleware/require_step_up.go` (Guard genérico scopeado: fast-pass o header, mapea REQUIRED/INVALID/REUSED/RELOGIN) + recableo REG-06/MFA/backup a él (compat ambos). httptest: fresco sin token 200, stale sin token 401+scope, doble-ok token 1-uso-1-scope, replay/relogin/cross-scope, Redis-down 500 + fast-pass 200.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /api/v1/auth/step-up/challenge` + guards en 8 ops (existentes recableadas, futuras declaran scope); wiring Challenger+Issuer+Verifier+Tracker → services; env `STEP_UP_MAX_AGE=300s, STEP_UP_TTL=300s, ENFORCE_STEP_UP_TOKEN=false`. `go build ./...` + smoke (fresco, challenge-doble, replay, federated-stale) en compose. Cierra Módulo 2.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: fresco link/unlink/disable/backup-regen sin token; stale→401→challenge-doble→token→op 1 vez→replay 401; federated-stale→relogin; cross-scope 401; último-factor intacto con token (Step-Up no bypasea RN). Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `stepup_smoke.js` challenge p95<400ms, guards fast-pass p95<10ms / token p95<50ms, replay/cross-scope 100% mapeados, Redis-down 500 + fast-pass 200, lock 401. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: scopes cerrados, doble-factor cuando ambos, aud-aislado 1-uso-1-op 5min + sub/scope amarrados, sin token en negocio, sin secretos en logs/eventos, fail-closed Redis (fast-pass offline ok), `no-store`, open-scope cerrado. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra Módulo 2.
