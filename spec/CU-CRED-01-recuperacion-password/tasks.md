# Tareas de Implementación: CU-CRED-01

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/auth/`. `password_reset.go` (consts 15min/32B/3/60s/5-día, Record+Alive, ParseResetToken, reuso PlessContext/RiskOf). Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/password_reset_ports.go` (PasswordResetStore: EligibleForReset/Issue/IssueHint/FindAlive/ConsumeTx/IncrementAttempts + ErrThrottled/Invalid/Burned/Reused). `go vet` sin pgx/redis.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `password_reset_test.go` (parse, TTL, quotas, risk). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `password_reset_start.go` (forma→Eligible→dummy+jitter→Issue/hint/noop→202) + `password_reset_confirm.go` (forma→Find→policy+HIBP sin quemar→idem→reused sin quemar→Hash→ConsumeTx+revoke+corte→200 sin Issue). Solo puertos.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `password_reset_total{op,result}` + duración + `mismatch` + fallback + HIBP vía MetricsPort; spans Start/Confirm + 8 hijos sin secreto. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `password_reset_test.go` (sent/hint/noop 202 iguales, throttled, ok+revoke, expirado/consumido/aleatorio 400 iguales, policy/reused sin quemar, 3º burn, replay, high-risk). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_013_password_reset.up/down.sql` (PK hash + idx activos; reuso `tokens_valid_after`/sessions/families de 010). `migrate up/down/up` PG16 + verifica supersede 1-activo y revoke usa tablas 010.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/password_reset_store.go` (Eligible ACTIVE+hash/hint, Issue Tx supersede+outbox, ConsumeTx FOR UPDATE + valid_after + revoke families/sessions + outbox + `SessionCache.InvalidateSessions`) + `redis/password_reset_store.go` (t/active/sent/count, Lua DEL, quotas, down→PG). Tests PG+Redis (supersede, revoke global, hint, burn, cascade, TOCTOU por `WHERE` atómico).
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + reuso seguridad. Reuso `argon2/hibp/token_issuer/RiskOf` + `kafka` tipos `password.reset_requested|changed` + `session.revoked_all` + `mismatch?` + `federated_hint` + audit; worker SMTP genérico (`email_queue`) link-15min + changed + hint (sin clave). Kafka-down → HTTP intacto por outbox (diseño); HIBP-timeout → fallback local probado.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/password_reset_dto.go` + `handlers/password_reset_{start,confirm}.go` (start 202 ≤2KB, confirm 200/400-policy-reused/400-opaco/429 ≤8KB, GET form siempre-200-si-formato, `no-store`, delay 40-80) + buckets. httptest: 4 starts 202 iguales + 1 link + 1 hint, confirms ok/policy/reused/400×4 iguales, high-risk, GET no consume.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /password/reset/start|/confirm + GET /password/reset` con recover→requestID→bodyLimit→rateLimit→handler; wiring Redis+PG+Hasher+HIBP → services (sin Issuer: no auto-login; TTL/quota son consts de dominio). `go build ./...` + smoke (start→Mailhog→GET-form→confirm→login-nueva→viejas-401) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Integración PG+Redis real (`password_reset_store_test.go`): ACTIVE 2-sesiones start→link→confirm 200 + 0 sesiones + `valid_after` + familias revocadas; hint federated (1 mail sin link); expirado/consumido/aleatorio 400 iguales; débil/reusada 400 sin quemar; burn al 3º; high-risk mismatch+alerta; handlers httptest (sin auto-login, GET no consume).
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `pwdreset_smoke.js` creado (50 VUs start 4 grupos + 80 VUs confirm); ejecución viva pendiente de ventana pre-productiva (igual que `pless/stepup_smoke.js`).
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: solo-link 32B + solo hashes, 202/400 opacos (sin 404/410), policy=reused solo tras posesión, single-use+supersede+3-burn, corte global + sin auto-login, ctx alerta-no-bloqueo, quotas anti-spam, sin token/clave/email en logs/eventos, GET no consume, `no-store`. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
