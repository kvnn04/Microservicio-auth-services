# Tareas de Implementación: CU-AUTH-01

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/auth/`. `login.go` (LoginOutcome, Device, DecideLogin, ShouldLock, LockDuration 15/30/60, consts límites/TTL/jitter). Reuso `User.CanAuthenticate/mfa` sin modificar schema (flag en migración). Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/authenticator.go` (CredentialStore, AttemptTracker, SessionIssuer, MFAPreTokenIssuer + ErrValidation/RateLimited/InvalidCredentials/Infra). `go vet` sin pgx/redis/jwt en domain.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `login_test.go` (matriz found×verify×locked×status×mfa, lock 5→true, duración exponencial, PENDING/federated→Invalid). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `login.go` (normalize→idempotencia→CheckLimits→Find→IsLocked→Verify/dummy+jitter 80-120→Decide→RecordFail+401 opaco o Reset+Issue/Challenge). Solo puertos dominio.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `login_total{result}` + duración + `failures{reason_internal}` + `locks_total` vía MetricsPort; span `UseCase.Login` + 8 hijos sin password. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `login_test.go` (éxito Issue, mfa Challenge 5min aud=mfa, 4 malos mismo error, lock sigue Invalid, replay no duplica fails, RedisDown fail-open). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_007_login_mfa_flag.up/down.sql` (mfa_enabled + idx parcial). `migrate up/down/up` PG16 + verifica default false en filas CU-REG existentes.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. Reuso `postgres/user_repository` (SELECT login, timeout 2s) + nuevo `redis/login_tracker.go` (sliding login:ip/account, fails INCR EX900, lock EX exponencial + notify NX 3600, fail-open 2x). Tests testcontainers (PG+Redis) incl. RedisDown y lock-expiry.
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + pre-token en `security/`. `security/mfa_pretoken_issuer.go` (JWT aud=mfa-challenge 5min, rechazado fuera de /mfa/verify) + `kafka` tipos `login.success|mfa_challenged|failed|locked` → `auth.login.v1` + audit + SMTP lock (throttle). Test: pre-token no entra a negocio (middleware lo 401), Kafka-down → HTTP intacto.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/login_dto.go` + `handlers/login.go` (32KB, X-Request-ID, 200 active+cookies / 202 mfa_required / 400 / 401 único / 429+Retry-After / 500, veta 403/404/409/423 con assert, `no-store`). Buckets middleware. httptest: 200, 202 con mfa_token aud correcto, 4×401 idénticos + timing, 429, 413.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /api/v1/auth/login` con cadena estándar; wiring PG+Redis+Argon2+Tracker → LoginService (+Fake Issuer hasta CU-AUTH-04, luego real) ; env `LOGIN_*`, `MFA_PRETOKEN_TTL=5m`; `/metrics`. `go build ./...` + smoke curl (buena/mala/pending/mfa/lock/429) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose PG+Redis+Kafka+Mailhog: registra+verifica (sin MFA)→login 200+cookies; activa MFA (seed CU-AUTH-02 o flag manual)→login 202 sin cookies + pre-token solo /mfa/verify; 4 malos→401 idénticos; 6ª mala tras lock→401 + mail 1; IP flood→429; Redis-down→200/401 intactos; Kafka-down→200 intactos. Evidencia PR.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `login_smoke.js` 150VUs 4min p95<500ms p99<900ms + timing `|p50|<80ms` bloqueante + abuse (lock opaco, 429) . Adjunta summaries.
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: 401 único (sin USER_NOT_FOUND/LOCKED/PENDING hints), dummy+jitter reales, ConstantTime, sin password/hash/token/email en logs/spans/eventos (hashes), pre-token scope aislado 5min, pepper igual registro, SQL parametrizado, `no-store`, cookies delegadas Secure/Lax/HttpOnly (CU-AUTH-04). Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
