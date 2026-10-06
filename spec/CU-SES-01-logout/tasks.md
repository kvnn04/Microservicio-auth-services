# Tareas de Implementación: CU-SES-01

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `logout.go` (LogoutResult, LogoutIdentity, DenylistTTL clamp 1s..15min). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/session_revoke_ports.go` (SessionRevoker: RevokeSID/RevokeByRefreshHash + ErrNotFound→Already/Unauthorized). `go vet` sin jwt/redis.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `logout_test.go` (TTL clamp, Already vs Ok). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `logout.go` (Verify tolerante-revoked + exp exigible → rate → idempotencia → RevokeSID o ByRefresh → ok/already). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `logout_total{result}` + duración + denylist gauge vía MetricsPort; span `UseCase.Logout` + 5 hijos sin tokens. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `logout_test.go` (ok triple-capa, already 200, expirado/malo 401, refresh-alt ok, replay 1-outbox, RedisDown vía PG). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_016_session_revoke.up/down.sql` (revoked_jtis + idx + purga worker). `migrate up/down/up` PG16 + verifica exp-index usa purga.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/session_revoker.go` (Tx SELECT family + UPDATE revoked + DELETE sess + INSERT revoked_jtis + outbox) + `redis/session_revoker.go` (DEL sess/fam + SET jti EX restante + índice by_hash; down→PG). Tests testcontainers (PG+Redis) incl. already y by-refresh.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + verifier en `security/`. Reuso `ed25519_verifier` tolerante-revoked (firma+exp, sin denylist/valid_after aquí) + `kafka` tipos `session.logged_out` + audit; sin SMTP. Test: denylisteado verifica igual para idempotencia + expirado 401.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/logout_dto.go` + `handlers/logout.go` (POST auth-tolerante + refresh-alt ≤4KB → 200 logged/already + Clear-Cookie MISMO Path + `no-store`, 401/429/500) + buckets logout. httptest: A/B (A muere B vive), replay already, sin-nada 401, refresh-alt, Clear-Cookie Path match, PG-down 500 sin cookie.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /api/v1/auth/logout` con recover→requestID→auth-tolerante→rateLimit→handler; wiring Verifier+Revoker → service; env `LOGOUT_RATE=30/min`. `go build ./...` + smoke (login×2→logout A→A 401/B 200→refresh A 401→replay already) en compose. Abre Módulo 4.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: A/B vivas→logout A→gateway A-401/B-200→refresh A-401-revoked→replay already→sin-Bearer-con-refresh ok→expirado 401→Redis-down 200→PG-down 500 sin cookie. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `logout_smoke.js` p95<150ms, replay 100% already, flood 429, denylist gateway, PG/Redis chaos medidos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: POST+Bearer (no GET/CSRF), sin Step-Up justificado, triple-capa revoke (jti corto + family duro + sess), idempotencia sin oráculo, sin tokens en logs/eventos (sid/jti), Clear-Cookie Path match, `no-store`, refresh-post-logout no dispara robo. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
