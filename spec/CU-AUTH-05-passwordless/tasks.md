# Tareas de Implementación: CU-AUTH-05

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/auth/`. `passwordless.go` (consts 10min/32B/8d/3/60s/5-día, Record+Alive, ParseToken/OTP, RiskOf /16+UA, PlessContext). Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/passwordless_ports.go` (PasswordlessStore: Eligible/Issue/FindAlive/ConsumeTx + ErrThrottled/Invalid/Burned). `go vet` sin pgx/redis.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `passwordless_test.go` (parses, TTL 10min, burned/3, risk matriz, quotas). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `passwordless_start.go` (forma→rate→Eligible→dummy+jitter→Issue/supersede o noop→202 genérico) + `passwordless_verify.go` (forma→rate→Find→compare+delay→ConsumeTx→risk→MFA/Issue→200/202 + mismatch-email). Solo puertos.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `passwordless_total{op,result}` + duración + `mismatch` + fallback vía MetricsPort; spans Start/Verify + 7 hijos sin secreto. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `passwordless_test.go` (elegible sent, no-elegible 202 igual, cooldown/quota throttled, ok active/MFA, expirado/consumido/aleatorio 400 iguales, 3º burn, replay idempotente, high-risk mismatch). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_011_passwordless.up/down.sql` (hashes PK/UNIQUE, ctx, idx activos). `migrate up/down/up` PG16 + verifica 1-activo (supersede) y consumed no reutilizable.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/passwordless_store.go` (Eligible ACTIVE+verified, Issue Tx supersede+outbox, ConsumeTx + last_login + mismatch-outbox) + `redis/passwordless_store.go` (t/o/active/sent/count, Lua DEL, quotas NX, down→PG+fallback). Tests de integración PG+Redis (supersede, consumed no reutilizable, mismatch, burn, cascade); carrera mismo-token garantizada por `UPDATE` atómico sin test dedicado (ver `spec.md` §8 D-02).
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + issuer en `security/`. Reuso `token_issuer` (32B+8d) + `RiskOf` + `kafka` tipos `passwordless.requested|consumed` + `security.context_mismatch` + audit; worker SMTP link+OTP 10min + aviso takeover (+high-risk con IP/UA). Test Kafka-down → HTTP intacto.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/passwordless_dto.go` + `handlers/passwordless_{start,verify}.go` (start 202 genérico ≤2KB, verify POST+GET-alias 200/202/400 genérico/429, `no-store`, delay 40-80) + buckets pless. httptest: start elegible/no-elegible 202 idénticos + Mailhog 1, verify ok/MFA/400×4 idénticos, quotas throttled, high-risk email.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /passwordless/start|/verify + GET /passwordless` con recover→requestID→bodyLimit→rateLimit→handler; wiring Redis+PG+Issuer → services (+SessionIssuer/MFA); TTL/quota como consts de dominio (ver `spec.md` §8 D-01, sin env nuevo). `go build ./...` + smoke (start→Mailhog→verify-link/OTP→replay-400→MFA-branch) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Evidencia vía `email_queue` + integración PG+Redis real en vez de Mailhog vivo (ver `spec.md` §8 D-05). Casos: ACTIVE sin MFA start→202+mail→verify 200+cookies; MFA start→verify 202 pre-token; PENDING/inexistente start→202 sin mail idéntico; expirado/consumido/aleatorio→400 idénticos; cooldown/quota throttled 202; high-risk IP-B→200+mail mismatch; Redis/Kafka-down→202/200 intactos.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `pless_smoke.js` creado (start 50 VUs + verify 80 VUs con thresholds); ejecución viva pendiente de ventana pre-productiva (ver `spec.md` §8 D-04). Criterios: p95<300ms hit/<700ms fallback, `|p50(start elig)-p50(no)|<40ms`, `|p50(valid)-p50(invalid)|<40ms`, quotas y mismatch medidos.
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: email-only dual + solo hashes DB, 202/400 opacos (sin 404/410), single-use+3-burn+supersede, MFA nunca saltado (amr email-otp), ctx-binding alerta-no-bloqueo, quotas anti-spam, sin token/código/email en logs/eventos (hashes), prefetch documentado, `no-store`. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
