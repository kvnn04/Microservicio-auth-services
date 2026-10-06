# Tareas de Implementación: CU-AUTH-04

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/auth/`. `tokens.go` (consts 15m/30d/90d/32B/20sess, AMR, SessionRequest/IssuedPair/Session, NewAccessClaims con validación aud/iss/TTL/amr). Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/token_ports.go` (AccessSigner, RefreshStore, SessionStore, SessionIssuer + ErrNoKey/Infra). `go vet` sin ed25519/redis/pgx en domain (solo structs).
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `tokens_test.go` (TTL exacto, amr cerrado, roles snapshot, kid exigido, absolute>sliding). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `issue_session.go` (Validate ACTIVE → GenIDs → Sign → Tx PG Sessions+Families+Hashes+Outbox (+EvictLRU 21ª) → Redis write-through → Output; orden firma→Tx→entrega, Tx-fail descarta JWT). Solo puertos.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `tokens_issued_total{method,amr}` + duración + `sessions_active/evicted` + fallback vía MetricsPort; span `Session.Issue` + 4 hijos sin tokens. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `issue_session_test.go` (password/MFA/federado amr exacto, nativo vs web lo decide adapter no service, 21ª evicta, PG-fail 0 entrega, RedisDown entrega, doble Issue = 2 sid). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_010_sessions_tokens.up/down.sql` (sessions/families/hashes/signing_keys placeholder + tokens_valid_after). `migrate up/down/up` PG16 + verifica FK cascade borra sesiones al borrar user + UNIQUE current_hash bloquea duplicado.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/session_store.go` (Tx Save+CreateFamily+EvictLRU+outbox) + `redis/session_store.go` (sess/fam/jti EX, down→PG+rehidrata) + genera clave Ed25519 real deploy (script `scripts/gen_ed25519.sh`, pub a `signing_keys`, privada a KMS/env, nunca repo). Tests testcontainers (PG+Redis) incl. RedisDown y LRU-21.
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + signer en `security/`. `security/ed25519_signer.go` (env/KMS, kid actual, fail-fast, nunca none) + `refresh_generator.go` (32B+sha256) + `kafka` tipos `session.issued` + audit; expone `jwks()` interno para CRYP-01 (solo lectura pública, sin privada). Test firma/verifica + sin-key 500 + JWKS-mock 10k/s.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. Sin rutas nuevas: `session_transport.go` (WritePair web-cookie vs nativo-body, flags HttpOnly/Secure/Lax/Path/Max-Age, `no-store`, nunca URL) + injerto en login/mfa_verify/federated_callback (traducen IssuedPair a 200/202). httptest: web cookie flags, nativo doble-body, Access header kid/exp, Refresh 43ch hash-only DB.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. Sin rutas nuevas; wiring `AccessSigner+RefreshStore+SessionStore → IssueService → Login/MFA/Federated`; env `SESSION_SIGNING_KEY(+KID), SESSION_ISS/AUD, MAX_SESSIONS=20, CLIENT_TYPE header`; `/metrics` + `/healthz` chequea clave cargada. `go build ./...` + smoke (login-web cookie, login-native body, federado, gateway-mock verifica offline) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose PG+Redis+Kafka: login→web cookie+body Access verificable JWKS-mock, nativo doble-body, MFA→amr totp, federado→amr federated, 21ª evicta 1ª, `valid_after` rechaza viejo, denylist jti tras SES-01 (preparado). Evidencia PR.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `issue_smoke.js` Issue-puro p95<200ms + e2e p95<600ms, JWKS-verify 10k/s p95<5ms, PG-down 100% 500 0 huérfanos, Redis-down 200 vía PG. Adjunta summaries.
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: Ed25519 + kid siempre + nunca none/HMAC-fallback, privada KMS/nunca repo-logs, Refresh 256-bit hash-only + family/chain, transporte híbrido flags + nunca URL, Access ≤8KB sin PII (sub), firma→Tx→entrega (sin huérfanos), LRU 20, `no-store`. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Habilita SES-01/02/04 y CRYP-01/02.
