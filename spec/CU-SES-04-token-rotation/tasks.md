# Tareas de Implementación: CU-SES-04

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `rotation.go` (consts gracia/idempotencia/flaps, RotateDecision, DecideRotate matriz current/parent/device/flaps). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/rotation_ports.go` (RotationStore: LookupForUpdate/RotateTx(CAS)/MarkReuseGlobal + errores Concurrent/Reuse/Expired/Revoked/Invalid, FamilyState). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `rotation_test.go` (matriz decide, gracia 10s borde, flaps 3 escala, device mismatch → reuse). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `rotate_session.go` (forma→rate→idempotencia-ReqID→lookup FOR UPDATE→decide→RotateTx CAS|grace|concurrent+flaps|global reuse→200/409/401). Solo puertos + reuso Signer/Generator/GlobalRevoker.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `rotation_total{result}` + `reuse_detected_total(P1)` + duración + `concurrent_409` vía MetricsPort; span + 8 hijos sin planos. Fake metrics + P1 mock.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `rotate_session_test.go` (ok sliding, replay-ReqID idempotente, race 409 + algoritmo, 4º flap global+P1, expirada/revoked/miss 401, CAS-perdido 409, RedisDown). `go test ./internal/service/... -race` + `-race -run Race` 2-goroutines (1×200+1×409). Verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_019_rotation_grace.up/down.sql` (last_rotated/parent/device + idx). `migrate up/down/up` PG16 + verifica CAS `WHERE current_hash` + FOR UPDATE bloquea doble-rotate.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/rotation_store.go` (LookupForUpdate JOIN, RotateTx CAS+hashes+sessions-jti+revoked_jtis+outbox misma Tx, MarkReuseGlobal delega SES-02) + `redis/rotation_store.go` (fam/SET, jti, idempotency-ReqID→par EX60 (único lugar con plano 60s), concurrent INCR EX10, down→PG). Tests testcontainers (PG+Redis) incl. race-CAS y gracia-ReqID.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + reuso seguridad. Reuso `ed25519/refresh_generator` (auth_time preservado, roles_ver preservado) + `kafka` tipos `rotated|reuse_detected(P1)|revoked_all{reuse}` + audit; worker SMTP `reuse_critical` (ambos devices) + pager P1 (mock en test). Test: rotate-ok sin email, reuse con email+P1.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/refresh_dto.go` + `handlers/refresh.go` (POST cookie/body ≤4KB → 200 rotated/grace + 409 retry + 401 INVALID|EXPIRED|REVOKED|COMPROMISED + 429/500, rota cookie MISMO Path con Max-Age real, `no-store`) + buckets refresh. httptest: ok mismo-sid, replay-ReqID, race-409, reuso-11s global, expirada/revoked/miss, PG-down 500 sin quemar. Documenta algoritmo cliente 409 en contracts + ejemplo JS.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /api/v1/auth/refresh` con recover→requestID→rateLimit→handler (sin auth clásica); wiring RotationStore+Signer+Generator+GlobalRevoker → service; env `ROTATE_GRACE=10s, REFRESH_*`. `go build ./...` + smoke (login→refresh×3 chain→reuso-viejo-global→relogin) en compose. Cierra Módulo 4.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: chain R1→R2→R3 (mismo sid, counters) → R1-reuso-11s global (0 sesiones + crítico + P1 mock) → relogin → replay-ReqID idempotente → race-409 + algoritmo (re-lee jar → ok) → expirada/revoked 401 → Redis-down 200 → PG-down 500. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `rotation_smoke.js` serie p95<250ms + paralelo 1×200/1×409 (0 globales) + diferido-11s 100% global + flood 429 + chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: single-use + CAS (nunca 2×200 mismo viejo), parent/device/ventana/flaps antes de global (sin falsos retry), global = SES-02 + email crítico (no solo family), auth_time/roles preservados (no escalación), sin planos en logs/eventos (prefix), `401` explícitos justificados (poseedor), cookie rotada MISMO Path, `no-store`. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra Módulo 4.
