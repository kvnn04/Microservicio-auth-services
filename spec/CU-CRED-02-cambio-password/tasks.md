# Tareas de Implementación: CU-CRED-02

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `password_change.go` (HistoryN=5, Rate=5/h, ValidateNewPassword reuso, DistinctFromHashes actual/history). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/password_change_ports.go` (PasswordHistoryStore: LastN/RotateTx(keepSID,keepFamily,peers) + errores Reused/InHistory/InvalidCurrent/StepUp). `go vet` sin pgx/redis.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `password_change_test.go` (matriz reused/history/ok, ventana móvil 6º permitido, federated-set). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `change_password.go` (auth→rate→policy→current/StepUp→reused/history(Verify×5)→Hash→RotateTx keep-actual→200+email). Solo puertos + reuso Tracker/StepUp/Hasher/HIBP.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `password_change_total{result,via}` + duración (buckets 2s) + `revoked_peers` vía MetricsPort; span `UseCase.ChangePassword` + 7 hijos sin claves. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `change_password_test.go` (ok pares+history, mala 401+fail/lock, reused/history 400, policy 400, federated-set±token, replay, TOCTOU concurrente). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_014_password_history.up/down.sql` (history + idx + password_ver). `migrate up/down/up` PG16 + verifica append-only (sin UNIQUE que bloquee re-uso tras ventana) + ver default 1.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/password_history_store.go` (LastN 5 + RotateTx: INSERT history(old)+UPDATE users(new,ver)+revoke fams/sess salvo keep + outbox misma Tx + re-Verify TOCTOU) + Redis DEL pares vía `sess:by_user` SET (mantener en Issue CU-AUTH-04: añadir `SADD` si falta) + reconciliador huérfanos. Tests testcontainers (PG+Redis) incl. RedisDown y 21-sesiones LRU.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + reuso seguridad. Reuso `argon2/hibp/tracker` + `kafka` tipos `password.changed{via}` + `session.revoked_peers{kept}` + audit; worker SMTP changed (peers+IP/hora). Test Kafka-down → 200 + HIBP-timeout fallback.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/password_change_dto.go` + `handlers/password_change.go` (POST auth ≤8KB → 200+sessions_revoked / 400-policy-reused-history-missing-unexpected / 401-current-stepup / 429, `no-store`) + rate `pwdchange:user 5/h` + Step-Up opcional-current. httptest: ok+pares, mala 401+lock, reused/history 400, federated±token, rate 429.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /api/v1/auth/password/change` con auth→rate→handler; wiring HistoryStore+Hasher+HIBP+Tracker(+StepUpVerifier) → service; env `PWD_HISTORY_N=5, PWDCHANGE_RATE=5/h`. `go build ./...` + smoke (A/B/C→change en A→B/C muertas+A viva→login nueva) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: 3 sesiones change-A ok→B/C refresh 401 + A 200 + history+1 + mail; mala×5→lock + buena 401; reused/history/policy 400; federated-set sin/con token; Redis-down PG-verdad; Kafka-down 200. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `pwdchange_smoke.js` p95<1200ms (Verify×5) + abuse 429/lock + TOCTOU 1×200/1×400. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: current=Step-Up (federated token), Verify×N + pepper + ConstantTime, sin claves/hashes en logs/eventos (ver), pares muertos + actual vivo (sin valid_after global), rate+lock, `no-store`, TOCTOU re-Verify en Tx. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
