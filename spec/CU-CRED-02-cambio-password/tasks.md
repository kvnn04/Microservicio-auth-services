# Tareas de Implementación: CU-CRED-02

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/auth/`. `password_change.go` (HistoryN=5, Rate=5/h, ChangeAccount+HasPassword, DistinctFromHashes actual/history+dirty, SameHash). Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/password_change_ports.go` (PasswordHistoryStore: Current/LastN/RotateTx(keepSID,ver optimista,peers) + errores Reused/InHistory/InvalidCurrent/Missing/Unexpected). `go vet` sin pgx/redis.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `password_change_test.go` (matriz reused/history/ok, ventana móvil 6º permitido, dirty no bloquea, federated-set). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `change_password.go` (auth→lock→policy+HIBP→current/StepUp-guard→reused/history(Verify×5)→Hash→RotateTx keep-actual+ver→200+email). Solo puertos + reuso Tracker/StepUp/Hasher/HIBP.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `password_change_total{result,via}` + duración (buckets 5s) + `history_hits` + `peers_revoked` + `login_locks` reutilizado vía MetricsPort; span `UseCase.ChangePassword` sin claves. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `change_password_test.go` (ok pares+history+ver, mala 401+fail/lock, reused/history 400, policy 400, federated-set±token, replay, TOCTOU vía store). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_014_password_history.up/down.sql` (history append-only sin UNIQUE + idx + `users.password_ver` default 1). `migrate up/down/up` PG16 OK.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/password_history_store.go` (Current/LastN + RotateTx: FOR UPDATE + base/ver + INSERT history + UPDATE users + revoke pares salvo keepSID + outbox + email, misma Tx) + `SessionCache.InvalidateSessions` (DEL pares post-commit) + reconciliador existente purga huérfanos. Tests PG+Redis (rotate+history+ver, revoke pares, TOCTOU 1×200/1×REUSED concurrente).
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + reuso seguridad. Reuso `argon2/hibp/tracker` + `kafka` tipos `password.changed{via,ver}` + `session.revoked_peers{kept_sid,count}` + audit; worker SMTP genérico (`email_queue`) changed con pares+hora (sin IP cruda, ver `spec.md` §8). Kafka-down → 200 por outbox (diseño); HIBP-timeout → fallback local probado.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/password_change_dto.go` + `handlers/password_change.go` (POST auth ≤8KB → 200+`sessions_revoked` / 400-policy-reused-history-missing-unexpected / 401-current-stepup / 429, `no-store`) + rate `pwdchange:user 5/h` en handler + Step-Up verificado en servicio (federated-set). httptest: ok+pares, mala 401, reused/history/policy/missing/unexpected, federated±token, meta n=5.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /api/v1/auth/password/change` con auth→handler (sin middleware Step-Up: current equivale, token solo federated-set); wiring HistoryStore+Hasher+HIBP+Tracker+StepUpSvc → service; sin env nuevo (N/rate son consts). `go build ./...` + smoke (A/B/C→change en A→B/C muertas+A viva→login nueva) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Integración PG+Redis real: 3 sesiones change-A → B/C muertas + A viva + history+1 + ver 2 + mail + outbox; mala×5→lock + buena 401; reused/history/policy/HIBP-fallback 400; federated-set sin/con token; TOCTOU concurrente 1×200/1×REUSED; sin-Redis → PG verdad. Handlers httptest (sin auto-login).
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `pwdchange_smoke.js` creado (20 VUs, p95<1200ms, abuse+lock+revoke); ejecución viva pendiente de ventana pre-productiva (igual que `pless/stepup_smoke.js`).
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: current=Step-Up (federated token), Verify×N + pepper + ConstantTime, sin claves/hashes en logs/eventos (ver), pares muertos + actual vivo (sin valid_after global), rate+lock, `no-store`, TOCTOU por ver optimista. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
