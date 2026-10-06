# Tareas de Implementación: CU-M2M-02

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `api_keys.go` (consts formato/TTL/solape/rate, APIKey, New/Parse/CanUse). Sin imports infra (solo regexp).
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/apikey_ports.go` (APIKeyStore: Create/Find/Verify/Rotate/Revoke/List/Touch + errores Taken/Delegation/NotFound/Insufficient/Expired). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `api_keys_test.go` (formato/regex, subset, CIDR, exp, solape). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `api_keys.go` (Create con transitividad+Step-Up + Verify directo + Rotate-solape + Revoke + List sin secreto) + `verify_api_key.go` (gateway). Solo puertos + reuso RoleStore/StepUp.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `apikey_total{op,result}` + use/suspend/fallback/expired vía MetricsPort; spans + 7 hijos (prefix). Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `api_keys_test.go` (1vez+transitividad, uso ok/403/401-exp/401-opaco, rotate ambas+auto, revoke, fails-suspend, replay-RequestID-no-duplica). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_028_api_keys.up/down.sql` (tabla + CHECKs + UNIQUEs + admin-scope-doc). `migrate up/down/up` PG16 + verifica prefijo-CHECK + owner-name-UNIQUE + hash-UNIQUE.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/apikey_store.go` (Create/Rotate-solape/Revoke/List/Touch-debounce + outbox misma Tx) + `redis/apikey_cache.go` (ak: EX300 + DEL/pub + use-sliding 1000 + fails-suspend + touch-debounce; down→PG+fail-closed-uso). Tests testcontainers (PG+Redis) incl. solape-24h fake-clock y pub/sub ≤1s.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + secreto en `security/`. `security/apikey_secret.go` (8+32B + SHA+pepper + ConstantTime + dummy) + regex scanners (contracts + `audit_pii_scan` extendido) + `kafka` tipos `apikey.*` + audit (ok 10%); worker SMTP owner (suspend/rotated). Test KMS/pepper-down + access-log masked.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/apikey_dto.go` + `handlers/api_keys.go` (4 gestión con Step-Up `apikeys:write`, 1vez, masked-list) + `middleware/require_api_key.go` (X-API-Key|ApiKey → Verify → ctx o 401/403/429) + buckets. httptest: create-1vez+lista, uso ok/403/401-exp/401-opacos, rotate/revoke, rate/suspend, PG-down fail-closed.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. 4 gestión + middleware registrable por ruta-key; wiring Store → services (+RoleStore transitividad); env `APIKEY_PEPPER, APIKEY_TTL=90d/1a`; `/metrics` nuevas. `go build ./...` + smoke (create→use→rotate→old+new→auto-old→revoke→lista) en compose. Cierra Módulo 6.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: admin→create (1 vez, hash-only)→use gateway 200→scope 403→exp 401→CIDR 401-opaco→flood 429→suspend+mail→rotate solape (ambas 24h, vieja muere 25h)→revoke inmediato (pub/sub ≤1s)→lista masked→PG/Redis/Kafka-down medidos. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `apikey_smoke.js` p95<50ms-hit/<150ms-PG + hit>95% + flood + suspend + solape + revoke-pub + chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: prefijo.hash + 1 exhibición + hash-only (nunca GET/logs), Step-Up gestión + transitividad (sin delegar ajeno), directa sin JWT/sesión, solape 24h + auto, revoke inmediato + pub, TTL 1a/90d + forense 30d, rate/key + suspend, fail-closed uso (sin cache ni PG → 500), regex pública scanners, `no-store`. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra Módulo 6.
