# Tareas de Implementación: CU-M2M-01

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `m2m.go` (consts 32B/5min/10-15min/solape-24h, M2MClient, NewClientID svc_, AllowsScope/IP). Sin imports infra (solo net/netip).
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/m2m_ports.go` (M2MClientStore: Create/Find/Verify/Rotate/Suspend/Unlock + errores Exists/NotFound/Suspended) + admin scope `admin:m2m` (extiende SEC-06). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `m2m_test.go` (prefijo, subset, CIDR, verify current/prev). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `m2m_provision.go` (admin-check + Create/Rotate/Unlock + secret-1vez) + `m2m_token.go` (forma→rate→lookup→status→verify→fails/suspend→cidr→scope→sign→200, sin sesión). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `m2m_token_total{result,aud}` + duración + suspend/rotating/fallback vía MetricsPort; spans Provision/Token + 7 hijos sin secreto. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `m2m_token_test.go` (ok subset, scope-400-solo-ok, 4×401 iguales, 10º suspend+unlock, solape Warning, rate 429, admin 403). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_027_m2m_clients.up/down.sql` (tabla + CHECK svc_ + extiende admin con `admin:m2m`). `migrate up/down/up` PG16 + verifica prefijo/UNIQUE hash + admin-scope.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/m2m_store.go` (Create/Rotate-solape/Suspend/Unlock + outbox misma Tx) + `redis/m2m_tracker.go` (fails INCR + suspend-espejo + rate; down→PG+fail-open). Tests testcontainers (PG+Redis) incl. solape-24h y suspend-race (10 paralelos → 1 suspend + 1 mail por NX).
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + secreto en `security/`. `security/m2m_secret.go` (32B + SHA+pepper + ConstantTime + dummy) + reuso `ed25519` (aud-M2M) + `kafka` tipos `m2m.*` + audit; worker SMTP técnico (suspend/rotated). Test KMS-down → 500 + access-log sin Basic.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/m2m_dto.go` + `handlers/m2m_{provision,token}.go` (admin 201/rotate/unlock + token form 200/400/401/429, Basic-primary, `no-store`, auth-log masked) + `require_roles(admin+admin:m2m)` + buckets. httptest: provision-1vez+hash-only, token ok/aud/scope, 4×401 iguales+delay, suspend+unlock, solape Warning, rate.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. 4 rutas (`/admin/m2m/*` + `/oauth2/token`) con recover→requestID→auth/rate→handler; wiring Store+Signer → services; env `M2M_PEPPER, M2M_AUDIENCES, SEED_*`; `/metrics` nuevas. `go build ./...` + smoke (provision→token→satélite-mock→rotate-solape→suspend→unlock) en compose. Abre Módulo 6.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: admin→provision (secret 1 vez, hash-only DB)→token Basic/body→satélite aud/scope/5min ok→scope/aud 400→4×401 iguales→10º suspend+mail→unlock→200→rotate (viej+nuevo 24h)→satélite rechaza humano y viceversa→Redis/KMS-down medidos. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `m2m_smoke.js` p95<100ms + idénticos + suspend + flood + chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: admin-only + 1 exhibición + hash-only (nunca re-emite), 5min-aud + sin refresh/family/sid, Basic+body + opaco (sin id/suspend/CIDR hints), subset + allowlist-aud (sin aud libre), CIDR emisión-check + audit (gateway-futuro doc), suspend 10/15 + unlock (sin 423), secret fuera de logs (Basic masked), `no-store`. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
