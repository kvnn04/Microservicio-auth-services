# Tareas de Implementación: CU-CRYP-01

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `jwks.go` (JWK, Validate OKP/32B/kid/alg, ETagFor ordenado). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/key_directory_ports.go` (KeyDirectory: ActivePubs/Reload + ErrNoKeys). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `jwks_test.go` (vectores OKP, ETag, orden). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `key_directory.go` (memoria atomic + Reload PG + ETag memo + suscripción keys.rotated <1s; 0 claves→ErrNoKeys). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `jwks_requests_total` (handler) + `keys_count` + `reload_total` vía MetricsPort; span Reload. Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `key_directory_test.go` (orden, vacío, reload-hook, ETag-cambia-tras-rotate). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_029_signing_keys_extend.up/down.sql` (priv_ref+retired_at+alg, sin privada). `migrate up/down/up` PG16 + verifica SELECT pubs sin priv + orden kid.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/` + JWK en `security/`. `postgres` Reload (`WHERE retired_at IS NULL ORDER BY kid DESC`) + `security/jwk.go` (parse/canonical) + memoria + pub/sub reload (canal + Redis PUBLISH multi-instancia). Tests incl. 0-claves y rotate-hook.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + scanner en `security|scripts/`. Sin Kafka aquí; `scripts/jwks_priv_scan.sh` + `TestJWKSNoPrivateMaterial` (ejemplos + fuzz) en CI (rojo si `d/priv/seed/secret`). Test: fixture con `d` → CI rojo.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/jwks_dto.go` + `handlers/jwks.go` (200+ETag/304, max-age=600, multikey) + `openid_configuration.go` (200, max-age=3600, URLs exactas env) + rate 100/min + GET-only. httptest: 2-keys ordenadas, 304, discovery exacto, 500-sin-claves, 429-flood, ejemplo-SDK refetch-on-unknown-kid verde.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. 2 rutas well-known (sin auth, primeras en cadena) + wiring Directory→handlers; env `PUBLIC_BASE_URL, JWKS_MAX_AGE=600`; `/metrics` + `/ready` (rojo sin claves). `go build ./...` + smoke (curl jwks+discovery+ETag) en compose. Abre Módulo 7.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: 2-keys → orden+ETag+304+discovery; SDK-ejemplo (cache-vieja + kid-nuevo → refetch → verifica); 0-claves → 500+P1; flood → 429; privada ausente en todo (scan). Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `jwks_smoke.js` p95<20ms + 304 + 429 + rotación-ETag. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: solo-públicas (memoria/DB/response, scanner+test), multikey-overlap (no solo-actual), cache+ETag + norma refetch (sin `kid` huérfano), sin auth/PII, rate, `no-store`? No: `public` aquí (documentado excepción), URLs https prod. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
