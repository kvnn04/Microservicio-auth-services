# Tareas de Implementación: CU-PRIV-01

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/shared/`. `privacy_export.go` (consts 30d/24h/10k, ExportBundle+Sanitize denylist, shape). Sin imports infra.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `shared/export_ports.go` (ExportStore: Request/MarkReady/GetForDownload/DestroyDue + BundleCollector.Collect + errores TooSoon/NotFound/Expired). `go vet` sin stores.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `privacy_export_test.go` (denylist por clave, schema, 30d, truncated). `go test ./internal/domain/... -race` verde + `privacy_schema.json` fixture válida.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `export_request.go` (Guard+30d→processing→202) + `export_build.go` (collect→sanitize→encrypt→ready+mail, failed-no-consume) + `export_download.go` (owner+24h→stream ZIP + audit por descarga). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `export_total{op,result}` + build-duration + size + expired vía MetricsPort; spans Request/Build/Download + 6 hijos (bytes). Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `export_test.go` (202/429-fecha, build+mail, owner/ajeno-404/410/multi, destroy, fallido-reintento, KEK-500). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_032_privacy_export.up/down.sql` (tabla + idx). `migrate up/down/up` PG16 + verifica 30d-check usa idx + BYTEA/path ambos.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/export_store.go` (Request 30d + MarkReady exp=ready+24h + GetForDownload owner/exp + DestroyDue + DELETE voluntario) + storage volumen `exports/` 0600 (umbral 10MB) + GC huérfanos semanal. Tests testcontainers (PG) incl. expiración y lease-worker (processing con heartbeat, re-pickup sin duplicar).
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + caja en `security/`. `security/export_box.go` (AES-GCM efímera + KEK-wrap AAD=user, fail-fast) + `privacy_schema.json` + scanner CI + `kafka` tipos `export.*` + audit; worker build (poll processing + lease) + SMTP ready (sin adjunto) + purga 24h. Test KEK-down → 500 + scanner-rojo con hash en fixture.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/export_dto.go` + 3 handlers (POST Step-Up 202/429/401, status, download ZIP streaming owner 404/410, `no-store`) + `require_step_up(privacy:export)` (14º scope) + buckets. httptest: stale 401, 2º-30d 429+fecha, build+mail, owner/ajeno/expirado, multi-download, destroy.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go` + worker. 3 rutas privacy con Step-Up/rate + wiring Store+Collector → services; env `EXPORT_KEK, EXPORT_COOLDOWN=30d, EXPORT_TTL=24h`; `/metrics` nuevas. `go build ./...` + smoke (request→build→download ZIP válido schema→24h-fake→410) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose: ACTIVE Step-Up request→processing→ready+mail→status→download ZIP (schema ok, sin secretos, con sub propio)→2ª ok→24h-fake 410+purga→re-request 429+fecha→fallido-infra reintento→ajeno 404→KEK-down 500. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `export_smoke.js` build p95<60s + download p95<5s + truncado-50k + chaos KEK/PG/SMTP + worker-kill re-pickup. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: Step-Up mandatorio (14º scope), allowlist sin secretos (hashes/TOTP/tokens fuera, scanner+schema CI), descarga autenticada (nunca URL pública; clave server-side), 1/30d + 429-fecha, AES-GCM + purga-24h + KEK fail-fast, `no-store`, audit sin contenido. Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
