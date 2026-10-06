# Tareas de Implementación: CU-SEC-03

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `travel.go` (consts 1000/100/24h/500, GeoPoint, TravelDecision, HaversineKm, EvaluateTravel con filtros ordenados). Sin imports infra/geo (solo math).
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/travel_ports.go` (GeoIPResolver, LastLocationStore Get/Save + ErrUnknown/None). `go vet` sin maxminddb.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `travel_test.go` (haversine, umbrales, filtros, bordes dt/acc/ASN). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `travel_guard.go` (PreIssueCheck: resolve 50ms-timeout→skip + GetLast + Evaluate + métrica/audit sin email) + injerto pre-Issue en login/passwordless/federated (ForceMFA convierte 200→202 idéntico MFA; Alert emite + high_risk). Solo puertos.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `impossible_travel_total{9 acciones}` + speed/distance + geo-duration + unknown vía MetricsPort; hijo `Defense.ImpossibleTravel` + 3 hijos (ciudad, no lat/lon). Fake metrics + mmdb mock.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `travel_guard_test.go` (forced indistinguible + email flag, alerted + suggest, 5 skips sin email, nogeoip fail-open, federado/pless injertos). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_022_login_geo.up/down.sql` (last_login_geo JSONB + login_locations + idx + purga worker doc). `migrate up/down/up` PG16 + verifica JSONB query por user.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/` + GeoIP en `identity/`. `postgres/last_location_store.go` (GetLast + SaveLogin en Tx Issue o best-effort) + `identity/geoip_resolver.go` (maxminddb local, 50ms timeout, private→Unknown, sin red) + montaje `geo/*.mmdb` (compose volume + `GEOIP_MMDB`, licencia/update-mensual doc). Tests testcontainers (PG) + mmdb-test (CI/mini-mmdb) incl. unknown/nogeoip.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/`. `kafka` tipos `travel.forced_mfa|alerted` + audit `travel.check`; worker SMTP `impossible_travel` (ciudades+hora+device, sin coords/IP) + `suggest_mfa`. Test Kafka-down → 200/202 + pendiente.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. Sin rutas nuevas: injerta guard en login/pless/federated handlers (forced `202` idéntico MFA sin reason; alerted `200` + email; skips silenciosos) + test `forced-indistinguishable` (diff 202-normal vs 202-forced vacío). Sin headers de riesgo al cliente.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. Sin rutas; wiring Resolver+Store → TravelGuard → 3 services; env `GEOIP_MMDB, TRAVEL_MAX_KMH=1000`; `/metrics` nuevas; mmdb presente en imagen (multi-stage COPY + checksum). `go build ./...` + smoke (Lima→Madrid MFA/alerta, VPN-mismo-ASN skip) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose + mmdb-test: Lima→Madrid 12min MFA→202-forced+mail→TOTP→200 Madrid; sin-MFA→200+mail high+suggest; 30h después→normal; mismo-ASN→normal; IP-privada→normal; mmdb-ausente→normales; PG-last-down→500 base. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `travel_smoke.js` overhead p95<15ms, forced/alerted/skip correctos, unknown/nogeoip, PG-chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: nunca bloqueo-duro (viajeros/VPN), forced indistinguible (sin reason/threshold leak), ciudad+hash (sin lat/lon/IP en logs/eventos), `last_geo` acceso restringido (GRANT doc), mmdb licencia/update, `no-store`, residual Step-Up futuro documentado (high_risk). Dictamen `seguridad.md` PASSED.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
