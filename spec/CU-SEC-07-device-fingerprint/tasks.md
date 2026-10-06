# Tareas de Implementación: CU-SEC-07

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/auth/`. `device.go` (consts 10/10min/24h/3, DeviceFP, Fingerprint/HMACFP/ExactMatch). Sin imports infra (solo crypto).
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/device_ports.go` (Fingerprinter, DeviceStore Find/AddTx/List, DeviceChallengeStore Issue/Verify/IssueKill/RedeemKill + errores). `go vet` sin UA/redis.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `device_test.go` (huella estable, HMAC, LRU conceptual, exact-match). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `device_check.go` (PreIssue: find→trusted/first/desconocido-dual) + `device_verify.go` (Verify→AddTx-evict→Issue+kill encadenado, fusión travel-MFA) + `device_kill.go` (Redeem→RevokeSID-solo-esa). Solo puertos + reuso Issuer/Revoker/MFAVerify-hook.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `device_unknown_total{8 acciones}` + trusted-hist + kill + hmac-mismatch vía MetricsPort; hijo `Defense.DeviceCheck` + 5 hijos (label). Fake metrics.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `device_check_test.go` (trusted/first/MFA-force/email-challenge+verify/kill ok-already-ajeno/quema/sin-key/PG-down). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_026_devices.up/down.sql` (trusted+challenges+kill_links). `migrate up/down/up` PG16 + verifica PK(user,fp) + evict-oldest query + kill 1-uso.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/device_store.go` (Find+touch, AddTx upsert+evict-11º+outbox, challenges OTP/link 10min-3fails, kill 24h used) + `redis` fast-path dev + quotas (down→PG). Tests testcontainers (PG+Redis) incl. LRU-11º y kill-ajeno-400.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/` + fingerprinter en `security|identity/`. `security/fingerprinter.go` (UA-parse+/24/HMAC, ConstantTime, sin-key→skip) + reuso `token_issuer` + `kafka` tipos `device.unknown|trusted|killed|challenge` + audit; worker triple-SMTP (challenge/MFA-nuevo/sesión-con-kill) siempre. Test HMAC-rotada (mismatch→re-desafío, sin 500).
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/device_dto.go` + `handlers/device_{verify,kill}.go` (POST verify encadenado 200/202 + GET|POST kill 200/already/400, `no-store`) + injerto PreIssue en login/pless/federated (forced-`202` idéntico MFA, `202 device_challenge` nuevo código) + buckets. httptest: trusted/first/dual/kill ok-already-ajeno/quema/sin-key + injertos idénticos.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go` + MFA-hook. `POST /device/verify + GET|POST /device/kill` con rate→handler; wiring Fingerprinter+Stores → services (+MFAVerify registra device post-TOTP); env `DEVICE_HMAC_KEY (+PREV)`. `go build ./...` + smoke (conocido/primero/MFA/email/kill) en compose. Cierra Módulo 5.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose + Mailhog: conocido→directo; primero→auto+info; MFA-nuevo→202+TOTP→200+trusted+kill-mail; no-MFA→202-challenge→OTP→200+kill-mail→kill-clic→muerta+confirm→re-clic already→kill-ajeno 400; quema 3º; sin-key skip; PG-down 500. Evidencia PR.
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `device_smoke.js` trusted p95<10ms + new p95<300ms + floods 429 + HMAC-rot + Redis/sin-key chaos. Adjunta summary.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: gruesa+HMAC (sin JS/PII fina, Q1 a confirmar o ajusta a fina), dual sin triple-factor, kill 24h anónimo 1-uso (solo su sid), exact-match (sin scoring), LRU + quotas (sin llenado atacante), challenge-scope aislado (no sesión), ConstantTime+delay, sin huella/UA/IP en logs/eventos (label/prefix), `no-store`. Dictamen `seguridad.md` PASSED + confirma Q1 o itera.
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`. Cierra Módulo 5.
