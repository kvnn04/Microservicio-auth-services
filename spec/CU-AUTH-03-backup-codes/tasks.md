# Tareas de Implementación: CU-AUTH-03

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/auth/`. `backup_codes.go` (Count/Alphabet/Canonicalize/Display/HashWithPepper+prev). Sin imports infra.
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/backup_ports.go` (BackupCodeStore GenerateTx/ConsumeTx/CountRemaining + ErrNotFound/AlreadyUsed). `go vet` sin pgx/redis.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `backup_codes_test.go` (canónico/display, hash pepper/prev, alfabeto rechaza 0/O/1, colisión). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `backup_codes.go` (GenerateForEnable/Regenerate con supersede + VerifyBackup autodetectado + injerto MFAVerify mismo challenge/fails/401 + quema en Disable). Solo puertos.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `backup_total{op,result}` + `remaining_gauge{bucket}` + cuenta `mfa verify{method:backup}` vía MetricsPort; hijos Generate/Consume/Notify. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `backup_verify_test.go` (generate únicos, consume ok-1+email, reuso/miss 401 igual TOTP, regenerate supersede, stale 401, PG-down 500, idempotencia RequestID). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_009_backup_codes.up/down.sql` (PK code_hash global + idx user + used flags). `migrate up/down/up` PG16 + prueba colisión global imposible + used nunca DELETE.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/backup_code_store.go` (GenerateTx quema-previos+INSERT 10 ON CONFLICT+relleno, ConsumeTx FOR UPDATE+used+remaining+outbox misma Tx) + reuso `redis/mfa_challenge` (sin claves nuevas salvo regen-rate). Tests testcontainers (PG+Redis) incl. concurrencia mismo código 1×200/1×401.
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + hasher en `security/`. `security/backup_hasher.go` (rand Crockford, SHA-256+pepper/prev, ConstantTime) + `kafka` tipos `backup.generated|consumed|regenerated|failed` + `mfa.verified{backup}` + audit; worker SMTP alta prioridad siempre (con remaining/links, sin planos). Test pepper-rotación (viejo verifica con prev).
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. Reuso `POST /mfa/verify` (acepta `backup_code` alias + autodetección, mismo 401) + nuevo `POST /backup-codes/regenerate` (Step-Up, 1 exhibición) + `GET /status` con remaining/warning + buckets. httptest: enable trae 10 1 vez, verify-backup ok/reuso/miss/agotado idénticos TOTP, regenerate stale 401/quema, status sin valores.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. `POST /mfa/backup-codes/regenerate` con fresh-auth + wiring BackupStore+Hasher → services (Enable/Verify/Regenerate/Disable); env `PASSWORD_PEPPER(+PREV), BACKUP_COUNT=10`. `go build ./...` + smoke (enable→login-202→consume→reuso-401→regen→viejo-401→agotado) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose + Mailhog: enroll→10 planos→status 10→login-202→consume B1 200+mail alta+9→reuso 401→miss 401 igual→regen fresca 10 nuevos+viejos muertos→stale 401→disable quema todos. Evidencia PR.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `backup_smoke.js` p95<300ms, reuso 100% 401, `|p50(totp-bad)-p50(backup-bad)|<40ms`, concurrencia 1×200/1×401. Adjunta summary.
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: 10×50 bits + SHA+pepper + solo hashes DB, 1 exhibición TLS + nunca GET/email/logs con planos, single-use Tx + supersede, mismo challenge/401 sin oráculo tipo, alerta siempre, Step-Up regen, último-factor en disable, `no-store`. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
