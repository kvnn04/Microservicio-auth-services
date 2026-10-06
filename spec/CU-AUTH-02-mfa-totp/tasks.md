# Tareas de Implementación: CU-AUTH-02

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [x] T-01: Definir entidades y value objects en `internal/domain/auth/`. `mfa_totp.go` (consts SHA1/6/30/20B/±1/5s/10min/5min/5fails/90s, TOTPSecret, NewCounter/Candidates/FormatCode). Sin imports infra (solo crypto/hmac en adapter, no dominio).
- [x] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`. `auth/mfa_ports.go` (TOTPProvider Generate/CodeAt/Validate, MFASecretStore Stage/Promote/GetActive/Disable, MFAChallengeStore Consume/RecordFail/MarkReplay + errores InvalidMFA/NoStaged/LastFactor). `go vet` sin otp/redis/pgx en domain.
- [x] T-03: Implementar pruebas unitarias del dominio garantizando invariantes. `mfa_totp_test.go` (vectores RFC, ventana, bordes counter, staged TTL conceptual). `go test ./internal/domain/... -race` verde.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [x] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso. `mfa_setup.go` (Setup Step-Up+Generate+Encrypt+Stage, Enable Decrypt+Validate±1+PromoteTx+backups 1 vez), `mfa_verify.go` (pre-token→Consume→rate→Decrypt→Validate→Replay→Issue+quema, todo opaco), `mfa_disable.go` (Step-Up+CanUnlink-last-factor+DisableTx+aviso). Solo puertos.
- [x] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio. `mfa_total{op,result}` + duración + `challenges_burned` + `replay_blocked` vía MetricsPort; spans Setup/Enable/Verify/Disable + hijos sin secreto. Fake metrics.
- [x] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks. `mfa_verify_test.go` + `mfa_setup_test.go` (ok/quema, replay 401, 5º burn, expirado igual, RedisDown DB-fallback/500-reuso, staged-expired, último-factor, idempotencia RequestID). `go test ./internal/service/... -race` verde.

## Fase 3: Infraestructura y Adaptadores
- [x] T-07: Crear migración SQL en `scripts/migrations/`. `20261005_008_mfa_totp.up/down.sql` (secrets staged, used_counters UNIQUE, challenges + idx). `migrate up/down/up` PG16 + verifica UNIQUE(user,counter) bloquea replay-DُB y staged-expire purga worker.
- [x] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`. `postgres/mfa_secret_store.go` (Stage/PromoteTx con users.mfa_enabled+backups CU-AUTH-03 en Tx, GetActive, DisableTx, challenges/used fallbacks) + `redis/mfa_challenge_store.go` (challenge EX300+denylist, fails INCR, used NX EX90, staged EX600, down→DB/500-reuso). Tests testcontainers (PG+Redis) incl. RedisDown y skew.
- [x] T-09: Implementar productor de eventos en `internal/adapter/colas/` + TOTP/SecretBox en `security/`. `security/totp_provider.go` (HMAC-SHA1 RFC4226/6238, 20B rand, b32, ConstantTime) + `secret_box.go` (AES-GCM AAD=user_id, fail-fast) + `kafka` tipos `mfa.enabled|verified|disabled|failed|replay_blocked` + audit; worker emails activado/desactivado/bloqueo. Vectores RFC en test + KMS-mock down → setup 500.
- [x] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`. `dto/mfa_dto.go` + 5 handlers (setup 200+QR, enable, verify SIN Bearer, disable, status) + fresh-auth middleware + buckets mfa + `errors/map` (401 único INVALID_MFA, STEP_UP, ALREADY/NO_STAGED/LAST_FACTOR). httptest: setup stale 401, enable ok+backups 1 vez, verify ok/quema/replay/5º-burn/expirado idénticos, disable último 400, QR sin secreto en logs.
- [x] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`. 5 rutas `/mfa/totp/*` + `/mfa/verify|/status` con recover→requestID→auth(+fresh)→rateLimit→handler (verify sin auth clásica, con pre-token); wiring Redis+PG+TOTP+Box+Challenge → services (+SessionIssuer CU-AUTH-04, +Backups CU-AUTH-03); env `MFA_ISSUER, MFA_SECRETS_KEY, STEP_UP=300s`. `go build ./...` + smoke (setup→enable→login-202→verify-200→replay-401→disable) en compose.

## Fase 4: Verificación, Carga y Seguridad
- [x] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP). Compose + Mailhog: enroll (QR+enable+backups 1 vez) → login 202 → verify ok 200+cookies → replay 401 → ±1 skew ok → 5 fallos quema → stale-setup 401 → disable último 400 / con resto 200+mail → pre-token en negocio 401. Evidencia PR.
- [x] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99. `mfa_smoke.js` 50VUs setup/enable p95<300ms + 100VUs verify p95<250ms hit/<600ms fallback, replay 100% 401, `|p50(valid)-p50(invalid)|<50ms`, Redis-down primer 200/reuso 500. Adjunta summary.
- [x] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks). Checklist: pre-token aud-aislado 5min 1 uso, ventana ±1 + replay 90s, ConstantTime, secreto cifrado + 1 exhibición + nunca logs, Step-Up setup/disable, último-factor, sin Bearer en verify, sin code/token en eventos, QR sin leak, NTP documentado. Dictamen `seguridad.md` PASSED.
- [x] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`. Solo tras T-12/13/14. `READY_FOR_DEV→...→COMPLETED`, 15/15, `last_updated`.
