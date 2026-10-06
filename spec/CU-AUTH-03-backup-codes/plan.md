# Plan de Implementación Técnica: CU-AUTH-03

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`backup_codes.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    BackupCount=10; BackupChars=10; BackupAlphabet="23456789ABCDEFGHJKMNPQRSTVWXYZ"
    BackupDisplaySep=4 // XXXX-XXXXXX solo display
  )
  type BackupCode struct { UserID, CodeHash string; Used bool }
  func Canonicalize(raw string) (string, error) // upper, sin guion/espacios, ^[Alphabet]{10}$
  func Display(canonical string) string // XXXX-XXXXXX
  func HashWithPepper(canonical, pepper string) string // hex(sha256(canonical+pepper))
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/backup_ports.go
  type BackupCodeStore interface {
    GenerateTx(ctx context.Context, userID string, hashes []string, supersede bool) error // INSERT 10 + (supersede? quema previos) + outbox; ON CONFLICT DO NOTHING + relleno
    ConsumeTx(ctx context.Context, userID, hash, challengeID string) (remaining int, err error) // SELECT FOR UPDATE + UPDATE used + outbox; ErrNotFound|ErrAlreadyUsed
    CountRemaining(ctx context.Context, userID string) (int, error)
  }
  ```
  Reuso `MFAChallengeStore` (consume/fails), `SessionIssuer`, `EventPublisher`, `SecretBox` no (hash, no cifrado).

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/backup_codes.go` (Generate en Enable + Regenerate) + injerto en `mfa_verify.go` (autodetección) + `mfa_disable.go` (quema al deshabilitar)
  * `GenerateForEnable(userID, reqID) → [10]planos`: `CSPRNG 10×10ch` (reintenta colisión memoria) → `HashWithPepper` → `GenerateTx(supersede=false)` → retorna planos 1 vez (el servicio los olvida tras retornar).
  * `Regenerate(userID /*freshAuth ya validada*/)` → `GenerateTx(supersede=true)` → retorna 10 nuevos.
  * `VerifyBackup(mfaToken, rawCode)`: normaliza/canonicaliza (malforma → `ErrValidation`) → `ChallengeStore.Consume` (igual TOTP) → rate → `BackupCodeStore.ConsumeTx` (miss/used → `RecordFail` + `ErrInvalidMFA` opaco igual TOTP) → quema challenge + `SessionIssuer.Issue` + email flag (outbox) → `Output{remaining, warning}`.
  * Autodetección en `MFAVerify`: `len(canónico)==10 && alfabeto backup → backup-path; len==6 dígitos → totp-path; otro → ErrValidation`. Misma `ChallengeStore`/fails/401 para ambos (sin oráculo tipo).
* **Flujo Orquestado:** Step-Up/pre-token primero → canonicaliza → challenge-consume → Tx backup → sesión + outbox email. Idempotencia RequestID (replay mismo RequestID+ mismo código → misma respuesta sin doble-consume: `used_challenge_id` + idempotency guard).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Reuso `POST /api/v1/auth/mfa/verify` (acepta `{mfa_token, code}` donde `code` 6d=TOTP o 10ch=backup, o `{mfa_token, backup_code}` alias) — sin rutas verify nuevas. Nueva `POST /api/v1/auth/mfa/backup-codes/regenerate` (auth+fresh Step-Up → `200 {backup_codes:[10], remaining:10}`) + `GET /mfa/status` añade `{backup_remaining, backup_warning}`.
  * DTO `dto/backup_dto.go`; `errors/map` reusa `INVALID_MFA` (consume) + `STEP_UP_REQUIRED` (regenerate stale).
  * Middleware reuso `mfa:verify:*` (sin bucket nuevo que distinga) + `backup:regen 10/hora/user`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/backup_code_store.go` (`mfa_backup_codes(code_hash PK global TEXT, user_id FK, used BOOL, used_at, used_challenge_id, superseded BOOL, created_at)`, `GenerateTx`: quema-previos opcional + `INSERT ... ON CONFLICT(code_hash) DO NOTHING` + verifica 10 insertados o rellena 1 intento extra; `ConsumeTx`: `SELECT ... FOR UPDATE` + `UPDATE used` + `SELECT COUNT remaining` en misma Tx + `INSERT outbox backup.consumed`).
  * Redis: reuso challenge/fails/rate CU-AUTH-02 (sin claves nuevas salvo `backup:regen:<user> EX 3600` para 10/hora).
* **Salida (Mensajería):** reuso `kafka` (`backup.generated|consumed|regenerated|failed` → `auth.backup.v1` + `mfa.verified{method:backup}` + audit); worker SMTP alta prioridad `backup_consumed` (con `remaining`, links regenerate/asegura, sin planos) siempre.
* **Salida (Seguridad):** `security/backup_hasher.go` (`crypto/rand` + `crypto/sha256`, `subtle.ConstantTimeCompare`, pepper `PASSWORD_PEPPER` + `PEPPER_PREV` ventana) + reuso TOTP tracker.

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `backup_total{op=generate|consume|regenerate, result=ok|invalid|replay|exhausted|rate_limited|error}` + `backup_remaining_gauge{bucket=0|1-2|3-10}` (actualizada al consumir/regenerar) + cuenta en `mfa_total{verify ok, method=backup}`. Vía MetricsPort.
* **Tracing (OpenTelemetry):** Hijos `Backup.GenerateHashes`, `Backup.ConsumeTx`, `Notify.BackupEmail` en `UseCase.MFA*`. Atributos `remaining, code_hash_prefix(8)`, nunca plano/token.
* **Logs Estructurados:** `pkg/logger`: `INFO backup generate/consume/regenerate` (con `remaining`), `WARN invalid/replay/exhausted/rate_limited`, `ERROR db`. Sin `backup_code/hash completo` (solo prefix 8 en DEBUG).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_009_backup_codes.up.sql` (+ down):
  ```sql
  CREATE TABLE mfa_backup_codes (
    code_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used BOOLEAN NOT NULL DEFAULT FALSE, used_at TIMESTAMPTZ, used_challenge_id UUID,
    superseded BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_backup_user ON mfa_backup_codes(user_id) WHERE NOT used;
  ```
  Down: `DROP TABLE mfa_backup_codes;`. Sin Redis nuevo (reuso challenge). Purga: nunca borra (auditoría; `used` crecen ≤10/regeneración, documenta retención indefinida + partición futura si abuso regenerate).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `backup_codes_test.go` (Canonicalize/display/alfabeto, Hash determinista + pepper-prev fallback, colisión memoria reintenta) + servicio `backup_verify_test.go` table-driven con fakes (generate 10 únicos + hashes no contienen planos, consume ok→remaining-1+email flag, reuso→401, miss→401 igual TOTP, regenerate supersede quema viejos, stale→401, PG-down→500 sin quemar). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/backup_smoke.js`: 50 VUs generate/regenerate (p95 <300ms) + 100 VUs verify-backup (válidos/inválidos/reusos, p95 <300ms PG-Tx, 100% reuso→401, `|p50(totp-bad)-p50(backup-bad)|<40ms` sin oráculo tipo) + concurrencia mismo código 2× (1×200+1×401 determinista). Chaos PG-down→500 sin quemar, Redis-down→consume 200 correcto (PG verdad).
