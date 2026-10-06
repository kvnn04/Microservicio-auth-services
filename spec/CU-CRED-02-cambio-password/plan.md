# Plan de Implementación Técnica: CU-CRED-02

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`password_change.go`) + `internal/domain/user/` (versión password).
* **Entidades / Value Objects:**
  ```go
  const PasswordHistoryN=5; const PwdChangeRatePerHour=5
  func ValidateNewPassword(newPlain, emailLocal string, breach BreachChecker) error // reuso Password.Validate CU-REG-01
  func DistinctFromHashes(newPlain string, hashes []string, verify func(plain, hash string) bool) (reusedActual, inHistory bool)
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/password_change_ports.go
  type PasswordHistoryStore interface {
    Current(ctx context.Context, userID string) (*ChangeAccount, error) // hash+ver+status+email
    LastN(ctx context.Context, userID string, n int) ([]string, error) // hashes desc
    RotateTx(ctx context.Context, userID, oldHash, newHash string, expectedVer int, keepSID, requestID string) (newVer, peersRevoked int, err error)
    // Tx: FOR UPDATE + base/ver (TOCTOU) + INSERT history(old) + UPDATE users(newHash,ver+1) + revoke families/sessions salvo keep + outbox + email
  }
  ```
  Reuso `PasswordHasher` (Verify×N + Hash), `BreachChecker`, `AttemptTracker` (fails), `StepUpService.Check` vía interfaz local (solo federated-set), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicio:** `internal/service/change_password.go`
  * `Change(userID, sid, family, currentOpt, newPlain, stepUpTokenOpt)`:
    1. `Users.FindByID` (ACTIVE? si no → `ErrAuth` genérico `401`; PENDING/LOCKED no cambian aquí).
    2. Rate `pwdchange:user 5/hora` (`ErrRateLimited`).
    3. Policy `ValidateNewPassword` (falla → `ErrPolicy` con details, sin fails cuenta).
    4. Si `hasPassword`: `Hasher.Verify(current, stored)` (falla → `RecordFail` + `ErrInvalidCurrent`); si no: `StepUpVerifier.VerifyFor(userID, cred:change-password, token)` o fast-pass (falla → `ErrStepUp`).
    5. `DistinctFromHashes`: `Verify(new, current)` → `ErrReused`; `LastN(5)` + Verify c/u → `ErrInHistory` (errores Verify de history corrupto se ignoran + `WARN`, no bloquean).
    6. `Hasher.Hash(new)` + `PasswordHistoryStore.RotateTx(old,new,keepSID,keepFamily)` (re-chequea `≠` en Tx con `SELECT FOR UPDATE` para TOCTOU) + email flag + métrica/audit. Idempotencia RequestID (mismo RequestID replay → mismo `200` si ese RequestID rotó, sino ejecuta).
* **Flujo Orquestado:** auth→rate→policy→StepUp-actual→history→hash→Tx rotate+revoke-pares→200. Nunca toca `tokens_valid_after`.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler `handlers/password_change.go` (`POST /api/v1/auth/password/change {current_password?, new_password}` auth → `200 {status, sessions_revoked}` o `400/401/429/500`, `no-store`, ≤8KB). `current` ausente con hash → `400 MISSING_CURRENT`; con federated-set exige `X-Step-Up-Token`/fast-pass verificado en el servicio (sin middleware Step-Up en la ruta: `current` equivale a Step-Up).
  * DTO `dto/password_change_dto.go`; `errors/map` (+`INVALID_CURRENT, PASSWORD_REUSED, PASSWORD_IN_HISTORY, MISSING_CURRENT, UNEXPECTED_CURRENT`).
  * Rutas `cmd/api/main.go`: `POST /password/change` con `auth → handler` (rate `pwdchange:user 5/h` en handler; Step-Up verificado en servicio solo federated-set).
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/password_history_store.go` (`password_history(user_id, hash, created_at) + INDEX(user,created)`, `RotateTx`: base/ver optimista + `INSERT history(old)` + `UPDATE users(hash,ver)` + `UPDATE families revoked WHERE user<>keep` + `DELETE sessions WHERE sid<>keep` + outbox `changed+revoked_peers` en una Tx; `LastN` con `ORDER BY DESC LIMIT 5`).
  * Redis: DEL de pares por claves exactas listadas en la Tx (`sess:<sid>`, `fam:<family>`, `jti:<jti>`; sin SCAN/`KEYS`, ver `spec.md` §8 D-04) + reconciliador existente purga huérfanos.
* **Salida (Mensajería):** reuso `kafka` (`password.changed{via}` + `session.revoked_peers{kept_sid, count}` + audit); worker SMTP `password_changed` (con `peers` + IP/hora + `si no fuiste tú`).
* **Salida (Seguridad):** reuso `argon2` (Verify×(2+N) + Hash, pepper) + `hibp` + `AttemptTracker` (fails a lock cuenta, compartido login).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `password_change_total{result, via}` + duración (histogram con buckets hasta 2s por Verify×5) + `pwdchange_history_hits_total` + `sessions_revoked_peers_total` + reuso `login_locks_total`. Vía MetricsPort.
* **Tracing (OpenTelemetry):** Raíz `UseCase.ChangePassword` (hijos `auth.check`, `ratelimit`, `crypto.verify_current`, `crypto.policy`, `crypto.history_check`, `crypto.hash`, `db.rotate+revoke`, `outbox.insert`). Atributos `history_n, peers`, nunca claves.
* **Logs Estructurados:** `pkg/logger`: `INFO password changed (peers)`, `WARN invalid_current/policy/reused/history/rate_limited/step_up`, `ERROR db`. Sin `current/new/hash` (solo `password_ver`).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_014_password_history.up.sql` (+ down):
  ```sql
  CREATE TABLE password_history (user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
  CREATE INDEX idx_pwdhist_user_created ON password_history(user_id, created_at DESC);
  ALTER TABLE users ADD COLUMN IF NOT EXISTS password_ver INT NOT NULL DEFAULT 1;
  -- SET sess:by_user:<uid> se mantiene en Redis desde Issue (014 documenta, no migra Redis)
  ```
  Down: `DROP TABLE password_history; ALTER TABLE users DROP COLUMN password_ver;`. Sin `valid_after` aquí (014 no lo toca).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `password_change_test.go` (Distinct matriz actual/history-5/ok, N ventana móvil, federated-set sin current) + servicio table-driven con fakes (ok+revoke-pares+history+1, current-mala→401+fail/lock, reused/history→400 sin fail extra, policy-fail→400 sin hash, federated-set sin token→401/con token→200, replay RequestID, TOCTOU: cambio concurrente 2× misma base → 1×200+1×400 REUSED por re-Verify en Tx). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/pwdchange_smoke.js`: 20 VUs change (p95 <1200ms por Verify×5, p99 <1800ms) + abuse (6/hora→6º 429, 5 current-malas→lock + buena 401) + pares-revoke verificado (B/C 401 en refresh) + Redis-down (PG verdad, `WARN`) + PG-down (500 0 cambios). Chaos history-corrupta (1 hash roto → `WARN` + cambio ok).
