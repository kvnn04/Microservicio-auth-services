# Plan de Implementación Técnica: CU-AUTH-02

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`mfa_totp.go`) + `internal/domain/user/` (flag `mfa_enabled` CU-AUTH-01).
* **Entidades / Value Objects:**
  ```go
  const (
    TOTPAlgo="SHA1"; TOTPDigits=6; TOTPStep=30*time.Second; TOTPSecretBytes=20
    TOTPWindow=1; TOTPLeeway=5*time.Second; StagedTTL=10*time.Minute
    PreTokenTTL=5*time.Minute; MaxVerifyFails=5; ReplayTTL=90*time.Second
  )
  type TOTPSecret struct { UserID string; SecretEnc []byte; Staged bool; Verified bool }
  func NewCounter(now time.Time) int64 // floor((now+leeway)/30)
  func Candidates(counter int64) []int64 // c-1,c,c+1
  func FormatCode(v uint32) string // %06d
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/mfa_ports.go
  type TOTPProvider interface {
    GenerateSecret(ctx context.Context) (raw []byte, b32 string, err error) // 20B CSPRNG
    CodeAt(ctx context.Context, raw []byte, counter int64) (string, error) // HMAC-SHA1 RFC4226 (para tests/vectores)
    Validate(ctx context.Context, raw []byte, code string, counter int64) (matchedCounter int64, ok bool) // ±1 ConstantTime
  }
  type MFASecretStore interface {
    Stage(ctx context.Context, userID string, secretEnc []byte) error // upsert staged EX 10min lógico (staged_expires_at)
    PromoteTx(ctx context.Context, userID string) error // staged→active + users.mfa_enabled=true + outbox (Tx PG)
    GetActive(ctx context.Context, userID string) (secretEnc []byte, err error) // ErrNotFound
    DisableTx(ctx context.Context, userID string) error // delete + mfa_enabled=false + outbox
  }
  type MFAChallengeStore interface {
    Consume(ctx context.Context, challengeID string) (userID string, err error) // GET+DEL atómico; ErrNotFound=>expired/burned
    RecordFail(ctx context.Context, challengeID string) (burned bool, err error) // INCR 5min; a 5 => DEL+denylist
    MarkReplay(ctx context.Context, userID string, counter int64) (fresh bool, err error) // SET NX EX 90 (false=>replay)
  }
  ```
  Reuso `SessionIssuer` (CU-AUTH-01/04), `EventPublisher/Outbox`, `PasswordHasher` no (aquí no hay password).

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/mfa_setup.go` (Setup+Enable), `mfa_verify.go` (Verify), `mfa_disable.go` (Disable+Status)
  * `Setup(userID, freshAuth)`: `RequireFreshAuth(5min)` → `TOTP.GenerateSecret` → `Encrypt(secret)` (puerto `SecretBox`, AES-GCM) → `Stage` (supersede) → `Output{otpauth_url, qr?}` (el servicio NO genera SVG; el adapter lo renderiza).
  * `Enable(userID, code)`: `GetStaged+Decrypt` (expirado → `ErrNoStaged`) → `TOTP.Validate(±1)` (falla → `ErrInvalidMFA`, sin quemar staged; 5 enables fallidos/hora → `429` vía tracker) → `PromoteTx` + delega `BackupCodes.Generate` (CU-AUTH-03 puerto, 10×1 vez) → `Output{backup_codes}`.
  * `Verify(mfaToken, code)`: `ParsePreToken` (firma+aud+exp; falla → `ErrInvalidMFA` opaco) → `ChallengeStore.Consume` (miss → `ErrInvalidMFA`) → rate-check challenge/IP → `SecretStore.GetActive+Decrypt` → `TOTP.Validate` (falla → `RecordFail` (posible burn) + `ErrInvalidMFA`) → `MarkReplay` (fresco? no → `ErrInvalidMFA` replay) → quema challenge (ya consumido) + `SessionIssuer.Issue` → `Output{cookies}`.
  * `Disable(userID)`: `RequireFreshAuth` → `ListFactors` (reuso CU-REG-06: si último → `ErrLastFactor`) → `DisableTx` + quema backups (CU-AUTH-03) + email.
* **Flujo Orquestado:** Step-Up primero (setup/enable/disable), pre-token primero (verify); cripto ConstantTime; Tx PG para promote/disable; idempotencia RequestID 24h (replay `enable` mismo code+RequestID no duplica backups).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/mfa_setup.go` (`POST /totp/setup` auth+fresh → `200 {secret_b32, otpauth_url, qr_svg, expires_in:600}`), `mfa_enable.go` (`POST /totp/enable {code}`), `mfa_verify.go` (`POST /mfa/verify {mfa_token, code}` SIN Bearer), `mfa_disable.go` (`DELETE /totp`), `mfa_status.go` (`GET /mfa/status`).
  * DTO `dto/mfa_dto.go`; middleware reuso `require_auth`, `require_fresh_auth(300s)`, buckets `mfa:setup 10/h/user, mfa:verify:challenge 5/min, mfa:verify:ip 20/min`; `errors/map.go` (+`INVALID_MFA, MFA_CHALLENGE_EXPIRED→401` mismo body, `MFA_ALREADY_ENABLED/NO_STAGED/LAST_AUTH_FACTOR`).
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/mfa/totp/setup|/enable`, `POST /api/v1/auth/mfa/verify`, `DELETE /totp`, `GET /status`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/mfa_secret_store.go` (`mfa_totp_secrets(user_id PK, secret_enc BYTEA, staged BOOL, staged_expires_at, verified, enabled_at)`, `mfa_used_counters(user_id, counter, UNIQUE)` fallback replay, `mfa_challenges(challenge_id PK, user_id, consumed, exp)` fallback single-use; Tx promote `UPDATE secrets + UPDATE users.mfa_enabled + INSERT outbox + INSERT backup_hashes (CU-AUTH-03)`).
  * Redis: `persistencia/redis/mfa_challenge_store.go` (`mfa:challenge:<id> EX 300`, `mfa:fails:<id> INCR EX 300` + denylist, `mfa:used:<u>:<c> NX EX 90`, `mfa:staged:<u> EX 600` зеркало rápido; down → DB fallback + `500 REPLAY_UNCHECKABLE` solo en reuso indetectable).
* **Salida (Mensajería):** reuso `kafka` (`mfa.enabled|verified|disabled|failed|replay_blocked` → `auth.mfa.v1` + audit); worker email `MFA activado/desactivado` (siempre) + `intento MFA bloqueado` (throttle).
* **Salida (Seguridad):** `security/totp_provider.go` (`crypto/hmac-sha1`, `crypto/rand` 20B, `base32.StdEncoding` sin padding para `secret_b32`, `ConstantTimeCompare` códigos) + `security/secret_box.go` (`AES-256-GCM`, key `MFA_SECRETS_KEY` 32B env/KMS, `AAD=user_id`, fail-fast sin key) + reuso `mfa_pretoken_issuer` (CU-AUTH-01; verify aquí, emisión allí).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `mfa_total{op,result}` (setup, enable, verify ok|invalid|replay|burned|expired, disable, last_factor, rate_limited), `mfa_verify_duration_seconds`, `mfa_challenges_burned_total{reason}`, `mfa_replay_blocked_total`, `mfa_kms_failures_total`. Vía MetricsPort + middleware.
* **Tracing (OpenTelemetry):** Raíces `UseCase.MFASetup/Enable/Verify/Disable` (hijos `auth.stepup.check`, `mfa.secret.generate|encrypt|decrypt`, `mfa.challenge.validate|burn|fails`, `crypto.totp.validate`, `replay.check|mark`, `db.mfa.*`, `session.issue` (verify), `outbox.insert`). Atributos `counters_tried`, nunca secreto/código/token.
* **Logs Estructurados:** `pkg/logger`: `INFO mfa setup/enable/verify/disable ok` (con `user_id`), `WARN invalid/replay/burned/rate_limited/no_staged`, `ERROR db/kms/replay_uncheckable`. Sin `secret/code/mfa_token`.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_008_mfa_totp.up.sql` (+ down):
  ```sql
  CREATE TABLE mfa_totp_secrets (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc BYTEA NOT NULL, staged BOOLEAN NOT NULL DEFAULT TRUE,
    staged_expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+INTERVAL '10 minutes',
    verified BOOLEAN NOT NULL DEFAULT FALSE, enabled_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE TABLE mfa_used_counters (user_id UUID NOT NULL, counter BIGINT NOT NULL, used_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (user_id, counter));
  CREATE TABLE mfa_challenges (challenge_id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, consumed BOOLEAN NOT NULL DEFAULT FALSE, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
  CREATE INDEX idx_mfa_challenges_user ON mfa_challenges(user_id) WHERE NOT consumed;
  ```
  Down: `DROP TABLE mfa_challenges, mfa_used_counters, mfa_totp_secrets;`. Redis `mfa:challenge:* EX300`, `mfa:used:*:* EX90`, `mfa:staged:* EX600`, `mfa:fails:* EX300`. Purga staged expirados por worker (`DELETE WHERE staged AND staged_expires_at<now()` cada 5min).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** Dominio+provider `totp_test.go` (vectores RFC6238 SHA1/6/30, ventana ±1 acepta / ±2 rechaza, zero-pad, counter bordes) + `secret_box_test.go` (roundtrip, AAD mismatch falla, sin key fail-fast). Servicio `mfa_verify_test.go` table-driven con fakes (ok→Issue+quema, replay→401 aunque cripto ok, 5º fallo quema, expirado→401 igual, RedisDown primer→200 DB / reuso→500, staged expirado→400, disable último→400). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/mfa_smoke.js`: 50 VUs setup/enable (p95 <300ms) + 100 VUs verify (válidos/inválidos/replay mezclados, p95 <250ms Redis-hit / <600ms DB-fallback, `replay_blocked` 100% 401, `|p50(valid)-p50(invalid)|<50ms` anti-oráculo challenge). Chaos Redis-down 60s → primer-uso 200 + reuso 500 medido; KMS-mock down → setup 500 + servicio no cae (solo op); skew ±40s simulado (counters ±1) → 200.
