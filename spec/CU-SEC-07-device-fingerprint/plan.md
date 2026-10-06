# Plan de Implementación Técnica: CU-SEC-07

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`device.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    DeviceMaxTrusted=10; DeviceChallengeTTL=10*time.Minute; KillLinkTTL=24*time.Hour
    DeviceMaxFails=3
  )
  type DeviceFP struct { Hash, HMAC, Label, IPMasked string }
  func Fingerprint(uaFamily, osFamily, class, ip24, lang string) (hash string)
  func HMACFP(hash, key string) string
  func ExactMatch(a, b string) bool // ConstantTime
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/device_ports.go
  type Fingerprinter interface { FromRequest(ua, ip, lang string) DeviceFP } // parse UA liviano + /24 + HMAC (key inyectada)
  type DeviceStore interface {
    Find(ctx context.Context, userID, fpHash string) (trusted bool, err error) // + touch last_seen
    AddTx(ctx context.Context, userID string, fp DeviceFP) error // upsert + evict oldest si 10 + outbox
    List(ctx context.Context, userID string) ([]DeviceFP, error) // (para SES-03 labels futuros, no endpoint aquí)
  }
  type DeviceChallengeStore interface {
    Issue(ctx context.Context, userID string, fp DeviceFP) (otpPlain, linkToken string, err error) // hashes + 1 activo + quotas
    Verify(ctx context.Context, userID, codeOrToken string) error // OTP/link 10min 1 uso + 3 fails queman; ErrInvalid
    IssueKill(ctx context.Context, userID, sid string) (killToken string, err error) // 24h 1 uso
    RedeemKill(ctx context.Context, killToken string) (sid string, err error) // valida + marca used; ErrInvalid|Expired
  }
  ```
  Reuso `MFAPreTokenIssuer`? No: challenge propio `aud=device-challenge` (o reuso `passwordless`-like con `purpose=device`; decisión: tabla propia `device_challenges` + `session_kill_links`, no mezclar propósitos).

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/device_check.go` (PreIssue) + `device_verify.go` + `device_kill.go`
  * `PreIssue(userID, mfa, req-ctx UA/IP/lang)`: `Fingerprinter` → `DeviceStore.Find` (hit+hmac-ok → `trusted`, touch, sigue) → miss/0 (`first`? auto-trusted + email-info + sigue) → desconocido: si `mfa` → `Output{forceMFA:true}` (el llamador emite su `202` + email nuevo-dispositivo, sin challenge propio); si no → `DeviceChallengeStore.Issue` + email challenge → `Output{device_challenge:true}` (el llamador responde `202 device_challenge`, sin Issue).
  * `VerifyChallenge(userID, code|token)`: `Verify` (3 fails queman) → `DeviceStore.AddTx` (evict) → retorna para que el llamador haga `Issue` + email sesión-con-kill (`IssueKill` en el mismo flujo post-Issue).
  * `RedeemKill(token)`: `RedeemKill` → revoca ESA `sid` (reuso `SessionRevoker.RevokeSID` SES-01 por `sid` directo, sin auth) → `200 killed|already` + emails.
  * Fusión travel: si `TravelGuard` también forzó MFA, un solo `202` con `device_fp` atado al `challenge_id` MFA (el `MFAVerify` registra device al verificar TOTP — inyecta `DeviceStore` en `mfa_verify` como paso post-verify).
* **Flujo Orquestado:** secreto-ok→`PreIssue`→(trusted|first→Issue) o (forceMFA→202) o (challenge→202 device) →verify→trusted+Issue+kill-link→email; kill anónimo→revoca-sid.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/device_verify.go` (`POST /device/verify {device_token?, code|token}` sin Bearer → `200` + sigue login? No: el verify-device NO emite sesión (solo registra trusted); el front tras `200 verify` debe REINTENTAR el login original (que ahora es trusted) o el back encadena? Decisión vinculante: encadena — `POST /device/verify` exitoso retorna DIRECTO el `200/202` de sesión (hace `Issue`/pre-token dentro, reuso llamador original con `device_trusted=true` flag interno). Sin doble-roundtrip) + `device_kill.go` (`GET|POST /device/kill?token=` → página/`200 killed|already`) .
  * DTO `dto/device_dto.go`; middleware reuso rate (`device:send 5/hora`, `verify:tok 5/min`, `kill:ip 30/min`); `errors/map` (+`DEVICE_CHALLENGE_REQUIRED→202` (no error), `INVALID_DEVICE_CHALLENGE→401` opaco, `KILL_INVALID→400`).
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/device/verify`, `GET|POST /api/v1/auth/device/kill`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/device_store.go` (`trusted_devices(user_id, fp_hash PK2, hmac, label, ip_masked, first_seen, last_seen)`, `device_challenges(challenge_hash PK, user_id, fp_hash, otp_hash, exp, fails, consumed)`, `session_kill_links(token_hash PK, user_id, sid, exp, used)`; `AddTx` con evict `DELETE oldest WHERE count>=10` + outbox).
  * Redis: `dev:<uid>:<fp> EX86400` fast-path + `dev:challenge:*` + quotas + `kill` no (PG verdad 24h) ; down → PG + `WARN` (Q-fail-open: sin PG no hay check — PG-down ya es `500` base).
* **Salida (Mensajería):** `kafka` (`device.unknown|trusted|killed`, `device.challenge_sent` + audit) + worker SMTP triple (challenge OTP/link-10min, nuevo-dispositivo (MFA), sesión-con-kill-link) siempre.
* **Salida (Seguridad):** `security/fingerprinter.go` (UA-parse liviano + `/24` + `HMAC_SHA256(DEVICE_HMAC_KEY)`, `ConstantTime`) + reuso `token_issuer` (OTP/link/kill 32B) + `MFAPreToken`? No (challenge propio `aud=device-challenge`).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `device_unknown_total{action=trusted|first|mfa_challenge|email_challenge|kill|invalid|rate|skipped_nohmac}` + `trusted_count` histogram + `device_kill_total{result}` + `hmac_mismatch_total`.
* **Tracing (OpenTelemetry):** Hijo `Defense.DeviceCheck` pre-Issue (hijos `device.fingerprint`, `db.trusted.lookup`, `challenge.issue|verify`, `db.trusted.add`, `kill.issue|redeem`). Atributos `label` (no huella).
* **Logs Estructurados:** `pkg/logger`: `INFO device trusted|first|killed`, `WARN unknown/mismatch/rate/quema`, `ERROR db`. Sin `fp/hmac/token/UA-crudo` (label+prefix).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_026_devices.up.sql` (+ down):
  ```sql
  CREATE TABLE trusted_devices (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fp_hash TEXT NOT NULL, hmac TEXT NOT NULL, label TEXT NOT NULL, ip_masked TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, fp_hash)
  );
  CREATE TABLE device_challenges (
    challenge_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fp_hash TEXT NOT NULL, otp_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
    fails INT NOT NULL DEFAULT 0, consumed BOOLEAN NOT NULL DEFAULT FALSE
  );
  CREATE TABLE session_kill_links (
    token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sid UUID NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used BOOLEAN NOT NULL DEFAULT FALSE
  );
  ```
  Down: `DROP TABLE ...;`. Redis `dev:*` (efímeros). `DEVICE_HMAC_KEY` env 32B (rotación dual-key documentada).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `device_test.go` (Fingerprint estable, HMAC mismatch, ExactMatch ConstantTime, LRU-10 evict-oldest) + servicio table-driven con fakes (trusted-direct, first-auto, MFA-force indistinguible, email-challenge+verify→Issue+kill, 3º-quema, kill ok/already/ajeno-400, sin-key skip, PG-down 500). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/device_smoke.js`: 50 VUs logins mismo-device (trusted, p95 overhead <10ms) + 30 VUs new-device (challenge/kill, p95 <300ms) + flood send 6/hora→429 + HMAC-rotada (1 re-desafío masivo medido) + Redis-down (PG verdad) + sin-key (100% skip). Chaos PG-down → `500` base.
