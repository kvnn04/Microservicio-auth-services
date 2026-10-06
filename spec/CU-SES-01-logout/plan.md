# Plan de Implementación Técnica: CU-SES-01

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`logout.go`) + `internal/domain/user/` (sesión ajena no).
* **Entidades / Value Objects:**
  ```go
  type LogoutResult string // LoggedOut | AlreadyLoggedOut
  type LogoutIdentity struct { UserID, SID, JTI, Family string; ExpiresAt time.Time }
  func DenylistTTL(expiresAt, now time.Time) time.Duration // clamp 1s..15min
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/session_revoke_ports.go
  type SessionRevoker interface {
    RevokeSID(ctx context.Context, id LogoutIdentity) (LogoutResult, error) // Tx PG + Redis + outbox; ErrNotFound→Already
    RevokeByRefreshHash(ctx context.Context, refreshHash string) (LogoutResult, error) // localiza family→sid→RevocaSID
  }
  ```
  Reuso `AccessSigner.Verify` (solo verifica, no firma), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicio:** `internal/service/logout.go`
  * `Logout(bearerClaims, refreshOpt, reqID)`:
    1. `Verify` Bearer (firma/kid/iss/aud/exp; `exp` pasado → `ErrUnauthorized`; revocado/denylist NO bloquea aquí — se verifica firma aunque esté en denylist para idempotencia).
    2. Rate `logout:user|ip` (`ErrRateLimited`).
    3. Idempotencia RequestID 24h.
    4. `SessionRevoker.RevokeSID` (si `ErrNotFound` → `AlreadyLoggedOut`, igual `200`) o `RevokeByRefreshHash` si vino sin Bearer pero con refresh.
    5. Métrica/audit (`ok|already`) + `Output{Status}` (el adapter pone Clear-Cookie).
* **Flujo Orquestado:** verify→rate→idempotencia→revoke(Tx+Redis+denylist+outbox)→200. Sin Step-Up, sin frescura, sin locks cuenta.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler `handlers/logout.go` (`POST /api/v1/auth/logout`, auth-parser tolerante-revoked (verifica firma aunque denylisteado), acepta Bearer o `{refresh_token}` body alternativo, `≤4KB`, `no-store`, mapea `401/429/500`, `200 logged_out|already_logged_out` + `Clear-Cookie refresh_token` MISMO Path/Domain/SameSite que Issue).
  * DTO `dto/logout_dto.go`; middleware reuso `rate_limit` (`logout:user 30/min`, `logout:ip 60/min`), `request_id`, `recover` (sin `require_fresh_auth`).
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/logout`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/session_revoker.go` (Tx: `SELECT family FROM sessions WHERE sid+user` (miss→`ErrNotFound`) + `UPDATE families revoked` + `DELETE sessions sid` + `INSERT revoked_jtis(jti, exp)` fallback + outbox `logged_out`).
  * Redis: `persistencia/redis/session_revoker.go` (`DEL sess/fam` + `SET jti revoked EX=restante`; `RevokeByRefreshHash`: `GET fam:*` inverso? Vinculante: mantiene índice `refresh:by_hash:<sha256> → family` desde Issue (añadir `SET` en CU-AUTH-04 si falta) para localizar sin SCAN; down → PG verdad + `WARN`).
* **Salida (Mensajería):** reuso `kafka` (`session.logged_out.v1` + audit `session.logout`); sin SMTP (logout propio no avisa; el robo se detecta en SES-04).
* **Salida (Seguridad):** reuso `ed25519_verifier` (misma JWKS/kid, `aud=api`, skew 30s; aquí NO exige `valid_after`/denylist para entrar — solo firma+exp).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `logout_total{result=ok|already|invalid|rate_limited|error}` + duración + `logout_denylist_size_gauge`. Vía MetricsPort + middleware (429).
* **Tracing (OpenTelemetry):** Raíz `UseCase.Logout` (hijos `jwt.verify`, `ratelimit`, `db.session.revoke`, `cache.revoke+denylist`, `outbox.insert`). Atributos `sid`, nunca tokens.
* **Logs Estructurados:** `pkg/logger`: `INFO logout ok|already` (con `sid`), `WARN invalid/rate_limited`, `ERROR db`. Sin `Access/Refresh` (solo `sid/jti`).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_016_session_revoke.up.sql` (+ down):
  ```sql
  CREATE TABLE IF NOT EXISTS revoked_jtis (jti UUID PRIMARY KEY, user_id UUID NOT NULL, expires_at TIMESTAMPTZ NOT NULL);
  CREATE INDEX IF NOT EXISTS idx_revoked_exp ON revoked_jtis(expires_at);
  -- purga por worker: DELETE WHERE expires_at<now() cada 5min
  -- índice inverso refresh ya existe (refresh_hashes.hash PK); se añade si falta:
  -- CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_hashes(family);
  ```
  Down: `DROP TABLE revoked_jtis;`. Redis `jti:* EX≤900`, `refresh:by_hash:*` (índice, documenta `SET` en Issue).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `logout_test.go` (DenylistTTL clamp, Already vs Ok) + servicio table-driven con fakes (ok revoca triple-capa, already mismo 200, expirado/malo 401, sin-Bearer-con-refresh ok, sin-nada 401, replay RequestID 1 outbox). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/logout_smoke.js`: 50 VUs logout (p95 <150ms sin Argon2, PG+Redis sanos), replay 100% `already`, flood 40/min→31º 429, gateway-mock (A denylisteado 401, B 200), refresh-post-logout 401 revoked-no-robo, Redis-down 200 vía PG-fallback + rehidrata, PG-down 500 sin Clear-Cookie.
