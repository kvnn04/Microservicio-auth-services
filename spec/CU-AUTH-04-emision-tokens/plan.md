# Plan de Implementación Técnica: CU-AUTH-04

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`tokens.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    AccessTTL=15*time.Minute; RefreshSliding=30*24*time.Hour; RefreshAbsolute=90*24*time.Hour
    RefreshBytes=32; MaxSessionsPerUser=20
  )
  type AMR string // AMRPassword ("pwd"), AMRTOTP ("totp"), AMRBackup ("backup"), AMRFederated ("federated_google")
  type SessionRequest struct { UserID string; Method string; AMR []AMR; AuthTime time.Time; Device Device }
  type IssuedPair struct { AccessJWT string; RefreshPlain string; SID, JTI, Family, KID string; ExpiresAt time.Time }
  func NewAccessClaims(sub, sid, jti, kid string, authTime time.Time, amr []AMR, roles []string, rolesVer int) (Claims, error)
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/token_ports.go
  type AccessSigner interface { Sign(ctx context.Context, claims Claims) (jwt string, kid string, err error) } // Ed25519, ErrNoKey
  type RefreshStore interface { CreateFamily(ctx context.Context, tx any, userID, family, refreshHash, parentHash string, sid string) error }
  type SessionStore interface { SaveTx(ctx context.Context, tx any, sess Session) error; EvictLRU(ctx context.Context, tx any, userID string) (evictedSID string, err error) }
  type SessionIssuer interface { Issue(ctx context.Context, req SessionRequest) (IssuedPair, error) } // implementado en service (orquesta), no en adapter
  ```
  `Session` VO: `{SID, UserID, Family, JTI, DeviceHash, IPHash, CreatedAt, LastSeen, ExpiresAt}`.

### Capa de Aplicación (`internal/service/`)
* **Servicio:** `internal/service/issue_session.go` (implementa `SessionIssuer` = puerto CU-AUTH-01/02/REG-04)
  * `Issue`: valida ACTIVE (vía `Users.FindByID` o confía en llamador + re-chequea `status` y `tokens_valid_after`), genera `sid/jti/family+CSPRNG 32B`, `AccessSigner.Sign(NewAccessClaims(...))`, abre Tx PG (`Sessions+Families+Hashes+Outbox`), `SessionStore.SaveTx` (+`EvictLRU` si `COUNT>=20`), `RefreshStore.CreateFamily`, commit, write-through Redis (`sess/fam/jti`), métrica/audit. Orden firma→Tx→entrega (si Tx falla descarta JWT).
  * `Device` viene del llamador (login/MFA/federado calculan `ip/24+ua` igual).
* **Flujo Orquestado:** `ValidateReq → GenIDs → Sign → Tx(PG) → Redis → Outbox → Output`. Sin HTTP aquí (el handler llamador decide cookie/body). Idempotencia: `Issue` no es idempotente por RequestID (cada login crea `sid` nuevo aunque mismo RequestID reintentado tras éxito? No: si el llamador reintenta mismo RequestID tras `200`, el servicio llamador devuelve idempotente sin re-`Issue`; `Issue` directo 2× = 2 sesiones — documentado).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):** Sin rutas nuevas (Issue es interno). Cambios: `handlers/login|mfa_verify|federated_callback` usan `Issue` y traducen a híbrida:
  * `http/session_transport.go` (nuevo helper): `WritePair(w, pair, isNative)` (web: `JSON{access_token,expires_in,sid}` + `Set-Cookie refresh_token=...; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/refresh; Max-Age=2592000`; nativo: JSON ambos). Flags por `ENV` (dev relaja `Secure` + `WARN`).
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/session_store.go` (`sessions(sid PK, user_id FK, family, jti_actual, device_hash, ip_hash, created_at, last_seen, expires_at)`, `refresh_families(family PK, user_id, current_hash UNIQUE, parent_hash, counter, absolute_exp, revoked)`, `refresh_hashes(hash PK, family FK, counter, expires_at)`; Tx `SaveTx+CreateFamily+EvictLRU(DELETE oldest)` + `INSERT outbox session.issued`).
  * Redis: `persistencia/redis/session_store.go` (`SET sess:<sid> EX 7776000`, `SET fam:<family> {current} EX 7776000`, `SET jti:<jti> 1 EX 900`; down → PG verdad + rehidrata).
* **Salida (Mensajería):** reuso `kafka` (`session.issued.v1` + audit `session.issue`); worker sin SMTP (SES lo usa para revoke mails).
* **Salida (Seguridad):** `security/ed25519_signer.go` (`crypto/ed25519`, `key = base64(64B seed+pub)` env `SESSION_SIGNING_KEY` o KMS `crypto.Signer`, `kid` de `signing_keys` PG/hot-reload, `Sign` con `kid` actual, fail-fast sin key; test con clave efímera) + `security/refresh_generator.go` (`crypto/rand` 32B + `sha256` hex, `ConstantTime`).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `tokens_issued_total{method,amr}` + `token_issue_duration_seconds` + `sessions_active_gauge` (worker 1min `COUNT sessions`) + `sessions_evicted_total{reason=lru}` + `issue_redis_fallback_total`. Vía MetricsPort en `Issue`.
* **Tracing (OpenTelemetry):** Span `Session.Issue` (hijos `crypto.ed25519.sign`, `db.session.insert`, `cache.session.save`, `outbox.insert`) como hijo del `UseCase.*` llamador. Atributos `kid,sid,family,amr`, nunca tokens.
* **Logs Estructurados:** `pkg/logger`: `INFO session issued` (con `sid,family,jti,kid,amr`), `WARN sessions evicted`, `ERROR no_signing_key/db_tx`. Sin Access/Refresh plano.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_010_sessions_tokens.up.sql` (+ down):
  ```sql
  CREATE TABLE sessions (
    sid UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family UUID NOT NULL, jti_actual UUID NOT NULL, device_hash TEXT NOT NULL, ip_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+INTERVAL '90 days'
  );
  CREATE INDEX idx_sessions_user_seen ON sessions(user_id, last_seen);
  CREATE TABLE refresh_families (
    family UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    current_hash TEXT NOT NULL UNIQUE, parent_hash TEXT NOT NULL DEFAULT '',
    counter INT NOT NULL DEFAULT 0, absolute_exp TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE
  );
  CREATE TABLE refresh_hashes (hash TEXT PRIMARY KEY, family UUID NOT NULL REFERENCES refresh_families(family) ON DELETE CASCADE, counter INT NOT NULL, expires_at TIMESTAMPTZ NOT NULL);
  CREATE TABLE signing_keys (kid TEXT PRIMARY KEY, alg TEXT NOT NULL DEFAULT 'EdDSA', pub_b64 TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), retired_at TIMESTAMPTZ);
  INSERT INTO signing_keys(kid, pub_b64) VALUES ('2026-10-a','<ed25519-pub-b64>') ON CONFLICT DO NOTHING;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z';
  ```
  Down: `DROP TABLE ...; ALTER TABLE users DROP COLUMN tokens_valid_after;`. Redis `sess:*/fam:*/jti:*` (sin migración). Seed `kid` se reemplaza por clave real en deploy (este valor es placeholder documentado, se genera en T-08).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `tokens_test.go` (claims TTL 900s, `aud/iss`, `amr` exacto, `roles_ver`) + `issue_session_test.go` table-driven con fakes (Signer fake-kid, Refresh/Session fakes: crea family+sesión+outbox, 21ª evicta 1ª, PG-fail no entrega, RedisDown entrega vía PG). `ed25519_signer_test.go` (firma/verifica vector, `kid` header, sin key → error, nunca `none`). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/issue_smoke.js` (Issue directo 200 VUs vía login mock, p95 <200ms sin Argon2 — Issue puro — + e2e login→Issue p95 <600ms con Argon2); JWKS-mock verifica 10k JWT/s p95 <5ms offline; PG-down → 100% 500 sin huérfanos (0 `sessions` sin `refresh_hashes`); Redis-down → 200 vía PG + rehidrata. Gateway-mock (`valid_after`/denylist) rechaza viejos aunque firmen.
