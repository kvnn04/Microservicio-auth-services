# Plan de Implementación Técnica: CU-CRYP-01

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`jwks.go` — tipos puros).
* **Entidades / Value Objects:**
  ```go
  type JWK struct { Kty, Crv, X, Use, Kid, Alg string }
  func (k JWK) Validate() error // kty==OKP, crv==Ed25519, x 32B b64url, use==sig, kid non-empty, alg==EdDSA
  func ETagFor(keys []JWK) string // hex(sha256(canonical sorted kid DESC))
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/key_directory_ports.go
  type KeyDirectory interface {
    ActivePubs(ctx context.Context) ([]JWK, error) // memoria (recargable), orden kid DESC; ErrNoKeys
    Reload(ctx context.Context) error // desde signing_keys WHERE retired_at IS NULL
  }
  ```

### Capa de Aplicación (`internal/service/`)
* **Servicio:** Sin servicio nuevo. `internal/service/key_directory.go` (implementa `KeyDirectory`: cache memoria `atomic.Value` + `Reload` desde PG + `ETag` memoizado; suscrito a evento interno `keys.rotated` (canal/pub-sub) para reload <1s).
* **Flujo Orquestado:** arranque `Reload` (0 claves → `ErrNoKeys` + `/ready` degradado) → handlers leen memoria → `304` si ETag match → reload ante rotación (CRYP-02 lo invoca, no HTTP).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/jwks.go` (`GET /.well-known/jwks.json` → `200 {keys}` + `ETag`/`304` + `max-age=600`) + `openid_configuration.go` (`GET /.well-known/openid-configuration` → `200` doc + `max-age=3600`), sin auth, `GET` solo (`HEAD` permitido, otros `405`), rate `100/min/IP` (matriz SEC-02).
  * DTO `dto/jwks_dto.go`; `errors` (`JWKS_UNAVAILABLE→500`).
  * Rutas `cmd/api/main.go` (+ documentadas en `PUBLIC_BASE_URL` env para `jwks_uri`/`issuer` exactos).
* **Salida (Persistencia):**
  * Postgres: extiende `signing_keys` (010): `+ priv_ref TEXT (kms:...|env:...#kid), + retired_at, + created` (migración 029; NUNCA columna privada). `KeyDirectory.Reload` = `SELECT kid, pub_b64 WHERE retired_at IS NULL ORDER BY kid DESC`.
* **Salida (Mensajería):** sin Kafka aquí (rotaciones auditan en CRYP-02/03); pub/sub interno `keys.rotated` (canal Go + Redis `PUBLISH keys.rotated` multi-instancia) dispara `Reload`.
* **Salida (Seguridad):** `security/jwk.go` (parse `pub_b64→x`, validación 32B, canonical JSON para ETag) + scanner `scripts/jwks_priv_scan.sh` + test `TestJWKSNoPrivateMaterial`.

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `jwks_requests_total{result,endpoint}` + `jwks_keys_count` + `jwks_reload_total{reason=startup|rotate|retire|manual}`.
* **Tracing (OpenTelemetry):** Sin span por request (hot); span en `Reload` + `http.server` base.
* **Logs Estructurados:** `pkg/logger`: `INFO jwks reload (kids,count)`, `WARN no_keys`, `ERROR reload_fail`. Sin material (solo `kid`s).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_029_signing_keys_extend.up.sql` (+ down):
  ```sql
  ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS priv_ref TEXT NOT NULL DEFAULT 'env:SESSION_SIGNING_KEY';
  ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;
  ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS alg TEXT NOT NULL DEFAULT 'EdDSA';
  -- backfill kid actual si 010 lo dejó placeholder: UPDATE ... (documentado, no dato sensible: solo pub)
  ```
  Down: `ALTER TABLE ... DROP COLUMN ...;`. Sin tabla nueva. mmdb no aplica.

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `jwks_test.go` (Validate OKP/32B/kid, ETag estable+orden, 304-match) + `key_directory_test.go` (Reload orden, 0 claves→ErrNoKeys, reload-tras-rotate <1s fake-pubsub) + `TestJWKSNoPrivateMaterial` (bodies ejemplo + fuzz 100 rotates sin `d`) + scanner sh en CI. `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/jwks_smoke.js`: 200 VUs `GET /jwks.json` (p95 <20ms memoria, `ETag`/`304` 2ª vuelta 100%, 0 `500`), flood 120/min→101º `429`, rotación simulada (nueva kid → ETag cambia + viejos verifican con set previo + nuevos con refetch — ejemplo SDK corre en CI como test de integración, no k6).
