# Plan de Implementación Técnica: CU-M2M-02

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`api_keys.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    APIKeyPrefixLen=8; APIKeySecretBytes=32; APIKeyDefaultTTL=90*24*time.Hour; APIKeyMaxTTL=365*24*time.Hour
    APIKeyOverlap=24*time.Hour; APIKeyUseRate=1000 // /min
  )
  type APIKey struct { Prefix, SecretHash, Owner, Name string; Scopes, CIDRs []string; Exp time.Time; Revoked, Superseded bool; Lineage, PrevPrefix string }
  func NewAPIKey(env string) (prefix, secretPlain, full string, err error) // ak_live|test_<8>.<43>
  func ParseAPIKey(raw string) (prefix, secret string, err error) // regex + split
  func (k APIKey) CanUse(now time.Time, ip string, needScope string) error // exp/revoked/cidr/scope
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/apikey_ports.go
  type APIKeyStore interface {
    CreateTx(ctx context.Context, k *APIKey) error // INSERT + outbox; ErrNameTaken|UnknownScope
    FindByPrefix(ctx context.Context, prefix string) (*APIKey, error) // ErrNotFound→401 opaco
    VerifySecret(secretPlain, hash, pepper string) bool // ConstantTime
    RotateTx(ctx context.Context, owner, prefix string) (*APIKey, string, error) // nueva + vieja superseded_until + outbox; ErrNotFound
    RevokeTx(ctx context.Context, owner, prefix string) error // revoked + outbox; ErrNotFound→404 si no propia
    List(ctx context.Context, owner string) ([]APIKey, error) // sin secreto
    Touch(ctx context.Context, prefix string) error // last_used eventual (debounce fuera)
  }
  ```
  Reuso `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/api_keys.go` (Create/Rotate/Revoke/List) + `verify_api_key.go` (gateway-side, usado por middleware propio y documentado para satélites)
  * `Create(owner, name, scopes, cidrs, exp, stepUpOK)`: Step-Up verificado fuera (middleware `require_step_up(apikeys:write)`) + `scopes ⊆ propios` (inyecta `RoleStore.List(owner)` para transitividad; si no → `ErrDelegationDenied`) + `NewAPIKey` + `CreateTx` → `Output{full 1 vez}`.
  * `Verify(raw, ip, needScope)`: `Parse` (malforma → `ErrInvalid`) → rate `1000/min/prefix` → `FindByPrefix` (miss → dummy+`ErrInvalid`) → `exp/revoked/suspend` → `VerifySecret` (falla → fails→suspend + `ErrInvalid`) → `CIDR` (deny → `ErrInvalid` opaco) → `scope` (falta → `ErrInsufficient` con details) → `Touch` (debounce) → `Output{owner, scopes}`.
  * `Rotate`: crea sucesora (hereda, `exp` nueva default, `lineage`, `prev`) + vieja `superseded_until=+24h` + outbox ambas → `Output{nueva 1 vez}`. `Revoke`: `RevokeTx` + pub + outbox → `Output{revoked}`.
* **Flujo Orquestado:** Step-Up→validar→rate→Tx→1vez→200/201; uso→parse→rate→lookup→exp/revoked→verify→fails→cidr→scope→touch→ok. Idempotencia: create mismo RequestID+name → `409` (no duplica por `UNIQUE(owner,name)`); verify no idempotente (cada uso cuenta rate/touch).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/api_keys.go` (`POST /api-keys` + `GET /api-keys` + `POST /:prefix/rotate` + `DELETE /:prefix`, auth-owner + Step-Up `apikeys:write` en mutaciones → `201/200/400/403/404/409/429`) + `middleware/require_api_key.go` (gateway interno: `X-API-Key|ApiKey` → `Verify` → inyecta `apikey{owner,scopes}` en ctx o `401/403/429`; documentado para satélites como referencia).
  * DTO `dto/apikey_dto.go`; `errors/map` (+`KEY_NAME_TAKEN→409`, `DELEGATION_DENIED→403`, `INSUFFICIENT_SCOPE→403`, `EXPIRED_API_KEY→401`, `INVALID_API_KEY→401` opaco).
  * Rutas `cmd/api/main.go`: 4 gestión + middleware verify registrable por ruta protegida-key.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/apikey_store.go` (`api_keys(prefix PK, secret_hash UNIQUE, owner FK, name, scopes/cidrs JSONB, exp, revoked, superseded_until, lineage, prev_prefix, last_used, created_at)`, `UNIQUE(owner,name)`, `CreateTx` + `RotateTx` + `RevokeTx` + outbox misma Tx + `Touch` (`UPDATE last_used` con debounce llamado desde Redis-gate)).
  * Redis: `persistencia/redis/apikey_cache.go` (`SET ak:<prefix> {hash,scopes,exp,revoked,owner} EX 300` + `DEL` en revoke/rotate + `PUBLISH apikey.revoked` + `INCR ak:use:<prefix>` sliding 1000/min + `ak:touch:<prefix> EX 300` debounce + `ak:fails:<prefix>` suspend 10/15min (paralelo M2M-01); down → PG + fail-closed uso (sin cache ni PG-hit → `500`)).
* **Salida (Mensajería):** `kafka` (`apikey.created|rotated|revoked|suspended|used_expired` + audit `apikey.*` con usos-ok 10%) + pub/sub Redis `apikey.revoked` (~1s); worker sin SMTP propio salvo `suspend` al owner (email técnico) + `rotated`.
* **Salida (Seguridad):** `security/apikey_secret.go` (`CSPRNG 8+32B` + `base62/base64url` + `SHA-256+pepper(APIKEY_PEPPER||M2M_PEPPER)` + `ConstantTime` + dummy) + regex pública en contracts para scanners + `access-log` mask `X-API-Key`.

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `apikey_total{op,result}` + `apikey_use_total{result}` (ok 10% + fallos 100%) + `apikey_suspend_total` + `apikey_redis_fallback_total` + `apikey_expired_total`.
* **Tracing (OpenTelemetry):** Raíces `UseCase.ApiKey*` + `Gateway.VerifyApiKey` (hijos `stepup.check`, `ratelimit`, `db.key.*`, `crypto.compare`, `cidr/scope.check`, `touch`, `outbox.insert`). Atributos `prefix` (público, nunca secreto).
* **Logs Estructurados:** `pkg/logger`: `INFO apikey create/rotate/revoke/use-ok(10%)` (con `prefix,owner`), `WARN invalid/expired/insufficient/suspend/rate/fallback`, `ERROR db`. Sin `secreto/full` (solo `prefix`).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_028_api_keys.up.sql` (+ down):
  ```sql
  CREATE TABLE api_keys (
    prefix TEXT PRIMARY KEY CHECK (prefix ~ '^ak_(live|test)_[A-Za-z0-9]{8}$'),
    secret_hash TEXT NOT NULL UNIQUE, owner UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, scopes JSONB NOT NULL DEFAULT '[]', cidrs JSONB NOT NULL DEFAULT '[]',
    exp TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE,
    superseded_until TIMESTAMPTZ, lineage UUID NOT NULL, prev_prefix TEXT,
    last_used TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner, name)
  );
  CREATE INDEX idx_apikey_owner ON api_keys(owner) WHERE NOT revoked;
  CREATE INDEX idx_apikey_lineage ON api_keys(lineage);
  -- scope admin nuevo (11º, extiende SEC-06 sin migrala de más):
  INSERT INTO role_catalog(role, scopes) VALUES ('admin', '["*","admin:roles","admin:m2m"]')
   ON CONFLICT (role) DO UPDATE SET scopes='["*","admin:roles","admin:m2m"]';
  -- NOTA: apikeys:write se chequea como scope sintético en middleware (sin columna nueva): el servicio exige 'admin' + (scope admin:m2m O apikeys:write-equivalente). Documentado en código.
  ```
  Down: `DROP TABLE api_keys;` (+ revert admin scopes — documentado). Redis `ak:*` (cache 300s + pub).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `api_keys_test.go` (New/Parse/regex, CanUse exp/revoked/cidr/scope, solape) + servicio table-driven con fakes (create-1vez+hash-only+transitividad-denied, uso ok 403-scope/401-exp/401-opaco, rotate-solape ambas + auto-revoke 24h fake-clock, revoke inmediato + lista sin secreto, fails→suspend). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/apikey_smoke.js`: 200 VUs uso (p95 <50ms Redis-hit / <150ms PG, cache-hit >95%) + flood 1100/min→1001º 429 + suspend 10-malos + rotate-solape + revoke-pub/sub ≤1s medido + PG-down (hit→200, miss→500 fail-closed) + Redis-down (PG verdad). Scanner-regex test en CI (fixture leak → rojo).
