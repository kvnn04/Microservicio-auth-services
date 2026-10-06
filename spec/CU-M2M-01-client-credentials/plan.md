# Plan de Implementación Técnica: CU-M2M-01

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`m2m.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    M2MSecretBytes=32; M2MTTL=5*time.Minute
    M2MMaxFails=10; M2MFailWindow=15*time.Minute; M2MSuspend=15*time.Minute
    M2MRotateOverlap=24*time.Hour
  )
  type M2MClient struct { ID string; SecretHash, PrevHash string; Scopes, CIDRs []string; Status string; SuspendedUntil time.Time }
  func (c M2MClient) AllowsScope(req []string) (grant []string, err error) // req ⊆ granted (vacío→default mínimo)
  func (c M2MClient) AllowsIP(ip string) bool // cidrs vacías=any
  func NewClientID(slug string) (string, error) // svc_+slug validado
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/m2m_ports.go
  type M2MClientStore interface {
    CreateTx(ctx context.Context, c *M2MClient, secretPlain string) error // hash fuera (servicio hashea), outbox; ErrExists
    FindForAuth(ctx context.Context, id string) (*M2MClient, error) // ErrNotFound→opaco
    VerifySecret(secretPlain, hash, prevHash, pepper string) (current, rotated bool) // ConstantTime ambas
    RotateTx(ctx context.Context, id, newHash string) error // prev=old 24h + outbox
    SuspendTx(ctx context.Context, id string) error // + outbox+email flag
    Unlock(ctx context.Context, id string) error // admin
  }
  ```
  Reuso `AccessSigner` (JWT `aud` target), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/m2m_provision.go` (Create/Rotate/Unlock, admin) + `m2m_token.go` (Token)
  * `Provision(adminID, slug, scopes, cidrs)`: valida admin (el handler ya autorizó; el servicio re-chequea rol via `RoleStore` para no confiar solo en middleware) → `NewClientID` → `CSPRNG 32B` → `Hash(pepper)` → `CreateTx` + `Output{id, secret 1 vez}`.
  * `Token(id, secret, scopeReq, audReq, ip)`: forma (`grant_type`, `aud ∈ allowlist`, scope parse; malforma → `ErrInvalidRequest/Scope`) → rate (`m2m:token`) → `FindForAuth` (miss → dummy+delay + `ErrInvalidClient`) → `status` (suspendido → `ErrInvalidClient` opaco) → `VerifySecret` (+prev-solape → `rotating=true`) → fails/suspend (`RecordFail`→10º `SuspendTx`+email) → `CIDR` (deny → `ErrInvalidClient`) → `AllowsScope` (fuera → `ErrInvalidScope` con details, SOLO tras secreto OK) → `AccessSigner.Sign(M2MClaims{sub,azp,scope,aud,exp 300,client:true})` → `Output{token}` (sin sesión/family/cookie).
* **Flujo Orquestado:** valida-admin/provision→hash→Tx→1vez; auth→rate→lookup→status→verify→fails→cidr→scope→sign→200. Idempotencia: provision mismo RequestID no duplica (`client_id` determinista por slug → `ON CONFLICT` → `409 CLIENT_EXISTS`); token no idempotente (cada llamada nuevo `jti`, 5min).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/m2m_provision.go` (`POST /admin/m2m/clients` + `POST /:id/rotate|/unlock`, auth-admin `admin+m2m` (nuevo scope admin `admin:m2m`, añadido a matriz SEC-06 como extensión) → `201/200`) + `handlers/m2m_token.go` (`POST /oauth2/token` form-urlencoded → `200/400/401/429`, lee Basic-primero-body-fallback, `no-store`, enmascara `Authorization` en access-log).
  * DTO `dto/m2m_dto.go`; middleware `require_roles(admin)` en provision + rate (`admin:m2m 20/min`, `m2m:token:ip 30/min, :client 10/min`); `errors/map` (+`INVALID_CLIENT→401` opaco, `INVALID_SCOPE→400`, `CLIENT_EXISTS→409`, `CIDR` como `INVALID_CLIENT`).
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/admin/m2m/clients|/:id/rotate|/:id/unlock`, `POST /api/v1/auth/oauth2/token`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/m2m_store.go` (`m2m_clients(client_id PK svc_*, secret_hash UNIQUE, prev_hash, prev_exp, scopes JSONB, cidrs JSONB, status, suspended_until, created_by, created_at)`, `CreateTx` + `RotateTx(prev 24h)` + `SuspendTx/Unlock` + outbox misma Tx).
  * Redis: `persistencia/redis/m2m_tracker.go` (`m2m:fails:<id> INCR EX 900`, `m2m:suspend:<id>` espejo rápido (verdad PG, Redis fast-reject) + rate buckets; down → PG + fail-open local + `WARN`).
* **Salida (Mensajería):** `kafka` (`m2m.client_created|rotated|token_issued|suspended` + audit `m2m.*`); worker SMTP técnico (`suspend`, `rotated`) al `tech_email` del cliente (provision lo exige).
* **Salida (Seguridad):** `security/m2m_secret.go` (`CSPRNG 32B` + `SHA-256+pepper(M2M_PEPPER||PASSWORD_PEPPER)` + `ConstantTime`, dummy-hash si miss) + reuso `ed25519_signer` (M2M `aud`, `kid` actual) + `cidr.Contains` (`net/netip`).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `m2m_token_total{result,aud}` + `m2m_issue_duration_seconds` + `m2m_suspend_total` + `m2m_rotating_use_total` + `m2m_redis_fallback_total`.
* **Tracing (OpenTelemetry):** Raíces `UseCase.M2MProvision/Token` (hijos `auth.admin_check`, `ratelimit`, `db.client.*`, `crypto.compare`, `cidr.check`, `scope.check`, `crypto.sign`, `outbox.insert`). Atributos `client_id, aud`, nunca secreto.
* **Logs Estructurados:** `pkg/logger`: `INFO m2m provision/token/rotate/unlock/suspend` (con `client_id`), `WARN invalid/scope/cidr/rate/fallback`, `ERROR db/nokey`. Sin `secret/Basic` (enmascarado access-log).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_027_m2m_clients.up.sql` (+ down):
  ```sql
  CREATE TABLE m2m_clients (
    client_id TEXT PRIMARY KEY CHECK (client_id ~ '^svc_[a-z0-9-]{3,32}$'),
    secret_hash TEXT NOT NULL UNIQUE, prev_hash TEXT, prev_exp TIMESTAMPTZ,
    scopes JSONB NOT NULL DEFAULT '[]', cidrs JSONB NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    suspended_until TIMESTAMPTZ, tech_email CITEXT NOT NULL, description TEXT NOT NULL,
    created_by UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  -- admin scope nuevo (extiende matriz SEC-06 sin migrala: el catálogo vive en role_catalog):
  INSERT INTO role_catalog(role, scopes) VALUES ('admin', '["*","admin:roles","admin:m2m"]')
   ON CONFLICT (role) DO UPDATE SET scopes='["*","admin:roles","admin:m2m"]';
  ```
  Down: `DROP TABLE m2m_clients;` (+ revert `role_catalog` admin a sin `admin:m2m` — documentado). Redis `m2m:*` (efímeros). Seed primer cliente por migración? No: por endpoint admin/seed (el seed admin humano de SEC-06 lo crea).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `m2m_test.go` (NewClientID prefijo, AllowsScope subset/vacío-default, AllowsIP CIDR/vacía, VerifySecret current/prev/mala) + servicio table-driven con fakes (provision 1-vez + hash-only, token ok subset, scope-fuera 400 solo-con-secreto-ok, miss/suspend/cidr 401 idénticos + delay, 10º suspend + unlock, prev-solape Warning, rate 429). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/m2m_smoke.js`: 100 VUs token (p95 <100ms sin Argon2 — SHA rápido, PG+Redis sanos), 4×401 idénticos p50±25ms, 10-fails→suspend (bueno también 401) + unlock→200, scope/aud 400s, flood→429, Redis-down (PG verdad), PG-down (500 0 tokens), KMS-down (500 0 none). Satélite-mock valida `aud/scope/5min` y rechaza humano (`client:true` ausente) y viceversa.
