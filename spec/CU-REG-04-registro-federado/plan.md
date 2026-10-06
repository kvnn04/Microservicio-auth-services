# Plan de Implementación Técnica: CU-REG-04

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (federación) + `internal/domain/user/` (identidad vinculada).
* **Entidades / Value Objects:**
  * `internal/domain/user/federated_identity.go`:
    ```go
    type Provider string // ProviderGoogle ("google"), extensible
    type FederatedIdentity struct { Provider Provider; Sub string; UserID string; EmailAtLink string; Iss string; CreatedAt time.Time }
    func NewFederatedIdentity(p Provider, sub, userID, email string) (*FederatedIdentity, error) // sub 1..255 sin control, email normalizado válido
    ```
  * `internal/domain/auth/federated.go`:
    ```go
    const StateBytes=32; const NonceBytes=32; const VerifierBytes=64; const StateTTL=10*time.Minute
    type OIDClaims struct { Sub, Email string; EmailVerified *bool; Nonce, Iss, Aud string; Exp, Iat int64 }
    func (c *OIDClaims) IsVerified() bool // == true estricto
    ```
* **Puertos de Salida (Interfaces del Dominio):**
  ```go
  // internal/domain/auth/identity_provider.go
  type AuthURL struct { URL string; State, Nonce string }
  type TokenSet struct { IDToken string; AccessToken string } // AccessToken solo memoria request
  type IdentityProviderClient interface {
    BuildAuthorizeURL(ctx context.Context, req AuthorizeReq) (AuthURL, Verifier string, err error) // req{Provider, RedirectURI, Scopes}
    ExchangeCode(ctx context.Context, provider Provider, code, verifier, redirectURI string) (TokenSet, error) // ErrInvalidCode | ErrIDPUnavailable
    VerifyIDToken(ctx context.Context, provider Provider, idToken, expectedNonce string) (OIDClaims, error) // ErrInvalidToken (firma/claims/nonce)
  }
  // internal/domain/user/federated_repository.go
  type FederatedRepository interface {
    FindByProviderSub(ctx context.Context, p Provider, sub string) (*FederatedIdentity, *User, error) // ErrNotFound
    FindUserByEmailNormalized(ctx context.Context, email string) (*User, error)
    CreateUserWithFederation(ctx context.Context, u *User, f *FederatedIdentity, outbox []shared.OutboxEvent) error // Tx + UNIQUE(provider,sub) + UNIQUE(email)
  }
  type FederatedStateStore interface {
    SaveState(ctx context.Context, state, nonce, verifier, ipHash, returnTo string) error // EX 600 NX
    ConsumeState(ctx context.Context, state string) (nonce, verifier, ipHash, returnTo string, err error) // GET+DEL atómico, ErrNotFound=>invalid_state
  }
  ```
  Reuso: `shared.EventPublisher/OutboxStore/AuditLogger`, `user.User` (+`Activate()` CU-REG-02, `password_algo='federated'`, `password_hash=''`).

### Capa de Aplicación (`internal/service/`)
* **Servicio / Caso de Uso:** `internal/service/register_federated.go`
  * `type RegisterFederatedService struct { IdPs auth.IdentityProviderClient; Fed user.FederatedRepository; Users user.UserRepository; States auth.FederatedStateStore; Outbox shared.OutboxStore; Metrics/Tracer }`
  * `Authorize(provider, returnTo, ip) → AuthURL` (genera state/nonce/verifier CSPRNG, `States.SaveState`, delega URL al adapter).
  * `Callback(provider, code, state, ip) → Output{Status: active|pending|linked_login, Collision bool}`:
    1. `States.ConsumeState(state)` (una vez; miss → `ErrInvalidState`, fail-closed).
    2. `IdPs.ExchangeCode` (timeout 5s+1retry en adapter; `ErrInvalidCode→400`, `ErrIDPUnavailable→502`, sin DB aún).
    3. `IdPs.VerifyIDToken(idToken, nonce)` (firma+claims+nonce ConstantTime; fail → `ErrInvalidToken→401`).
    4. Normaliza email (VO CU-REG-01; malformado → `ErrInvalidEmail`).
    5. `Fed.FindByProviderSub` hit → login (verifica `users.status`, retorna linked_login/active/pending, sin crear).
    6. Miss → `Fed.FindUserByEmailNormalized`: si hit (distinto sub) → `ErrLinkRequired` + encola `security.federated_collision` (throttle 1/h, reuso CU-REG-03) + audit; si miss → `IsVerified()? ACTIVE+sesión : PENDING+OTP`, `CreateUserWithFederation` Tx (carrera UNIQUE → trata como hit/colisión según constraint violado).
    7. Idempotencia `X-Request-ID` 24h + métrica/audit (con `sub_hash`, sin tokens).
* **Flujo de Ejecución Orquestado:** state-first (seguridad) → canje → verificación JWT → lookups → Tx crea o 409. Nunca crea antes de validar firma. Sesión delegada a `service/issue_session.go` (CU-AUTH-04, inyectado como puerto, no import directo).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers: `internal/adapter/http/handlers/federated_authorize.go` (`GET /api/v1/auth/federated/:provider/authorize?return_to=` → `302` + `Set-Cookie: fed_state=<state>; HttpOnly; Secure; SameSite=Lax; Max-Age=600`) y `federated_callback.go` (`GET /:provider/callback?code=&state=` → JSON `200/400/401/404/409/502`, `Cache-Control: no-store`, borra cookie). DTO `dto/federated_dto.go` (`AuthorizeResponse{url}`, `CallbackResponse{status,message}`, errores `INVALID_FEDERATED_STATE|INVALID_FEDERATED_CODE|INVALID_ID_TOKEN|ACCOUNT_LINK_REQUIRED|IDP_UNAVAILABLE|PROVIDER_NOT_SUPPORTED`).
  * Middleware: reuso `rate_limit` (+buckets `fed_authz:ip 20/min`, `fed_cb:ip 10/min`, `fed_cb:state 5/min`), `request_id`, `recover`; `provider_allowlist.go` (`404` si provider ∉ config).
  * Errors: `errors/map.go` (+mapeos 400/401/404/409/502 federados, `409` solo aquí permitido).
  * Rutas `cmd/api/main.go`: `GET /api/v1/auth/federated/:provider/authorize`, `GET /:provider/callback`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/federated_repository.go` (pgxpool, Tx `CreateUserWithFederation`: `INSERT users(status bifurcado, password_algo='federated') + INSERT federated_identities + INSERT outbox`; `UNIQUE(provider,sub)`, `UNIQUE(email_normalized)`; `FindByProviderSub` JOIN users).
  * Redis: `persistencia/redis/federated_state_store.go` (`SET fed:state:<state> {nonce,verifier,ip,return} NX EX 600`, Lua `GET+DEL` atómico en `ConsumeState`; `fed:notify:<email_hash>` throttle reuso CU-REG-03).
* **Salida (Mensajería):** reuso `colas/kafka/user_producer.go` + tipos `federated.registered`, `user.activated` (si ACTIVE), `verification_requested` (si PENDING→CU-REG-02), `security.federated_collision`, `audit`. Worker SMTP plantillas federadas (bienvenida vs colisión).
* **Salida (Identidad externa):** `internal/adapter/identity/google_oidc_client.go` (nuevo, `golang.org/x/oauth2 + go-oidc`-style mínimo o `net/http` + `lestrrat-go/jwx` a elegir en T-08; OIDC discovery `https://accounts.google.com/.well-known/openid-configuration` cache 24h, JWKS `oauth2/v3/certs` cache 1h/10min-rotación, `http.Client{Timeout:5s}` + 1 retry, allowlist `alg RS256/ES256`, validación `iss/aud/exp/iat/nonce` estricta). `client_secret` desde env/HSM, nunca log. Interfaz permite mocks + fake-IdP en tests (httptest con JWKS propia).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `federated_registration_total{provider,result}` (active, pending, linked_login, link_required, cancelled, invalid_state, invalid_token, idp_unavailable, rate_limited, error), `federated_idp_latency_seconds{op=token|jwks|discovery}`, `federated_collisions_total{provider}`, `jwks_cache_hits_total{hit}`. Vía `MetricsPort` en servicio + middleware cuenta `429`.
* **Tracing (OpenTelemetry):** Raíz `UseCase.RegisterFederated` con hijos `oauth.build_authorize`, `fed.state.consume`, `oauth.exchange_code`, `jwks.fetch|cache`, `jwt.verify`, `db.federated.lookup`, `db.user.insert+link`, `outbox.insert`, `kafka.produce` (worker). Atributos `provider, email_verified, email.domain`; secretos nunca.
* **Logs Estructurados:** `pkg/logger` slog: `INFO federated authorize/callback result` (con `provider, result, sub_hash`), `WARN link_required/invalid_state/cancelled/idp_retry`, `ERROR idp_unavailable/db_tx` (con `op`, sin cuerpo IdP). Prohibido `code/state/verifier/nonce/id_token/access_token/email` en prod.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_004_federated_identities.up.sql` (+ down):
  ```sql
  CREATE TABLE federated_identities (
    provider TEXT NOT NULL CHECK (provider IN ('google')),
    sub TEXT NOT NULL CHECK (char_length(sub) BETWEEN 1 AND 255),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_at_link CITEXT NOT NULL, iss TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, sub)
  );
  CREATE INDEX idx_fed_user ON federated_identities(user_id);
  ALTER TABLE users ADD COLUMN IF NOT EXISTS federated_only BOOLEAN NOT NULL DEFAULT FALSE;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_source TEXT; -- 'classic' | 'federated_google'
  -- users.password_hash nullable para federados (si era NOT NULL, relaja):
  -- ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
  ```
  Down: `DROP TABLE federated_identities; ALTER TABLE users DROP COLUMN ...;`. Redis claves `fed:state:<statehex> EX 600`, `fed:notify:*` (reuso throttle). Documenta CHECK ampliable (`IN ('google','apple',...)`) en deltas futuros.

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** Dominio `federated_identity_test.go` (sub vacío/largo, provider inválido), `oidclaims_test.go` (verified estricto true vs "true"/null). Servicio `register_federated_test.go` table-driven con fakes (`FakeIdP`: firma OK/mala, nonce OK/mismatch, verified true/false; `FakeFedRepo`; `FakeStateStore`): verified→active+sesión, no-verified→pending+OTP, colisión→409+notify sin crear, replay state→400, `kid` miss→401, carrera UNIQUE(provider,sub)→login. `go test -race` verde, cobertura ≥85% dominio+servicio.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/federated_smoke.js` contra fake-IdP local (no Google real): 50 VUs 3min authorize+callback; SLO p95 <400ms (sin IdP real) / <1200ms (con IdP mock 200ms), p99 <800/<2000, `idp_unavailable` inyectado (mock 5xx 30s) → 100% `502` sin crear filas + recupera sin duplicados (UNIQUE). Chaos JWKS-rotación (mock cambia `kid`) → 1 refresh y sigue `200`; Redis-down en callback → `500` fail-closed medido (único caso fail-closed documentado).
