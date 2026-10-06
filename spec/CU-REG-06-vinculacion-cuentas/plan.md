# Plan de Implementación Técnica: CU-REG-06

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/user/` (vínculos) + `internal/domain/auth/` (step-up mínimo + estados link).
* **Entidades / Value Objects:** Reuso `FederatedIdentity`, `OIDClaims`, `User` (CU-REG-04/01) + nuevo:
  ```go
  // internal/domain/user/link_policy.go
  const MaxLinkedProviders=5; const StepUpMaxAge=5*time.Minute
  func CountFactors(hasPassword bool, federated int) int
  func CanUnlink(hasPassword bool, federated int, target Provider) (bool, string) // false+LAST_AUTH_FACTOR si quedarían 0
  func RequireFreshAuth(authTime time.Time, now time.Time) error // ErrStepUpRequired si >5min o cero
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/user/federated_link.go (extiende FederatedRepository CU-REG-04)
  type FederatedLinkStore interface {
    FederatedRepository // FindByProviderSub, CreateUserWithFederation (reuso)
    LinkTx(ctx context.Context, f *FederatedIdentity) error // INSERT + UNIQUE(provider,sub)+UNIQUE(provider,user_id) + outbox; ErrAlreadyLinkedSelf | ErrProviderTaken | ErrCollisionForeign
    UnlinkTx(ctx context.Context, userID string, p Provider) (bool, error) // DELETE + outbox; false si no existía
    ListByUser(ctx context.Context, userID string) ([]FederatedIdentity, bool hasPassword, error)
  }
  type LinkStateStore interface {
    SaveLinkState(ctx context.Context, state, userID, nonce, verifier, ipHash string) error // EX 600 NX
    ConsumeLinkState(ctx context.Context, state string) (userID, nonce, verifier string, err error) // GET+DEL, ErrNotFound
  }
  ```
  `auth.IdentityProviderClient` y `FederatedStateStore`-anónimo se reutilizan (el cliente OIDC no distingue link vs registro; el servicio elige redirect `.../link/callback`).

### Capa de Aplicación (`internal/service/`)
* **Servicio / Caso de Uso:** `internal/service/link_federated.go` + `unlink_federated.go` (+ `list_linked.go` lectura)
  * `LinkInitiate(userID, provider, ip, passwordOpt?) → {URL, State}`: `RequireFreshAuth` (+ `Hasher.Verify` si `hasPassword`, `ErrStepUp` genérico) → genera state/nonce/verifier → `SaveLinkState` → `IdPs.BuildAuthorizeURL(linkCallbackURI)`.
  * `LinkCallback(callerUserID, state, code)`:
    1. `ConsumeLinkState(state)` (miss → `ErrInvalidState`); exige `boundUserID==callerUserID` (mismatch → `ErrInvalidState` + audit fijación).
    2. `ExchangeCode` + `VerifyIDToken(nonce)` (igual CU-REG-04: `400/401/502`).
    3. `LinkTx(FederatedIdentity{provider,sub,callerUserID})`: `miss→INSERT ok`; `UNIQUE(provider,sub)` con mismo user → `already_linked`; con otro user → `ErrCollisionForeign`; `UNIQUE(provider,user_id)` distinto sub → `ErrProviderTaken`.
    4. Idempotencia RequestID 24h + métrica/audit.
  * `Unlink(userID, provider, passwordOpt?)`: `RequireFreshAuth` (+password si tiene) → `ListByUser` → `CanUnlink` (si no → `ErrLastFactor`) → `UnlinkTx` (si false → `ErrNotLinked`) + email aviso (siempre, sin throttle).
  * `List(userID)` sin Step-Up (solo Bearer válido).
* **Flujo de Ejecución Orquestado:** auth+ Step-Up primero (sin tocar IdP/Redis de más) → state/lookup → canje JWT → Tx link/unlink → outbox. Nunca canjea sin `user-match`, nunca borra sin `CanUnlink`.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers: `handlers/federated_link_initiate.go` (`POST /:provider/link {current_password?}` auth → `200 {url,state,expires_in}`), `federated_link_callback.go` (`GET /:provider/link/callback?code=&state=` auth → `200 linked/already_linked` o `400/401/404/409/502`), `federated_unlink.go` (`DELETE /:provider [+body] / POST /:provider/unlink` auth+Step-Up → `200 unlinked` o `400/404`), `federated_linked_list.go` (`GET /linked` auth → `200 []`).
  * DTO `dto/federated_link_dto.go` (requests/responses/errores `STEP_UP_REQUIRED, INVALID_STEP_UP, INVALID_LINK_STATE, FEDERATED_ALREADY_LINKED, PROVIDER_ALREADY_LINKED, LAST_AUTH_FACTOR, FEDERATED_NOT_LINKED, LINK_STATE_UNAVAILABLE`).
  * Middleware: `require_auth.go` (Bearer → `user_id, auth_time`) + `require_fresh_auth.go` (`≤300s` o `401 STEP_UP_REQUIRED`) aplicado a initiate/callback/unlink (no a list) + reuso rate-limit (`link:initiate 10/h/user`, `callback 10/min/IP`, `unlink 10/h/user`, `linked 60/min/user`) + `provider_allowlist`.
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/federated/:provider/link`, `GET //link/callback`, `DELETE //:provider`, `POST //:provider/unlink`, `GET /api/v1/auth/federated/linked`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/federated_link_store.go` (`LinkTx`: `INSERT ... ON CONFLICT DO NOTHING RETURNING` + mapea constraint violado a `already/self/collision/taken`; `UnlinkTx`: `DELETE ... RETURNING`; `ListByUser`: `SELECT federated + users(password_hash IS NOT NULL)`; migraciones: `006_link_unique_provider_user` añade `UNIQUE(provider,user_id)` si 004 no lo trajo).
  * Redis: `persistencia/redis/federated_link_state.go` (`SET fed:link:<state> NX EX 600`, Lua `GET+DEL`; caído → `ErrLinkStateUnavailable→500` fail-closed).
* **Salida (Mensajería/Identidad):** reuso `colas/kafka` (`federated.linked/unlinked/link_collision` + audit) + `identity/google_oidc_client.go` con `redirect_uri` link-callback (mismo cliente, distinto callback registrado en Google console). Worker emails link/colisión/unlink-aviso (sin tokens).
* **Salida (Seguridad):** reuso `argon2_hasher.Verify` (ConstantTime) para `current_password`; contadores `link:passwd_fail:<user>` 3/15min → `429` (reuso CU-SEC-01 futuro).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `federated_link_total{provider,op,result}` (initiate, link ok/already/collision/taken, unlink ok/last_factor/not_linked, list, step_up_required, idp_unavailable, rate_limited), `unlink_last_factor_blocked_total`, `link_state_failures_total{reason}`. Vía MetricsPort + middleware.
* **Tracing (OpenTelemetry):** Raíces `UseCase.LinkFederatedInitiate/Callback`, `UseCase.UnlinkFederated` (hijos `auth.stepup.check (+crypto.verify?)`, `fed.linkstate.save|consume`, `oauth.exchange`, `jwt.verify`, `db.federated.link|unlink`, `outbox.insert`). Atributos `provider`, nunca secretos/sub plano.
* **Logs Estructurados:** `pkg/logger`: `INFO link initiate/callback ok, unlink ok, list` (con `provider, sub_hash`), `WARN collision/taken/last_factor/step_up/invalid_state`, `ERROR idp/db/linkstate`. Sin `code/sub/token/password`.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_006_link_constraints.up.sql` (+ down):
  ```sql
  CREATE UNIQUE INDEX IF NOT EXISTS uq_fed_provider_user ON federated_identities(provider, user_id);
  -- (PK(provider,sub) e idx_fed_user ya existen desde 004)
  ```
  Down: `DROP INDEX IF EXISTS uq_fed_provider_user;`. Sin tablas nuevas. Redis `fed:link:<statehex> EX 600` (+ `fed_state`-cookie opcional `fed_link_state`).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `link_policy_test.go` (CountFactors/CanUnlink matriz, RequireFreshAuth 5min borde), servicio `link_federated_test.go` table-driven con fakes (initiate stale→401, password mala→401, callback user-mismatch→400, sub libre→linked, self→already, ajeno→409+notify ambas, provider-taken→400, unlink último→400, unlink ok→email, list enmascara). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/link_smoke.js` vs fake-IdP: 30 VUs initiate+callback link (p95 <500ms), 10 VUs unlink/list; colisión concurrente (2 users mismo sub → 1×200 + 1×409 determinista por `PK`); replay callback (state consumido → `400`); Redis-down → `500 LINK_STATE_UNAVAILABLE` medido; IdP-5xx → `502` sin filas. Chaos stale-session (auth_time 30min) → 100% `401 STEP_UP_REQUIRED` en initiate/unlink.
