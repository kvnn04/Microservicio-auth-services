# Plan de Implementación Técnica: CU-SEC-06

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`rbac.go`).
* **Entidades / Value Objects:**
  ```go
  type Role string // RoleUser ("user"), RoleAdmin ("admin"), RoleSupport ("support_readonly")
  const ScopesVer=1
  func (r Role) Valid() bool
  func ResolveScopes(roles []Role) (scopes []string, ver int) // catálogo: user→[read:me,write:me], support→[+read:users:support], admin→[* inc admin:roles]
  func IsLastAdmin(targetRoles []Role, remove []Role, allAdmins int) bool
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/rbac_ports.go
  type RoleStore interface {
    List(ctx context.Context, userID string) ([]Role, int, error) // roles + roles_ver
    ChangeTx(ctx context.Context, targetID, grantedBy string, add, remove []Role, force bool) (roles []Role, ver int, err error)
    // Tx: INSERT/DELETE user_roles + UPDATE users.roles_ver + revoke-all (reuso GlobalSessionRevoker) + valid_after si force + outbox; ErrUnknownRole|LastAdmin|NotFound
  }
  type ScopeResolver interface { Resolve(roles []Role) (scopes []string, ver int) } // puro, testeable sin I/O
  ```
  Reuso `GlobalSessionRevoker` (revoke-all), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/role_change.go` + `role_bootstrap.go`
  * `Change(callerID, callerRoles, targetID, add, remove, force)`: autoriza (`admin`+`admin:roles`, si no → `ErrForbidden`; `LAST_ADMIN` check con `COUNT admins`) → rate (`admin:roles 20/min`) → `RoleStore.ChangeTx` (revoke-all + `ver+1` (+`valid_after` si force) + outbox `roles.changed` + `revoked_all` + email flag) → `Output{roles,ver}`.
  * `BootstrapStart/Confirm`: si admins>0 o disabled → opaco `202`/nada (igual reset-pattern); si `email==SEED` → link 15min (tabla `bootstrap_tokens` o reuso `password_reset`-like con `purpose=bootstrap` — decisión: reuso `deletion_cancel_tokens`-pattern con tabla propia `bootstrap_tokens`) → `Confirm` otorga `admin` + deshabilita (flag `bootstrap_done` en `system_flags`) + audit.
  * `Issue`-integración: `issue_session.go` llama `ScopeResolver.Resolve(List(target))` para snapshot (si `RoleStore` down → `Issue` falla `500`, sin snapshot parcial).
  * `Rotate`-integración: `rotate_session.go` añade chequeo `roles_ver` (si `snapshot.ver != current` → `ErrStaleRoles` → `403`, sin rotar).
* **Flujo Orquestado:** autoriza→rate→Tx(change+revoke+outbox)→200+email; bootstrap opaco→link→admin único.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/roles_change.go` (`POST /admin/users/:id/roles {add,remove} ?force` auth-admin → `200/400/403/404/429`) + `roles_bootstrap.go` (`POST /admin/bootstrap` opaco + `POST /bootstrap/confirm`) + `middleware/require_roles.go` (gateway-side helper documentado + usado en el propio admin: `require(admin+admin:roles)`).
  * DTO `dto/rbac_dto.go`; `errors/map` (+`FORBIDDEN, UNKNOWN_ROLE, LAST_ADMIN, STALE_ROLES→403`).
  * Rutas `cmd/api/main.go`: 3 rutas admin + recableo `Rotate` con `stale-check` + `Issue` con `Resolve`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/role_store.go` (`user_roles(user_id, role, granted_by, granted_at, PK(user,role))`, `role_catalog(role PK, scopes JSONB, ver)` seed `SCOPES_VER=1`, `users.roles_ver` (migra), `bootstrap_tokens`, `system_flags`; `ChangeTx`: `INSERT/DELETE` + `UPDATE ver` (+`valid_after` si force) + `revoke-all` (llama SQL SES-02 inline en misma Tx) + outbox).
  * Redis: `roles:ver:<uid>` pub + `DEL sess/fam` (reuso sweep) + `roles:ver` cache gateway (`GET` 60s TTL, invalidada por pub `roles.changed`).
* **Salida (Mensajería):** `kafka` (`roles.changed.v1` + `revoked_all{reason:roles_changed}` + audit `roles.*` + `bootstrap`) + pub/sub Redis `roles.changed` (~1s); worker SMTP `roles_changed` (con roles nuevos) siempre.
* **Salida (Seguridad):** `security/scope_resolve.go` (catálogo en código + `role_catalog` DB como verdad; mismatch código-vs-DB → DB manda + `WARN` + métrica `rbac_catalog_drift_total`).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `role_changes_total{change,role}` + `stale_roles_rejections_total` + `rbac_redis_fallback_total` + `rbac_catalog_drift_total` + `bootstrap_total`.
* **Tracing (OpenTelemetry):** Raíces `UseCase.RoleChange/Bootstrap`, `Issue.ResolveScopes`, `Guard.RolesVerCheck`. Atributos `roles, ver`, nunca PII.
* **Logs Estructurados:** `pkg/logger`: `INFO role grant/revoke/bootstrap (roles, ver, granted_by)`, `WARN forbidden/unknown/last_admin/stale/rate`, `ERROR db`. Sin secretos (roles son códigos públicos internos).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_025_rbac.up.sql` (+ down):
  ```sql
  CREATE TABLE role_catalog (role TEXT PRIMARY KEY, scopes JSONB NOT NULL, ver INT NOT NULL DEFAULT 1);
  INSERT INTO role_catalog(role, scopes) VALUES
   ('user','["read:me","write:me"]'),
   ('support_readonly','["read:me","write:me","read:users:support"]'),
   ('admin','["*","admin:roles"]') ON CONFLICT DO NOTHING;
  CREATE TABLE user_roles (user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL REFERENCES role_catalog(role), granted_by UUID, granted_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (user_id, role));
  ALTER TABLE users ADD COLUMN IF NOT EXISTS roles_ver INT NOT NULL DEFAULT 1;
  CREATE TABLE bootstrap_tokens (token_hash TEXT PRIMARY KEY, email CITEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, consumed BOOLEAN NOT NULL DEFAULT FALSE);
  CREATE TABLE system_flags (k TEXT PRIMARY KEY, v TEXT NOT NULL);
  INSERT INTO user_roles(user_id, role) -- backfill: todo ACTIVE existente recibe 'user' (idempotente, solo si no tiene roles):
  SELECT id, 'user' FROM users WHERE status='ACTIVE' AND NOT EXISTS (SELECT 1 FROM user_roles WHERE user_id=users.id) ON CONFLICT DO NOTHING;
  ```
  Down: `DROP TABLE ...; ALTER TABLE users DROP COLUMN roles_ver;`. Redis `roles:ver:*` (cache gateway).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `rbac_test.go` (catálogo→scopes, snapshot, LastAdmin matriz, bootstrap-condiciones) + servicio table-driven con fakes (grant+revoke-all+ver+1, upgrade también revoca, rotate-stale→403, support→403 grant, unknown→400, inexistente→404, bootstrap 2º opaco, force→valid_after). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/rbac_smoke.js`: 20 VUs grant/revoke (p95 <300ms con revoke-all) + gateway-mock (viejo `403 STALE` ≤1s pub/sub o ≤60s cache) + rotate-stale `403` + flood admin 25/min→429 + Redis-down (PG verdad) + PG-down (500 0 cambios) + bootstrap-race (2 confirms mismo token → 1×admin + 1×400).
