# Plan de Implementación Técnica: CU-SES-02

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`logout_global.go`).
* **Entidades / Value Objects:**
  ```go
  type GlobalRevokeResult struct { Sessions, Families int; ValidAfter time.Time }
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/session_global_ports.go
  type GlobalSessionRevoker interface {
    RevokeAll(ctx context.Context, userID string) (GlobalRevokeResult, error) // Tx PG + Redis sweep + outbox + pub; ErrNotFound→revoca 0 igual 200 si user borrado? No: si user no existe → ErrUnauthorized base
  }
  ```
  Reuso `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicio:** `internal/service/logout_global.go`
  * `LogoutGlobal(sub, reqID)`:
    1. Rate `logout-global:user|ip` (`ErrRateLimited`).
    2. Idempotencia RequestID (dedup outbox por `event_id=hash(RequestID)`).
    3. `GlobalSessionRevoker.RevokeAll` (Tx: `valid_after=now` + `families revoked` + `sessions DELETE` + outbox `revoked_all` + audit; post-commit Redis sweep `by_user` + `PUBLISH revoked_all` + best-effort DEL challenges indexados).
    4. `Output{sessions, families}` → `200` + email flag (outbox SMTP) + métrica.
* **Flujo Orquestado:** rate→idempotencia→Tx→sweep/pub→200+Clear-Cookie+email. Sin Step-Up, sin frescura, sin denylist-N.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler `handlers/logout_global.go` (`POST /api/v1/auth/logout-global`, auth-base (firma+exp, sin fresh/denylist/valid_after para entrar), `≤4KB`, `no-store`, `200 {logged_out_global, sessions_revoked}` + Clear-Cookie, `401/429/500`).
  * DTO `dto/logout_global_dto.go`; middleware `rate_limit` (`logout-global:user 5/hora`, `:ip 20/hora`), `request_id`, `recover`.
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/logout-global`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/global_revoker.go` (Tx única: `UPDATE users valid_after` + `UPDATE families revoked RETURNING count` + `DELETE sessions RETURNING count` + outbox; `valid_after` con `clock_timestamp()`).
  * Redis: `persistencia/redis/global_revoker.go` (lee `SMEMBERS sess:by_user:<sub>` → `DEL` cada `sess/fam` + `DEL by_user` + `PUBLISH auth.session.revoked_all {user, valid_after}` + best-effort `DEL mfa:challenge:by_user:<sub>/*` si indexado; down → PG + `WARN` + reconciliador).
* **Salida (Mensajería):** `kafka` (`session.revoked_all.v1` + audit `session.logout_global`); worker SMTP `global_logout` (con N + hora/IP). Gateways suscritos a `PUBLISH` invalidan cache `valid_after` en ~1s (además de Kafka).
* **Salida (Seguridad):** reuso verifier base (sin checks que impidan entrar a revocados).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `logout_global_total{result}` + `sessions_revoked_count` Histogram + duración. Vía MetricsPort + middleware.
* **Tracing (OpenTelemetry):** Raíz `UseCase.LogoutGlobal` (hijos `jwt.verify`, `ratelimit`, `db.global_revoke`, `cache.sweep+pub`, `outbox.insert`). Atributos counts, nunca tokens.
* **Logs Estructurados:** `pkg/logger`: `INFO logout_global (sessions, families)` + `WARN rate_limited` + `ERROR db`. Sin tokens.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_017_global_revoke_noop.up.sql` (+ down):
  ```sql
  -- CU-SES-02: sin tablas nuevas (reusa users.tokens_valid_after (010), sessions/families (010)).
  -- Acelera barrido por usuario si falta:
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_families_user ON refresh_families(user_id) WHERE NOT revoked;
  ```
  Down: `DROP INDEX ...;`. Redis `sess:by_user:*` (índice, mantenido desde Issue; 017 lo documenta y el worker lo repara si falta con `SCAN` acotado + `WARN`).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** servicio table-driven con fakes (3 vivas→`{3,N}` + 0 vivas + email flag, repeat→`{0}` mismo 200, expirado→401, rate 6º→429, RedisDown→200 + pendiente, PGDown→500 sin cookie). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/logout_global_smoke.js`: 20 VUs global (p95 <300ms con 20 sesiones/user), repeat 100% `200/0`, flood→429, gateway-mock (pre-corte 200, post-corte 401 en ≤1s con pub/sub o ≤60s sin él), Refresh-post →401, Redis-down 200 + reconcilia, PG-down 500.
