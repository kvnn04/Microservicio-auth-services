# Plan de Implementación Técnica: CU-SES-03

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`sessions.go`).
* **Entidades / Value Objects:**
  ```go
  type SessionView struct { SID, DeviceLabel, IPMasked, Location string; CreatedAt, LastSeen time.Time; Current bool }
  func MaskIP(ip string) string // 203.0.113.42 → 203.0.113.xxx (v6: /64 + ::xxxx)
  func DeviceLabel(uaFamily, osFamily string) string // Chrome · Windows
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/session_list_ports.go
  type SessionLister interface {
    List(ctx context.Context, userID, currentSID string) ([]SessionView, error) // PG verdad, orden last_seen DESC
    RevokeOne(ctx context.Context, userID, currentSID, targetSID string) error // ErrUseLogout si target==current; ErrNotFound (404 único); triple-capa + outbox
  }
  ```
  Reuso `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/list_sessions.go` + `revoke_session.go`
  * `List`: rate-check (middleware ya lo hizo, doble-chequeo ligero) → `Lister.List` → `Output{sessions,total}` (el servicio marca `Current`, el adapter no decide).
  * `RevokeOne`: valida `target≠current` (`ErrUseLogout`) + formato UUID (`ErrValidation`) → rate → `Lister.RevokeOne` (miss→`ErrNotFound` opaco + jitter 10-20ms; ok→email flag + métrica) → `Output{revoked}`.
* **Flujo Orquestado:** auth→rate→list/revoke→200. Sin Step-Up, sin frescura, sin locks.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/sessions_list.go` (`GET /api/v1/auth/sessions` → `200 {sessions,total}`) + `sessions_revoke_one.go` (`DELETE /sessions/:sid` → `200/400/404/429`) + `sessions_touch.go`? No: el touch es header opcional en middleware existente (ver abajo), sin ruta nueva.
  * DTO `dto/sessions_dto.go`; middleware `rate_limit` (`sessions:list 60/min/user`, `revoke-one 20/hora/user`), `request_id`, `recover`; `errors/map` (+`USE_LOGOUT→400`, `SESSION_NOT_FOUND→404`).
  * Rutas `cmd/api/main.go`: `GET /api/v1/auth/sessions`, `DELETE /api/v1/auth/sessions/:sid`. Touch: middleware `session_touch.go` (lee `X-Session-Touch: <sid>` o deriva de Bearer `sid`, debounce Redis `touch:<sid> EX 300`, `UPDATE sessions last_seen` async — best-effort, sin bloquear response).
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/session_lister.go` (`SELECT sid, device_label, ip_masked, location, created_at, last_seen WHERE user_id ORDER BY last_seen DESC`; `RevokeOne` Tx: `SELECT target FOR UPDATE (miss→NotFound)` + `UPDATE families revoked` + `DELETE sessions target` + `INSERT revoked_jtis(target.jti_actual)` + outbox `revoked_one`; `sess:by_user` se mantiene).
  * Redis: `persistencia/redis/session_lister.go` (fast-path lista: `SMEMBERS by_user` + `MGET sess:*` con fallback PG si miss parcial/total; `DEL sess:<t>/fam:<t>` + `SET jti:<tjti>` en revoke; `touch` debounce key).
  * Nota columnas: `sessions` necesita `device_label, ip_masked, location` (denormalizados al Issue en CU-AUTH-04; si faltan en filas viejas, lista muestra `unknown` + worker backfill best-effort — migración 018 los añade NULLable).
* **Salida (Mensajería):** `kafka` (`session.revoked_one.v1` + audit `session.list|revoke_one`; list NO emite evento bus, solo audit/métrica) + worker SMTP `session_closed_remotely` (con device) siempre.
* **Salida (Seguridad):** reuso verifier base (sin checks que bloqueen revocados para entrar al revoke — igual SES-01: firma+exp bastan).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `sessions_listed_total{result}` + `session_revoked_one_total{result=ok|use_logout|not_found|rate_limited}` + duraciones. Vía MetricsPort + middleware.
* **Tracing (OpenTelemetry):** Raíces `UseCase.ListSessions/RevokeSession` (hijos `jwt.verify`, `ratelimit`, `db.sessions.*`, `cache.*`, `outbox.insert` (revoke)). Atributos `target_sid`, nunca tokens.
* **Logs Estructurados:** `pkg/logger`: `INFO sessions listed (total), session revoked_one (target)`, `WARN use_logout/not_found/rate_limited`, `ERROR db`. Sin tokens/IP completa (masked).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_018_session_labels.up.sql` (+ down):
  ```sql
  ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_label TEXT NOT NULL DEFAULT 'unknown';
  ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_masked TEXT NOT NULL DEFAULT 'unknown';
  ALTER TABLE sessions ADD COLUMN IF NOT EXISTS location TEXT;
  -- backfill: UPDATE sessions SET device_label='migrated', ip_masked='migrated' WHERE device_label='unknown'; (una vez, documentado)
  ```
  Down: `ALTER TABLE sessions DROP COLUMN ...;`. Redis touch-keys `touch:<sid> EX300` (efímeras).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `sessions_test.go` (MaskIP v4/v6, DeviceLabel, orden) + servicio table-driven con fakes (list 3 masked+current, revoke remote ok, actual→UseLogout, ajena/muerta→NotFound idénticos, replay RequestID). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/sessions_smoke.js`: 50 VUs list (p95 <120ms PG, hit-rate Redis), 20 VUs revoke (p95 <200ms), flood list 70/min→429 + revoke 25/hora→429, PG-down list→500-no-`[]` + revoke 500-0-cambios, Redis-down 200 vía PG, touch-debounce (100 req mismo sid → ≤1 UPDATE/5min medido en PG logs).
