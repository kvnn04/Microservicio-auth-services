# Plan de Implementación Técnica: CU-SES-04

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`rotation.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    GraceWindow=10*time.Second; IdempotencyWindow=60*time.Second
    ConcurrentLimit=3; ConcurrentWindow=10*time.Second
  )
  type RotateDecision string // Rotate | GraceIdempotent | ConcurrentRetry | ReuseTheft | Expired | Revoked | Invalid
  func DecideRotate presentedHash, currentHash, parentHash string, rotatedAt time.Time, now time.Time, sameDevice bool, sameReqID bool, flaps int) RotateDecision
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/rotation_ports.go
  type RotationStore interface {
    LookupForUpdate(ctx context.Context, tx any, refreshHash string) (family FamilyState, isCurrent, isParent bool, err error) // ErrNotFound→Invalid
    RotateTx(ctx context.Context, oldHash string, newPair IssuedPair) error // CAS WHERE current_hash=old; ErrConcurrent|ErrReuse (ya cambió a otro)
    MarkReuseGlobal(ctx context.Context, familyID, userID string) (GlobalRevokeResult, error) // delega a GlobalSessionRevoker SES-02
  }
  type FamilyState struct { Family, UserID, SID, CurrentHash, ParentHash string; Counter int; AbsoluteExp, SlidingExp time.Time; Revoked bool; RotatedAt time.Time; DeviceHash string }
  ```
  Reuso `AccessSigner` (nuevo Access mismo `sid`), `RefreshGenerator` (32B), `GlobalSessionRevoker` (reuse→global), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicio:** `internal/service/rotate_session.go`
  * `Rotate(refreshPlain, reqID, ip, ua)`:
    1. Forma (43ch → hash; malforma → `ErrValidation`) + rate (`refresh:ip|fam`) + idempotencia (`idempotency:refresh:<reqID> EX 60` hit → mismo par guardado → `GraceIdempotent`, sin tocar chain).
    2. Abre Tx PG (`SELECT family FOR UPDATE` por hash en `refresh_hashes` → `families`): miss → `ErrInvalid` (sin alarma); `revoked` → `ErrRevoked`; `absolute/sliding` pasado → `ErrExpired` (+ marca `revoked=expired` best-effort).
    3. `DecideRotate(...)`: `current` → `RotateTx` (CAS; si pierde CAS por otro rotate intermedio → `ErrConcurrent` + cuenta flaps `concurrent:<oldHash> INCR EX 10`, a 3 → escala a `ReuseTheft`); `parent + ≤10s + mismo device` → `GraceIdempotent`? No hay par guardado salvo mismo RequestID (el RequestID difiere en race) → `ErrConcurrent` (con algoritmo cliente); `parent/antiguo` fuera de gracia o distinto device o flaps≥3 → `MarkReuseGlobal` (Tx SES-02 + email crítico + P1) → `ErrCompromised`.
    4. `RotateTx` genera `newPlain/newAccess(same sid/auth_time, new jti)` + `INSERT hashes` + `UPDATE families` + `UPDATE sessions jti_actual/last_seen` + `INSERT revoked_jtis(oldJti)` + `DEL/SET` Redis + outbox `rotated` (+ guarda `idempotency:refresh:<reqID> → par` EX 60 + `fam:last_1s`? No se guarda plano salvo idempotency-keyed) → `Output{access, refresh, sid}` (el adapter rota cookie).
* **Flujo Orquestado:** forma→rate→idempotencia→lookup(FOR UPDATE)→decide→rotate|grace|concurrent|global→200/409/401. Sin Bearer, sin Step-Up, sin locks cuenta.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler `handlers/refresh.go` (`POST /api/v1/auth/refresh`, lee cookie `refresh_token` o body `{refresh_token}`, `≤4KB`, `no-store`, mapea `200 rotated / 200 grace / 409 CONCURRENT_ROTATION {retry:true} / 401 INVALID|EXPIRED|REVOKED|COMPROMISED / 429/500`, rota cookie `Set-Cookie` con `Max-Age` restante real MISMO Path).
  * DTO `dto/refresh_dto.go`; middleware rate (`refresh:ip 30/min`, `refresh:fam 10/min` por hash familiar si identificable), `request_id` (clave de gracia), `recover`.
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/refresh`.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/rotation_store.go` (`LookupForUpdate`: `JOIN hashes→families FOR UPDATE`; `RotateTx`: `UPDATE families ... WHERE current_hash=old` (0 filas → `ErrConcurrent`) + `INSERT hashes(new)` + `UPDATE sessions jti/last_seen` + `INSERT revoked_jtis(old)` + outbox; `MarkReuseGlobal`: invoca `global_revoker` SES-02 en la misma Tx + outbox `reuse_detected`).
  * Redis: `persistencia/redis/rotation_store.go` (`GET fam:<family>` fast-path + `SET` nuevo + `SET jti:old EX` + `SET idempotency:refresh:<reqID> {access,refresh} EX 60` (guarda plano 60s SOLO keyed por RequestID — ventana mínima, documentado) + `INCR concurrent:<oldH> EX 10`; down → PG verdad + `WARN` (idempotency-grace degradada a `409`, documentado)).
* **Salida (Mensajería):** `kafka` (`session.rotated.v1` + `session.reuse_detected.v1` P1 + `session.revoked_all{reason:reuse_detected}` + audit); worker SMTP `reuse_critical` (ambos devices/horas + `cambia tu clave`) + `rotated` no (ruido: rotate-ok no envía email, solo audit/métrica).
* **Salida (Seguridad):** reuso `ed25519_signer` (nuevo Access, `auth_time` preservado, `roles_ver` preservado) + `refresh_generator` + `ConstantTime` en compares + `device_hash` check (igualdad estricta para gracia; mismatch → global).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `rotation_total{result=ok|grace_idempotent|concurrent|reuse|expired|revoked|invalid|rate_limited|error}` + `reuse_detected_total{severity=critical}` (P1 pager) + `rotation_duration_seconds` + `concurrent_409_total`. Vía MetricsPort + middleware.
* **Tracing (OpenTelemetry):** Raíz `UseCase.RotateSession` (hijos `ratelimit`, `idempotency.check`, `db.refresh.lookup`, `reuse.check`, `crypto.rand+sign`, `db.rotate (CAS)`, `cache.rotate+denylist`, `outbox.insert`, `global_revoke` (si reuse)). Atributos `family, counter, grace`, nunca planos.
* **Logs Estructurados:** `pkg/logger`: `INFO session rotated (family, counter)`, `WARN concurrent/expired/revoked/rate_limited`, `CRITICAL reuse_detected (family, devices)` + P1. Sin `Refresh` plano (solo `hash_prefix(8)`).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_019_rotation_grace.up.sql` (+ down):
  ```sql
  ALTER TABLE refresh_families ADD COLUMN IF NOT EXISTS last_rotated_at TIMESTAMPTZ NOT NULL DEFAULT now();
  ALTER TABLE refresh_families ADD COLUMN IF NOT EXISTS last_parent_hash TEXT NOT NULL DEFAULT '';
  ALTER TABLE refresh_families ADD COLUMN IF NOT EXISTS device_hash TEXT NOT NULL DEFAULT '';
  CREATE INDEX IF NOT EXISTS idx_hashes_family ON refresh_hashes(family);
  ```
  Down: `ALTER TABLE ... DROP COLUMN ...;`. Redis `idempotency:refresh:* EX60`, `concurrent:* EX10`, `fam:last*` NO (solo idempotency-keyed guarda plano 60s).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `rotation_test.go` (Decide matriz current/parent-gracia/concurrent/antiguo/device/flaps) + servicio table-driven con fakes (ok mismo-sid + sliding acotado, replay-mismo-ReqID idempotente, race `409` + algoritmo cliente (re-lee jar → ok), 4º flap → global + P1, expirada/revoked/miss → 401 sin alarma/m con login-hint, CAS-perdido → `409`). `go test -race` verde, con `-run Race` test de 2 goroutines mismo Refresh (1×200 + 1×409 determinista por CAS, nunca 2×200 ni global).
* **Pruebas de Estrés / Carga:** k6 `scripts/load/rotation_smoke.js`: 100 VUs rotate-seriado por family (p95 <250ms, 0 `409` en serie), 2×paralelo mismo token (100% 1×200+1×409, 0 globales), reuso diferido 11s (100% global+P1+email), flood 40/min→429, PG-down 500 sin quemar, Redis-down 200 vía PG (grace degradada a `409` documentada). Chaos absolute-vencido → `401` + re-login.
