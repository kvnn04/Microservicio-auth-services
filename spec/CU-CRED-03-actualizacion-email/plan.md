# Plan de Implementación Técnica: CU-CRED-03

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/user/` (`email_change.go`).
* **Entidades / Value Objects:**
  ```go
  const (
    EmailChangeTTL=15*time.Minute; EmailChangeTokenBytes=32; EmailChangeMaxAttempts=3
    EmailChangeRatePerHour=3; EmailChangeCooldown=60*time.Second; EmailChangeMaxDay=5
  )
  type EmailChangeRecord struct { RequesterID, TokenHash, NewNormalized, NewOriginal string; ExpiresAt time.Time; Attempts int; Consumed bool }
  func (r *EmailChangeRecord) Alive(now time.Time) bool
  func ParseEmailChangeToken(raw string) (hash string, err error)
  func MaskEmail(normalized string) string // u***@dominio
  ```
  Reuso `Email.Normalize` (CU-REG-01), `RiskOf`? No (sin ctx-binding aquí — el Step-Up + buzón nuevo bastan; documentado).
* **Puertos de Salida:**
  ```go
  // internal/domain/user/email_change_ports.go
  type EmailChangeStore interface {
    QuotaCheck(ctx context.Context, userID string) (allowed bool, retry time.Duration, err error) // 60s/5-24h
    Taken(ctx context.Context, newNorm, requesterID string) (takenByOther bool, err error) // 409 solo otro dueño
    Issue(ctx context.Context, rec *EmailChangeRecord) error // dual-write + supersede + outbox + doble-mail
    FindAlive(ctx context.Context, hash string) (*EmailChangeRecord, error) // Redis→PG; ErrEmailChangeInvalid
    ConfirmTx(ctx context.Context, hash string) (requesterID, newNormalized string, err error) // re-UNIQUE+burn, update, revoke_all, outbox×2
    IncrementAttempts(ctx context.Context, hash string) (burned bool, err error) // al 3º quema
  }
  ```
  Errores en `user`: `ErrEmailAlreadyInUse` (reuso → 409), `ErrEmailChangeInvalid/Burned` (→ 400). Reuso `StepUpChecker` del servicio (start), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicios:** `internal/service/email_change_start.go` + `email_change_confirm.go`
  * `Start(userID, authTime, stepUpTokenOpt, newRaw)`: `Guard(cred:change-email)` en el servicio vía `StepUpChecker` (fast-pass o token; falla → `ErrStepUp`, ver §8 D-01 — sin middleware para no quemar el `jti` dos veces) → normaliza (malforma/igual → `ErrValidation/Same`) → `Taken` (taken → `ErrTaken` + audit) → quotas (throttled → `ThrottledError` → handler `429`) → `Issue` + outbox `requested(old+new)` + doble-mail → `Output{masked}`.
  * `Confirm(token, bearerUserOpt)`: forma → rate confirm → `FindAlive` (miss→`ErrInvalid`+delay) → valida bearer ausente o igual-requester (distinto → `ErrInvalid` opaco) → `ConfirmTx` (re-UNIQUE new, race → `ErrTaken` + quema; ok → update + `valid_after` + revoke_all + outbox `changed+revoked_all+2 mails`) → `Output{masked}` (sin `Issue`).
* **Flujo Orquestado:** Step-Up→norm→rate→unicidad→quotas→issue+doble-mail→202/409; forma→rate→find→bearer-check→Tx update+revoke→200. Idempotencia RequestID (start 60s, confirm replay mismo RequestID → mismo `200`).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handlers `handlers/email_change_start.go` (`POST /email/change/start {new_email}` auth → `202/400/401/409/429`) + `email_change_confirm.go` (`POST /email/change/confirm {token}` ±Bearer verificado → `200/400/409` + `GET /email/change?token=` form no-consume).
  * DTO `dto/email_change_dto.go`; Step-Up verificado en el servicio (sin middleware `RequireStepUp` en la ruta, ver §8 D-01) + rate (`emailchange:user 3/h` en handler, `:ip 20/h|20/min` en `main.go`) + `no-store`.
  * Rutas `cmd/api/main.go`: `POST /api/v1/auth/email/change/start|/confirm`, `GET /email/change`. Start con `auth` (+Step-Up en servicio); confirm anónimo (+Bearer opcional verificado). TTL/rate/quota son consts de dominio, sin env nuevo.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/email_change_store.go` (`email_change_tokens(token_hash PK, requester FK, new_normalized CITEXT, new_original, expires_at, attempts, consumed, superseded, created_at)`, `Taken` (solo lectura) + `Issue` (supersede + INSERT + outbox + doble-mail en Tx), `ConfirmTx` (`SELECT requester FOR UPDATE` + re-UNIQUE taken? → `ErrTaken`+burn + `UPDATE users SET email_*, verified, valid_after` + `UPDATE token consumed` + `UPDATE families revoked + DELETE sessions ALL` + outbox×2 en una Tx)).
  * Redis: `persistencia/redis/email_change_store.go` (`emailchange:t/active/sent/count` EX 900/3600/86400, Lua DEL, quotas; down → PG + fallback).
* **Salida (Mensajería):** reuso `kafka` (`email.change_requested|changed` → `auth.email.v1`, `session.revoked_all{reason:email_change}`, + audit); worker SMTP doble (nuevo link-15min + viejo aviso-mask sin token, + `email_changed` al nuevo tras confirmar).
* **Salida (Seguridad):** reuso `token_issuer` (32B), `Email.Normalize`, `StepUpVerifier`, `MaskEmail`.

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `email_change_total{op=start|confirm, result=sent|taken|throttled|success|invalid|step_up_required|rate_limited|error}` + duración + `emailchange_redis_fallback_total`. Vía MetricsPort + middleware.
* **Tracing (OpenTelemetry):** Raíces `UseCase.EmailChangeStart/Confirm` (hijos `stepup.check`, `ratelimit`, `email.normalize`, `db.uniqueness`, `crypto.rand`, `cache+db.save|lookup|consume`, `db.email.update+revoke_all`, `outbox.insert×2`). Atributos `new_domain`, nunca token/emails (mask).
* **Logs Estructurados:** `pkg/logger`: `INFO email change sent/changed` (masked), `WARN taken/throttled/invalid/step_up/rate/fallback`, `ERROR db`. Sin `token/new/old` completos (hashes/mask).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_015_email_change.up.sql` (+ down):
  ```sql
  CREATE TABLE email_change_tokens (
    token_hash TEXT PRIMARY KEY, requester UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_normalized CITEXT NOT NULL, new_original TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL, attempts INT NOT NULL DEFAULT 0,
    consumed BOOLEAN NOT NULL DEFAULT FALSE, superseded BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_emailchange_req_active ON email_change_tokens(requester) WHERE NOT consumed;
  ```
  Down: `DROP TABLE email_change_tokens;`. Redis `emailchange:*` (sin migración). Reuso `valid_after/sessions/families` (010).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `email_change_test.go` (Mask, parse, Alive, quotas) + servicio table-driven con fakes (start fresco→sent+2mails, stale→401, taken→409+audit, throttled→429, confirm ok+revoke_all+verified, race-taken→409+burn, inválidos 400 iguales, bearer-ajeno→400, replay RequestID). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/emailchange_smoke.js`: 30 VUs start (libres/tomados/stale, `409/401` correctos, 4º/hora→429) + 50 VUs confirm (válidos/inválidos/race, p95 <400ms sin Argon2, `400` idénticos, race 1×200/1×409) + doble-mail verificado Mailhog + Redis/Kafka-down intactos, PG-down `500` 0 cambios.
