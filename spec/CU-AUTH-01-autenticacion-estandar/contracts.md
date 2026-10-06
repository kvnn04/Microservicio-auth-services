# Contratos de Integración: CU-AUTH-01

## 1. Contrato HTTP (API REST)

* **Ruta:** `POST /api/v1/auth/login`
* **Autenticación requerida:** Ninguna (si trae Bearer válido se ignora; login es re-emisión). `X-Request-ID: UUIDv4` recomendado (idempotencia side-effects 24h).
* **Headers:** `Content-Type: application/json` obligatorio. Respuesta `Cache-Control: no-store`. `429` añade `Retry-After` + `X-RateLimit-Remaining: 0`.
* **Límites:** Body ≤32KB → `413`. Rate `login:ip` 10/min, `login:account` 5/min.
* **Cookies:** Solo en `200` (sesión CU-AUTH-04: `Set-Cookie` Refresh HttpOnly Secure Lax + Access según CU-AUTH-04). `202/401` sin `Set-Cookie` sesión.

### Request Payload
```json
{ "email": "user@example.com", "password": "Str0ng!Passw0rd-2026" }
```
`email` normaliza igual registro (malformado → `400`); `password` string `1..128` runas (vacía → `400`, sin contar fallo cuenta).

### Respuestas

#### `200 OK` — Sin MFA
```json
{ "success": true, "data": { "status": "active", "message": "Sesión iniciada." } }
```
+ cookies sesión (CU-AUTH-04). Sin `user_id/email` en body.

#### `202 Accepted` — MFA requerido
```json
{ "success": true, "data": { "status": "mfa_required", "mfa_token": "<jwt aud=mfa-challenge 5min>", "methods": ["totp"], "expires_in": 300 } }
```
`mfa_token` solo válido en `POST /api/v1/auth/mfa/verify` (CU-AUTH-02); en cualquier API negocio → `401`.

#### `401 Unauthorized` — Único fallo auth (opaco)
```json
{ "success": false, "error": { "code": "INVALID_CREDENTIALS", "message": "Credenciales incorrectas.", "details": [] } }
```
Mismo body para no-existe/mala/PENDING/LOCKED/borrada/federated-only. Sin `Retry-After` (ese solo en 429 IP).

#### `400 / 429 / 500`
```json
{ "success": false, "error": { "code": "VALIDATION_FAILED", "message": "Datos inválidos.", "details": [{"field": "email", "reason": "INVALID_FORMAT"}] } }
{ "success": false, "error": { "code": "RATE_LIMITED", "message": "Demasiadas solicitudes.", "details": [] } }
{ "success": false, "error": { "code": "INTERNAL_ERROR", "message": "No pudimos procesar tu solicitud.", "details": [] } }
```

```bash
curl -X POST http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" -H "X-Request-ID: <uuid>" -d '{"email":"user@example.com","password":"..."}'
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox/worker. Sin `password/hash/tokens` (solo `mfa challenge_id`). Key `user_id` o `email_hash` si no-existe.

* **Tópico:** `auth.login.v1` — **Key:** `user_id`/`email_hash`
```json
{ "event_id": "uuid", "event_type": "login.success", "occurred_at": "2026-10-05T12:00:00Z", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "email_hash": "sha256:...", "mfa": false, "device_hash": "sha256:...", "request_id": "550e8400-..." } }
{ "event_id": "uuid", "event_type": "login.mfa_challenged", "occurred_at": "...",
  "payload": { "user_id": "uuid", "challenge_id": "uuid", "methods": ["totp"] } }
{ "event_id": "uuid", "event_type": "login.failed", "occurred_at": "...",
  "payload": { "email_hash": "sha256:...", "reason_internal": "bad_password", "fails": 3 } }
{ "event_id": "uuid", "event_type": "login.locked", "occurred_at": "...",
  "payload": { "user_id": "uuid-or-null", "locked_until": "2026-10-05T12:15:00Z", "lock_count": 1 } }
```
* **Tópico:** `auth.audit.v1` — `{action:"login.attempt", email_hash, user_id?, result:success|mfa_required|invalid|rate_limited, reason_internal?, ip_hash, device_hash, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email `security.login_lock` al dueño vía worker SMTP (throttle 1/h, con links login/forgot, sin detalles ataque).
