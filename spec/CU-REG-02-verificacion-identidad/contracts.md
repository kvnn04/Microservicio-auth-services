# Contratos de Integración: CU-REG-02

## 1. Contrato HTTP (API REST)

* **Rutas:**
  * `POST /api/v1/auth/verify-email` (canónica)
  * `GET /api/v1/auth/verify-email?token=<base64url>` (alias Magic Link, idempotente, misma lógica)
  * `POST /api/v1/auth/resend-verification` (reenvío)
* **Autenticación requerida:** Ninguna. No requiere Bearer. `X-Request-ID: UUIDv4` obligatorio (idempotencia 24h; si ausente se genera y devuelve, pero sin garantía idempotente).
* **Headers:** `Content-Type: application/json` (POST), `Cache-Control: no-store` (respuesta siempre), `Retry-After` (solo 429).
* **Rate-limit:** `verify:ip` 10/min, `verify:tok_hash` 5/min, `resend:email_hash` 3/hora + `resend:ip` 10/hora. Excedido → `429 RATE_LIMITED` sin consumir intento.
* **Límites:** POST verify body ≤4KB, resend ≤2KB → `413` si excede.

### Request Payload — Verify
```json
{ "token": "B64url_43_chars_32B_opaque" }
```
o
```json
{ "code": "87654321" }
```
Reglas: exactamente uno de `token|code`. `token` = base64url sin padding, 43 chars, decode = 32B exactos. `code` = string `^[0-9]{8}$`. Otro → `400 VALIDATION_FAILED` (único caso con detalle por campo; no revela existencia).
```bash
curl -X POST http://localhost:8080/api/v1/auth/verify-email \
 -H "Content-Type: application/json" -H "X-Request-ID: 550e8400-e29b-41d4-a716-446655440001" \
 -d '{"token":"...43ch..."}'
curl "http://localhost:8080/api/v1/auth/verify-email?token=...43ch..."
```

### Request Payload — Resend
```json
{ "email": "user@example.com" }
```
`email` misma normalización CU-REG-01. Respuesta siempre genérica (anti-enumeración).

### Respuestas

#### `200 OK` — Verificado / ya verificado
```json
{ "success": true, "data": { "status": "active", "message": "Cuenta verificada. Ya puedes iniciar sesión." } }
```
o idempotente:
```json
{ "success": true, "data": { "status": "already_verified", "message": "Esta cuenta ya estaba verificada." } }
```

#### `202 Accepted` — Reenvío (siempre genérico)
```json
{ "success": true, "data": { "status": "if_exists_verification_sent", "message": "Si la cuenta existe y está pendiente, recibirás un nuevo correo." } }
```
Se retorna igual exista/no-exista, ACTIVE/PENDING, cooldown/cuota excedida, Redis/Kafka caídos (outbox pendiente).

#### `400 Bad Request` — Formato
```json
{ "success": false, "error": { "code": "VALIDATION_FAILED", "message": "Datos inválidos.", "details": [{"field": "token", "reason": "INVALID_FORMAT"}] } }
```

#### `400 Bad Request` — Secreto inválido/expirado/consumido/quemado (INDISTINGUIBLE)
```json
{ "success": false, "error": { "code": "INVALID_OR_EXPIRED", "message": "El enlace o código es inválido o expiró. Solicita uno nuevo.", "details": [] } }
```
Mismo body para no-existe/expirado/consumido/quemado/ACTIVE-ajeno. Sin `user_id/email`. Con delay 40-80ms.

#### `429 Too Many Requests`
```json
{ "success": false, "error": { "code": "RATE_LIMITED", "message": "Demasiadas solicitudes. Intenta de nuevo.", "details": [] } }
```
+ `Retry-After: 42`.

#### `500 Internal Server Error`
```json
{ "success": false, "error": { "code": "INTERNAL_ERROR", "message": "No pudimos procesar tu solicitud.", "details": [] } }
```

## 2. Eventos Asíncronos (Kafka)

Producidos vía outbox/worker, nunca en request. `event_id` UUIDv7 (idempotencia), `occurred_at` UTC. Sin `token/code/email` plano salvo `verification_requested` dirigido al mailer (igual que CU-REG-01).

* **Tópico:** `auth.user.activated.v1` — **Key:** `user_id`
```json
{
  "event_id": "uuid",
  "event_type": "user.activated",
  "occurred_at": "2026-10-05T12:15:00Z",
  "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "activated_at": "2026-10-05T12:15:00Z", "method": "link", "request_id": "550e8400-..." }
}
```
`method`: `link|otp`.

* **Tópico:** `auth.email.verification_requested.v1` (reenvío) — **Key:** `user_id`
```json
{
  "event_id": "uuid",
  "event_type": "email.verification_requested",
  "occurred_at": "2026-10-05T12:00:00Z",
  "trace_id": "4bf92f...",
  "payload": {
    "user_id": "uuid",
    "email": "user@example.com",
    "verification_token_hash": "sha256:...",
    "otp_hash": "sha256:...",
    "expires_at": "2026-10-05T12:15:00Z",
    "is_resend": true
  }
}
```
Token plano nunca en Kafka; el worker lo resuelve internamente desde Postgres/Redis para SMTP (link `https://front/verify?token=<b64url>` + `code 8d` en plantilla).

* **Tópico:** `auth.audit.v1` — **Key:** `user_id` o `email_hash`
```json
{
  "event_id": "uuid",
  "event_type": "audit.user_verify",
  "occurred_at": "2026-10-05T12:15:00Z",
  "payload": {
    "action": "user.verify",
    "user_id": "uuid",
    "email_hash": "sha256:...",
    "result": "success|already_verified|invalid_or_expired|resent|throttled",
    "method": "link|otp|null",
    "attempts_left": 2,
    "redis_path": "hit|fallback",
    "trace_id": "4bf92f...",
    "request_id": "550e8400-..."
  }
}
```
DLQ `auth.dlq.v1` con headers `original-topic, retry-count`. Schemas BACKWARD en registry.
