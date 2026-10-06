# Contratos de Integración: CU-AUTH-05

## 1. Contrato HTTP (API REST)

* **Rutas:**
  * `POST /api/v1/auth/passwordless/start {email}` → `202` genérico siempre
  * `POST /api/v1/auth/passwordless/verify {token|code}` → `200/202/400`
  * `GET /api/v1/auth/passwordless?token=` → alias link (idempotente, mismo efecto)
* **Auth:** Ninguna (anónimo). `X-Request-ID` recomendado (idempotencia 24h). Body ≤2KB (start) / ≤4KB (verify). `Cache-Control: no-store`.
* **Rate-limit:** `pless:start:ip 10/hora`, `pless:start:email 3/hora`, `pless:verify:ip 20/min`, `pless:verify:tok 5/min` → `429 + Retry-After`.

### Start
```bash
curl -X POST http://localhost:8080/api/v1/auth/passwordless/start -H "Content-Type: application/json" -H "X-Request-ID: <uuid>" -d '{"email":"user@example.com"}'
# 202 { "success": true, "data": { "status": "if_exists_sent", "message": "Si la cuenta existe recibirás un correo." } }
```
Mismo `202` exista o no, ACTIVE o no, throttled o no.

### Verify
```json
// { "token": "<43ch>" } o { "code": "87654321" }
// 200 { "success": true, "data": { "status": "active", "message": "Sesión iniciada." } } + cookies (sin MFA)
// 202 { "success": true, "data": { "status": "mfa_required", "mfa_token": "<...>", "methods": ["totp"], "expires_in": 300 } }
// 400 { "success": false, "error": { "code": "INVALID_OR_EXPIRED", "message": "El enlace o código es inválido o expiró.", "details": [] } }
```
Mismo `400` para miss/expirado/consumido/quemado. GET-alias: `curl "http://localhost:8080/api/v1/auth/passwordless?token=..."` (con/sin Bearer, mismo `200/202/400` JSON, no redirect con tokens).

## 2. Eventos Asíncronos (Kafka)

Vía outbox. Sin `token/código` plano (solo hashes). Key `user_id`/`email_hash`.

* **Tópico:** `auth.passwordless.v1` — **Key:** `user_id`/`email_hash`
```json
{ "event_id": "uuid", "event_type": "passwordless.requested", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid-or-null", "email_hash": "sha256:...", "expires_at": "...+10min" } }
{ "event_id": "uuid", "event_type": "passwordless.consumed", "occurred_at": "...",
  "payload": { "user_id": "uuid", "risk": "low", "method": "link", "request_id": "550e8400-..." } }
```
* **Tópico:** `auth.security.context_mismatch.v1` (solo `risk=high`) — `{user_id, ip_hash, ua_hash, prev_ip_hash, trace_id}`.
* **Tópico:** `auth.audit.v1` — `{action:"passwordless.start|verify", email_hash, user_id?, result, risk?, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. SMTP link+OTP 10min + avisos takeover vía worker.
