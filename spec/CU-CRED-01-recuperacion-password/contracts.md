# Contratos de Integración: CU-CRED-01

## 1. Contrato HTTP (API REST)

* **Rutas:**
  * `POST /api/v1/auth/password/reset/start {email}` → `202` genérico siempre
  * `POST /api/v1/auth/password/reset/confirm {token, new_password[, new_password_confirm]}` → `200/400`
  * `GET /api/v1/auth/password/reset?token=` → form (siempre `200` si formato OK, no consume ni revela)
* **Auth:** Ninguna. `X-Request-ID` recomendado. Body ≤2KB (start) / ≤8KB (confirm). `Cache-Control: no-store`.
* **Rate-limit:** `pwdreset:start:ip 10/hora`, `confirm:ip 20/min`, `:tok 5/min` → `429 + Retry-After`. El bucket `:email 3/hora` y las quotas (60s/5-24h) responden `202` genérico en vez de `429` para no oracular elegibilidad.

### Start / Confirm
```bash
curl -X POST http://localhost:8080/api/v1/auth/password/reset/start -H "Content-Type: application/json" -H "X-Request-ID: <uuid>" -d '{"email":"user@example.com"}'
# 202 { "success": true, "data": { "status": "if_exists_sent", "message": "Si la cuenta existe recibirás un correo." } }
curl -X POST http://localhost:8080/api/v1/auth/password/reset/confirm -H "Content-Type: application/json" -d '{"token":"<43ch>","new_password":"Nu3va!Valida-2026"}'
# 200 { "success": true, "data": { "status": "password_changed", "message": "Inicia sesión con tu nueva clave." } }
# 400 { "success": false, "error": { "code": "INVALID_OR_EXPIRED", "message": "El enlace es inválido o expiró.", "details": [] } }
# 400 POLICY: { "code": "PASSWORD_POLICY_FAILED", "details": [{"field":"new_password","reason":"TOO_SHORT|MISSING_CLASS|COMPROMISED"}] }
# 400 REUSED: { "code": "PASSWORD_REUSED", "message": "Elige una clave distinta a la actual.", "details": [] }
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox. Sin `token/clave` (solo hashes). Key `user_id`/`email_hash`.

* **Tópico:** `auth.password.v1` — **Key:** `user_id`/`email_hash`
```json
{ "event_id": "uuid", "event_type": "password.reset_requested", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid-or-null", "email_hash": "sha256:...", "expires_at": "...+15min" } }
{ "event_id": "uuid", "event_type": "password.changed", "occurred_at": "...",
  "payload": { "user_id": "uuid", "via": "reset", "risk": "low|high", "request_id": "550e8400-..." } }
{ "event_id": "uuid", "event_type": "password.reset_federated_hint", "occurred_at": "...",
  "payload": { "user_id": "uuid", "email_hash": "sha256:..." } }
```
* **Tópico:** `auth.session.revoked_all.v1` — `{user_id, reason:"password_reset", valid_after, trace_id}` (consumido por gateways/SES).
* **Tópico:** `auth.audit.v1` — `{action:"password.reset_start|confirm", email_hash, user_id?, result, risk?, trace_id}` (+ `security.context_mismatch` si high). Schemas BACKWARD, DLQ `auth.dlq.v1`. SMTP link-15min + `password_changed` + hint vía worker.
