# Contratos de Integración: CU-CRED-03

## 1. Contrato HTTP (API REST)

* **Rutas:**
  * `POST /api/v1/auth/email/change/start {new_email}` (Bearer ACTIVE + Step-Up `cred:change-email`) → `202/409`
  * `POST /api/v1/auth/email/change/confirm {token}` (±Bearer del requester) → `200/400/409`
  * `GET /api/v1/auth/email/change?token=` → form (siempre `200` si formato OK, no consume)
* **Rate-limit:** `emailchange:user 3/hora`, `:ip 20/hora`, `confirm:ip 20/min` → `429 + Retry-After`. Body ≤2KB/4KB. `Cache-Control: no-store`.

```bash
curl -X POST http://localhost:8080/api/v1/auth/email/change/start -H "Authorization: Bearer <fresh>" -H "X-Step-Up-Token: <scope>" -H "Content-Type: application/json" -d '{"new_email":"nuevo@example.com"}'
# 202 { "success": true, "data": { "status": "confirmation_sent", "new_email_masked": "n***@example.com" } }
# 409 { "success": false, "error": { "code": "EMAIL_TAKEN", "message": "Ese correo ya está en uso.", "details": [] } }
curl -X POST http://localhost:8080/api/v1/auth/email/change/confirm -H "Content-Type: application/json" -d '{"token":"<43ch>"}'
# 200 { "success": true, "data": { "status": "email_changed", "new_email_masked": "n***@example.com" } }
# 400 { "success": false, "error": { "code": "INVALID_OR_EXPIRED", "message": "El enlace es inválido o expiró.", "details": [] } }
```

### Errores
`401 STEP_UP_REQUIRED` (start sin frescura/token), `400 SAME_EMAIL/VALIDATION_FAILED`, `409 EMAIL_TAKEN` (start libre-tomado o confirm-race), `429` (rate o send-throttle), `500` (infra, 0 cambios).

## 2. Eventos Asíncronos (Kafka)

Vía outbox (doble-mail en start, triple en confirm). Sin `token` (hashes) + mask. Key `user_id`.

* **Tópico:** `auth.email.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "email.change_requested", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "old_hash": "sha256:...", "new_hash": "sha256:...", "new_masked": "n***@example.com" } }
{ "event_id": "uuid", "event_type": "email.changed", "occurred_at": "...",
  "payload": { "user_id": "uuid", "new_hash": "sha256:...", "new_masked": "n***@example.com" } }
```
* **Tópico:** `auth.session.revoked_all.v1` — `{user_id, reason:"email_change", valid_after, trace_id}`.
* **Tópico:** `auth.audit.v1` — `{action:"email.change_start|confirm", user_id, old_hash, new_hash, result:taken|throttled|success|invalid, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. SMTP: nuevo link-15min + viejo aviso-mask + `changed` al nuevo vía worker.
