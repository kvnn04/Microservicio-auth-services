# Contratos de Integración: CU-SEC-05

## 1. Contrato HTTP (API REST)

* **Rutas:**
  * `POST /api/v1/auth/account/deletion/request {confirm_email, accepted:true}` (Bearer ACTIVE + Step-Up `account:delete`) → `202`
  * `POST /api/v1/auth/account/deletion/cancel/start {email}` (anónimo opaco) → `202`
  * `POST /api/v1/auth/account/deletion/cancel/confirm {token}` → `200/410`
* **Rate-limit:** `deletion:user 3/día`, `cancel-start:ip 10/hora` → `429`. `Cache-Control: no-store`.
* **Login en gracia:** `POST /login` con cuenta `DELETION_REQUESTED` → `401 INVALID_CREDENTIALS` OPACO (igual mala; el `403 ACCOUNT_DELETED` solo en endpoints con posesión probada — anti-oráculo).

```bash
curl -X POST http://localhost:8080/api/v1/auth/account/deletion/request -H "Authorization: Bearer <fresh>" -H "X-Step-Up-Token: <account:delete>" -H "Content-Type: application/json" -d '{"confirm_email":"user@example.com","accepted":true}'
# 202 { "success": true, "data": { "status": "deletion_requested", "effective_at": "...+30d" } } + Clear-Cookie
curl -X POST http://localhost:8080/api/v1/auth/account/deletion/cancel/confirm -H "Content-Type: application/json" -d '{"token":"<43ch>"}'
# 200 { "success": true, "data": { "status": "active" } }
# 410 { "success": false, "error": { "code": "DELETION_EXECUTED", "message": "Ya fue eliminada.", "details": [] } }
```

### Errores
`401 STEP_UP_REQUIRED/INVALID` (sin triple), `400 DELETION_CONFIRM_REQUIRED` (email/accepted), `409 DELETION_ALREADY_REQUESTED {effective_at}`, `410 DELETION_EXECUTED`, `429`, `500` (0 cambios).

## 2. Eventos Asíncronos (Kafka)

Vía outbox (corte y hard). Post-hard sin PII (solo `anon_id` + `user_id` histórico 1 vez). Key `user_id`.

* **Tópico:** `auth.deletion.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "deletion.requested", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "effective_at": "...+30d" } }
{ "event_id": "uuid", "event_type": "deletion.cancelled", "occurred_at": "...",
  "payload": { "user_id": "uuid" } }
```
* **Tópico:** `auth.user.erased.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "user.erased", "occurred_at": "...",
  "payload": { "user_id": "uuid", "anon_id": "anon:abc123", "fiscal_retained": true } }
```
* **Tópico:** `auth.session.revoked_all.v1` — `{reason:"deletion"}` + `auth.audit.v1 {action:deletion.*, anon_id?}`. Schemas BACKWARD, DLQ `auth.dlq.v1` (erased reintentado 24h). SMTP solicitud/recordatorio-25 (sin post-hard).
