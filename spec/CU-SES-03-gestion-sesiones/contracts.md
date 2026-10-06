# Contratos de Integración: CU-SES-03

## 1. Contrato HTTP (API REST)

* **Rutas (Bearer ACTIVE, sin Step-Up):**
  * `GET /api/v1/auth/sessions` → `200 {sessions,total}`
  * `DELETE /api/v1/auth/sessions/:sid` → `200 revoked` (remota) / `400 USE_LOGOUT` (actual) / `404`
* **Rate-limit:** `sessions:list 60/min/user`, `revoke-one 20/hora/user` → `429 + Retry-After`. `Cache-Control: no-store`.

```bash
curl http://localhost:8080/api/v1/auth/sessions -H "Authorization: Bearer <A>"
# 200 { "success": true, "data": { "total": 3, "sessions": [
#   {"sid":"...","device_label":"Chrome · Windows","ip_masked":"203.0.113.xxx","location":"Lima, PE",
#    "created_at":"...","last_seen_at":"...","current":true}, ... ] } }
curl -X POST http://localhost:8080/api/v1/auth/logout -H "Authorization: Bearer <A>" # actual por aquí
curl -X DELETE http://localhost:8080/api/v1/auth/sessions/<sid-C> -H "Authorization: Bearer <A>"
# 200 { "success": true, "data": { "status": "revoked", "sid": "<C>" } }
# 400 { "code": "USE_LOGOUT" } | 404 { "code": "SESSION_NOT_FOUND" }
```

## 2. Eventos Asíncronos (Kafka)

List: solo audit/métrica (sin bus). Revoke-one vía outbox. Sin tokens. Key `user_id`.

* **Tópico:** `auth.session.revoked_one.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "session.revoked_one", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "sid": "uuid", "device_label": "Chrome · Windows", "by": "self" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"session.list|revoke_one", target_sid?, result, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email `session_closed_remotely` (device+hora) vía worker siempre.
