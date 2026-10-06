# Contratos de Integración: CU-SES-01

## 1. Contrato HTTP (API REST)

* **Ruta:** `POST /api/v1/auth/logout` (Bearer actual o `{refresh_token}` alternativo; sin Step-Up).
* **Rate-limit:** `logout:user 30/min`, `logout:ip 60/min` → `429 + Retry-After`. Body ≤4KB (ignorado salvo refresh-alt). `Cache-Control: no-store`.
* **Cookies:** `Set-Cookie: refresh_token=; Max-Age=0; Path=/api/v1/auth/refresh; HttpOnly; Secure; SameSite=Lax` (MISMO Path que Issue). Front MUST drop Access memoria; nativo borra keystore.

```bash
curl -X POST http://localhost:8080/api/v1/auth/logout -H "Authorization: Bearer <Access-A>" -H "X-Request-ID: <uuid>"
# 200 { "success": true, "data": { "status": "logged_out" } } + Clear-Cookie
# 200 { "success": true, "data": { "status": "already_logged_out" } }
# 401 { "success": false, "error": { "code": "UNAUTHORIZED", "message": "No autenticado.", "details": [] } }
# alternativa sin Bearer:
curl -X POST http://localhost:8080/api/v1/auth/logout -H "Content-Type: application/json" -d '{"refresh_token":"<43ch>"}'
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox en la Tx revoke. Sin tokens (solo `sid/jti/family`). Key `user_id`.

* **Tópico:** `auth.session.logged_out.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "session.logged_out", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "sid": "uuid", "family": "uuid", "jti": "uuid", "already": false } }
```
* **Tópico:** `auth.audit.v1` — `{action:"session.logout", user_id, sid, family, jti, result:ok|already, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Gateways leen denylist `jti` (Redis, fallback `revoked_jtis` PG); `/refresh` posterior da `401 FAMILY_REVOKED` (no robo).
