# Contratos de Integración: CU-REG-06

## 1. Contrato HTTP (API REST)

* **Rutas (todas con `Authorization: Bearer` salvo 401):**
  * `POST /api/v1/auth/federated/{provider}/link` (initiate, Step-Up fresco + `current_password?`) → `200 {url,state}`
  * `GET /api/v1/auth/federated/{provider}/link/callback?code=&state=` (misma sesión) → `200 linked/already_linked`
  * `DELETE /api/v1/auth/federated/{provider}` (o `POST /:provider/unlink`, mismo efecto, Step-Up) → `200 unlinked`
  * `GET /api/v1/auth/federated/linked` (Bearer normal, sin frescura) → `200 []`
* **Step-Up:** initiate/callback/unlink exigen `auth_time≤300s` o `401 STEP_UP_REQUIRED {meta:{max_age:300}}` + `current_password` si `password_hash` existe o `401 INVALID_STEP_UP`. Rate-limit `link:initiate 10/h/user`, `callback 10/min/IP`, `unlink 10/h/user`, `linked 60/min/user` → `429`.

### Initiate
```bash
curl -X POST http://localhost:8080/api/v1/auth/federated/google/link \
 -H "Authorization: Bearer <fresh>" -H "X-Request-ID: <uuid>" -H "Content-Type: application/json" \
 -d '{"current_password":"...solo si tiene password..."}'
# 200 { "success": true, "data": { "url": "https://accounts.google.com/...&state=...&nonce=...&code_challenge=...", "state": "...64hex", "expires_in": 600 } }
```

### Callback / Unlink / List
```bash
curl "http://localhost:8080/api/v1/auth/federated/google/link/callback?code=<c>&state=<s>" -H "Authorization: Bearer <same-user-fresh>"
# 200 { "success": true, "data": { "status": "linked", "provider": "google" } }
# 200 { "success": true, "data": { "status": "already_linked", "provider": "google" } }
curl -X DELETE http://localhost:8080/api/v1/auth/federated/google -H "Authorization: Bearer <fresh>" -H "Content-Type: application/json" -d '{"current_password":"..."}'
# 200 { "success": true, "data": { "status": "unlinked", "provider": "google" } }
curl http://localhost:8080/api/v1/auth/federated/linked -H "Authorization: Bearer <valid>"
# 200 { "success": true, "data": { "linked": [{ "provider": "google", "email_masked": "u***@example.com", "sub_hash": "a1b2c3d4", "linked_at": "2026-10-05T12:00:00Z" }] } }
```

### Errores
```json
{ "success": false, "error": { "code": "STEP_UP_REQUIRED", "message": "Confirma tu identidad de nuevo.", "details": [] } } // 401 + meta.max_age
{ "success": false, "error": { "code": "INVALID_STEP_UP", "message": "No pudimos confirmarte.", "details": [] } } // 401 password mala
{ "success": false, "error": { "code": "INVALID_LINK_STATE", "message": "Flujo inválido o expirado.", "details": [] } } // 400 state/user-mismatch/replay
{ "success": false, "error": { "code": "FEDERATED_ALREADY_LINKED", "message": "Esta cuenta Google ya está vinculada a otra cuenta.", "details": [] } } // 409 ajeno
{ "success": false, "error": { "code": "PROVIDER_ALREADY_LINKED", "message": "Ya tienes este proveedor vinculado.", "details": [] } } // 400 mismo provider distinto sub
{ "success": false, "error": { "code": "LAST_AUTH_FACTOR", "message": "Vincula otro acceso antes de quitar el único.", "details": [] } } // 400 unlink último
{ "success": false, "error": { "code": "FEDERATED_NOT_LINKED", "message": "Ese proveedor no está vinculado.", "details": [] } } // 404 propio
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox. Key `user_id` (colisión: `sub_hash`). Sin secretos ni `sub` plano en audit (hash).

* **Tópico:** `auth.federated.linked.v1` / `auth.federated.unlinked.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "federated.linked", "occurred_at": "2026-10-05T12:00:00Z", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "provider": "google", "sub_hash": "sha256:...", "request_id": "550e8400-..." } }
{ "event_id": "uuid", "event_type": "federated.unlinked", "occurred_at": "2026-10-05T12:00:00Z",
  "payload": { "user_id": "uuid", "provider": "google", "sub_hash": "sha256:...", "factors_left": 1 } }
```
* **Tópico:** `auth.security.federated_link_collision.v1` — **Key:** `sub_hash`
```json
{ "event_id": "uuid", "event_type": "security.federated_link_collision", "occurred_at": "2026-10-05T12:00:00Z",
  "payload": { "provider": "google", "sub_hash": "sha256:...", "requester_user_id": "uuid", "owner_user_id": "uuid", "ip_hash": "sha256:..." } }
```
* **Tópico:** `auth.audit.v1` — `{action:"federated.link|unlink|list", provider, sub_hash, result, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`.
