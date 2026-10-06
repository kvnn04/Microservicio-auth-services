# Contratos de Integración: CU-REG-04

## 1. Contrato HTTP (API REST)

* **Rutas:**
  * `GET /api/v1/auth/federated/{provider}/authorize?return_to=/app` → `302` al IdP (MVP `provider=google`, otro → `404 PROVIDER_NOT_SUPPORTED`)
  * `GET /api/v1/auth/federated/{provider}/callback?code=<authcode>&state=<state>[&error=access_denied]` → JSON (no redirect con tokens)
* **Autenticación requerida:** Ninguna (si trae Bearer válido → `400 USE_LINK_FLOW`, debe usar CU-REG-06). `X-Request-ID` recomendado (idempotencia callback 24h).
* **Headers:** `Cookie: fed_state=<state>` (seteada por authorize, `HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`), respuesta `Cache-Control: no-store`, `Set-Cookie` sesión solo si `active` (formato CU-AUTH-04).
* **Rate-limit:** `fed_authz:ip` 20/min, `fed_cb:ip` 10/min, `fed_cb:state` 5/min → `429 + Retry-After`.

### Authorize
```bash
curl -i "http://localhost:8080/api/v1/auth/federated/google/authorize?return_to=/app"
# 302 Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=https%3A%2F%2Fapi%2Fcallback&response_type=code&scope=openid%20email%20profile&state=...64hex&nonce=...64hex&code_challenge=...&code_challenge_method=S256
# Set-Cookie: fed_state=...64hex; HttpOnly; Secure; SameSite=Lax; Max-Age=600
```

### Callback — éxito
```json
// verified=true, email nuevo
{ "success": true, "data": { "status": "active", "provider": "google", "message": "Cuenta creada con Google. Sesión iniciada." } }
// + Set-Cookie: access/refresh (CU-AUTH-04)
// verified=false, email nuevo
{ "success": true, "data": { "status": "pending_verification", "provider": "google", "message": "Verifica tu correo para activar." } }
// sub ya vinculado
{ "success": true, "data": { "status": "active", "provider": "google", "message": "Sesión iniciada con Google." } }
```

### Errores
```json
{ "success": false, "error": { "code": "INVALID_FEDERATED_STATE", "message": "Flujo inválido o expirado. Inicia de nuevo.", "details": [] } } // 400 state/nonce/PKCE/replay
{ "success": false, "error": { "code": "INVALID_FEDERATED_CODE", "message": "No pudimos validarte con Google.", "details": [] } } // 400 code/cancelled
{ "success": false, "error": { "code": "INVALID_ID_TOKEN", "message": "No pudimos validarte con Google.", "details": [] } } // 401 firma/claims/nonce
{ "success": false, "error": { "code": "PROVIDER_NOT_SUPPORTED", "message": "Proveedor no soportado.", "details": [] } } // 404
{ "success": false, "error": { "code": "ACCOUNT_LINK_REQUIRED", "message": "Esta dirección ya tiene cuenta. Inicia sesión para vincular.", "details": [] } } // 409 colisión (sin revelar previo)
{ "success": false, "error": { "code": "IDP_UNAVAILABLE", "message": "Google no responde. Intenta en unos segundos.", "details": [] } } // 502 + Retry-After: 5
{ "success": false, "error": { "code": "RATE_LIMITED", "message": "Demasiadas solicitudes.", "details": [] } } // 429
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox/worker. Sin `code/tokens IdP` ni email plano salvo mailer. Key `user_id` (o `email_hash` en colisión).

* **Tópico:** `auth.federated.registered.v1` — **Key:** `user_id`
```json
{
  "event_id": "uuid", "event_type": "federated.registered",
  "occurred_at": "2026-10-05T12:00:00Z", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "provider": "google", "sub_hash": "sha256:...", "email_hash": "sha256:...", "email_domain": "example.com", "email_verified_by_idp": true, "status": "active", "request_id": "550e8400-..." }
}
```
* **Tópico:** `auth.user.activated.v1` (solo si `verified=true`) + `auth.email.verification_requested.v1` (solo si `pending`) — mismos schemas CU-REG-01/02.
* **Tópico:** `auth.security.federated_collision.v1` — **Key:** `email_hash`
```json
{
  "event_id": "uuid", "event_type": "security.federated_collision",
  "occurred_at": "2026-10-05T12:00:00Z",
  "payload": { "email_hash": "sha256:...", "provider": "google", "sub_hash": "sha256:...", "existing_user_id": "uuid", "ip_hash": "sha256:...", "action": "notify_owner_require_link" }
}
```
* **Tópico:** `auth.audit.v1`
```json
{
  "event_id": "uuid", "event_type": "audit.federated",
  "occurred_at": "2026-10-05T12:00:00Z",
  "payload": { "action": "federated.register", "provider": "google", "sub_hash": "sha256:...", "email_hash": "sha256:...", "result": "active|pending|linked_login|link_required|cancelled|invalid|idp_unavailable", "trace_id": "4bf92f...", "request_id": "550e8400-..." }
}
```
Schemas BACKWARD, DLQ `auth.dlq.v1`.
