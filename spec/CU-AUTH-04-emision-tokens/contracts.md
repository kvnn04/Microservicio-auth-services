# Contratos de Integración: CU-AUTH-04

## 1. Contrato HTTP (API REST)

> **Sin rutas nuevas.** Issue es interno; el transporte se observa en `POST /login`, `POST /mfa/verify`, `GET /federated/*/callback` (los tres delegan aquí). Este contrato fija el formato entregado.

* **Web (defecto):** `200 {access_token, token_type:Bearer, expires_in:900, sid}` + `Set-Cookie: refresh_token=<43ch>; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/refresh; Max-Age=2592000` (+ `__Host-` si estricto). Access NUNCA en cookie.
* **Nativo (`X-Client-Type: native`):** `200 {access_token, refresh_token, token_type, expires_in, sid}` sin `Set-Cookie`.
* **Headers:** `Cache-Control: no-store` siempre. Nunca tokens en URL/query/logs.

### Access JWT (Ed25519, 15min)
```json
// header
{ "alg": "EdDSA", "kid": "2026-10-a", "typ": "JWT" }
// payload (claims mínimos)
{ "iss": "https://auth.example.com", "aud": "api", "sub": "uuid", "sid": "uuid", "jti": "uuid",
  "iat": 1720000000, "exp": 1720000900, "auth_time": 1720000000,
  "amr": ["pwd"], "scope": "openid profile api", "roles": ["user"], "roles_ver": 3, "token_ver": 1 }
```
`amr` ejemplos: `["pwd"]`, `["pwd","totp"]`, `["pwd","backup"]`, `["federated_google"]`. Verificación gateway: firma `kid` (JWKS CU-CRYP-01) + `iss/aud/exp` + `iat≥tokens_valid_after` + `jti∉denylist`.

### Refresh opaco
`refresh_token`: `43ch base64url (32B)`; en DB solo `SHA-256 hex`. `family UUIDv7`, `counter 0`, `expires_at +30d`, `absolute_exp +90d`. Solo `POST /api/v1/auth/refresh` (CU-SES-04).

```bash
# web
curl -i -X POST http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"...","password":"..."}'
# HTTP/1.1 200 + Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/refresh
# {"success":true,"data":{"status":"active","access_token":"eyJ...","expires_in":900,"sid":"..."}}
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox en la Tx Issue. Sin tokens (solo `jti/family` + hashes). Key `user_id`.

* **Tópico:** `auth.session.issued.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "session.issued", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "sid": "uuid", "family": "uuid", "jti": "uuid", "kid": "2026-10-a",
    "method": "password", "amr": ["pwd"], "device_hash": "sha256:...", "expires_at": "..." } }
```
* **Tópico:** `auth.audit.v1` — `{action:"session.issue", user_id, sid, family, jti, amr, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Gateway/consumidores usan JWKS (CU-CRYP-01), nunca llaman a Auth por request (stateless).
