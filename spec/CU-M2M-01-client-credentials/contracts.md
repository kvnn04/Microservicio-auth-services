# Contratos de Integración: CU-M2M-01

## 1. Contrato HTTP (API REST)

* **Provision (admin `admin` + `admin:m2m`):**
  * `POST /api/v1/auth/admin/m2m/clients {slug, scopes[], cidrs[], tech_email, description}` → `201 {client_id, client_secret (1 vez), scopes, cidrs}`
  * `POST /:id/rotate` → `200 {client_secret (nuevo, 1 vez)}` (viejo 24h) | `POST /:id/unlock` → `200`
* **Token (sin Bearer; Basic o body):**
  * `POST /api/v1/auth/oauth2/token` `Content-Type: application/x-www-form-urlencoded` + (`Authorization: Basic base64(id:secret)` o `client_id+client_secret` body) + `grant_type=client_credentials&scope=<sp>&audience=<svc>` → `200`
* **Rate-limit:** `admin:m2m 20/min`, `m2m:token:ip 30/min`, `:client 10/min` → `429`. `Cache-Control: no-store`. Access-log enmascara `Authorization`.

```bash
curl -X POST http://localhost:8080/api/v1/auth/oauth2/token -H "Content-Type: application/x-www-form-urlencoded" \
  -u "svc-facturas:<secret>" -d "grant_type=client_credentials&scope=invoices%3Aread&audience=billing"
# 200 { "access_token": "eyJ...", "token_type": "Bearer", "expires_in": 300, "scope": "invoices:read" }
# 401 { "success": false, "error": { "code": "INVALID_CLIENT", "message": "Cliente inválido.", "details": [] } }
# 400 { "code": "INVALID_SCOPE" } | 429
```

### Access M2M (Ed25519, 5min, sin Refresh/sesión)
```json
{ "iss": "https://auth.example.com", "aud": "billing", "sub": "svc-facturas", "azp": "svc-facturas",
  "scope": "invoices:read", "scope_ver": 1, "client": true, "iat": 1720000000, "exp": 1720000300, "jti": "uuid" }
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox en sus Tx. Sin `secret` (solo `hash_prefix(8)` en DEBUG). Key `client_id`.

* **Tópico:** `auth.m2m.v1` — **Key:** `client_id`
```json
{ "event_id": "uuid", "event_type": "m2m.client_created", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "client_id": "svc-facturas", "scopes": ["invoices:read"], "granted_by": "uuid" } }
{ "event_id": "uuid", "event_type": "m2m.token_issued", "occurred_at": "...",
  "payload": { "client_id": "svc-facturas", "aud": "billing", "scope": "invoices:read", "rotating": false } }
{ "event_id": "uuid", "event_type": "m2m.suspended", "occurred_at": "...",
  "payload": { "client_id": "svc-facturas", "until": "...+15min" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"m2m.token|provision|rotate|suspend", client_id, aud?, result, ip_hash, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. SMTP técnico (suspend/rotated) vía worker.
