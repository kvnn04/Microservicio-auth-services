# Contratos de Integración: CU-M2M-02

## 1. Contrato HTTP (API REST)

* **Gestión (Bearer owner + Step-Up `apikeys:write`):**
  * `POST /api/v1/auth/api-keys {name, scopes[], expires_at?, cidrs[]}` → `201 {prefix, api_key (1 vez)}`
  * `GET /api/v1/auth/api-keys` → `200 [{prefix, name, scopes, exp, last_used, revoked}]` (sin secreto)
  * `POST /api-keys/:prefix/rotate` → `200 {api_key (nueva, 1 vez), old_valid_until:+24h}`
  * `DELETE /api-keys/:prefix` → `200 {revoked:true}`
* **Uso (integrador → gateway/servicio):** `X-API-Key: <full>` (o `Authorization: ApiKey <full>`) por request → `200` negocio o `401/403/429`.
* **Rate-limit:** gestión `20/min`, uso `1000/min/key` → `429`. `Cache-Control: no-store`.

```bash
curl -X POST http://localhost:8080/api/v1/auth/api-keys -H "Authorization: Bearer <admin>" -H "X-Step-Up-Token: <apikeys:write>" -H "Content-Type: application/json" -d '{"name":"etl-nocturno","scopes":["invoices:read"],"cidrs":["10.0.0.0/8"]}'
# 201 { "success": true, "data": { "prefix": "ak_live_A1b2C3d4", "api_key": "ak_live_A1b2C3d4.<43ch> (1 vez)", "expires_at": "...+90d" } }
curl http://localhost:8080/api/v1/invoices -H "X-API-Key: ak_live_A1b2C3d4.<43ch>"
# 401 { "code": "INVALID_API_KEY" } | 401 { "code": "EXPIRED_API_KEY" } | 403 { "code": "INSUFFICIENT_SCOPE" }
```

### Regex pública (secret-scanning, pre-commit)
```
ak_(live|test)_[A-Za-z0-9]{8}\.[A-Za-z0-9_-]{43}
```

## 2. Eventos Asíncronos (Kafka + Pub/Sub)

Vía outbox en sus Tx (+ pub/sub Redis `apikey.revoked` ~1s). Sin `secreto` (solo `prefix`). Key `prefix`.

* **Tópico:** `auth.apikey.v1` — **Key:** `prefix`
```json
{ "event_id": "uuid", "event_type": "apikey.created", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "prefix": "ak_live_A1b2C3d4", "owner": "uuid", "scopes": ["invoices:read"], "exp": "...+90d" } }
{ "event_id": "uuid", "event_type": "apikey.rotated", "occurred_at": "...",
  "payload": { "prefix": "ak_live_Nueva123", "prev_prefix": "ak_live_Vieja456", "old_valid_until": "...+24h" } }
{ "event_id": "uuid", "event_type": "apikey.revoked", "occurred_at": "...",
  "payload": { "prefix": "ak_live_A1b2C3d4", "reason": "manual|rotated|expired|suspend" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"apikey.create|use|rotate|revoke|suspend", prefix, owner, result, trace_id}` (usos-ok 10%). Schemas BACKWARD, DLQ `auth.dlq.v1`. SMTP owner (suspend/rotated) vía worker.
