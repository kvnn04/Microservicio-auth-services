# Contratos de Integración: CU-PRIV-02

## 1. Contrato HTTP (API REST)

* **Rutas (Bearer ACTIVE, sin Step-Up):**
  * `GET /api/v1/auth/privacy/consents` → `200 {consents:[...]}` (estados + versiones + `revocable` + `text_url`)
  * `PUT /api/v1/auth/privacy/consents/:purpose {status:granted|revoked}` → `200`
* **Rate-limit:** `consents:user 30/min` → `429`. `Cache-Control: no-store`.

```bash
curl http://localhost:8080/api/v1/auth/privacy/consents -H "Authorization: Bearer <A>"
# 200 { "success": true, "data": { "consents": [
#   {"purpose":"terms","essential":true,"revocable":false,"status":"granted","version":"v2026.10","text_url":"..."},
#   {"purpose":"marketing","essential":false,"revocable":true,"status":"revoked","version":"v2026.10","text_url":"..."}, ... ] } }
curl -X PUT http://localhost:8080/api/v1/auth/privacy/consents/marketing -H "Authorization: Bearer <A>" -d '{"status":"granted"}'
# 200 { "success": true, "data": { "purpose": "marketing", "status": "granted", "version": "v2026.10" } }
# 400 { "code": "ESSENTIAL_CONSENT", "message": "Para retirar esto elimina tu cuenta.", "deletion_url": "/api/v1/auth/account/deletion/request" }
# 404 { "code": "UNKNOWN_PURPOSE" }
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox en su Tx. Sin texto legal (solo `purpose/status/version`). Key `user_id`.

* **Tópico:** `auth.consent.changed.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "consent.changed", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "purpose": "marketing", "status": "revoked", "version": "v2026.10" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"consent.set", purpose, status, version, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Satélites suspenden/reanudan al recibir (sin ACK). Email `profiling_off` informativo (1 vez/revoke) vía worker.
