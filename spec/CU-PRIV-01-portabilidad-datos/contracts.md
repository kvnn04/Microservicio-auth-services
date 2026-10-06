# Contratos de Integración: CU-PRIV-01

## 1. Contrato HTTP (API REST)

* **Rutas (Bearer ACTIVE; `POST` + Step-Up `privacy:export`):**
  * `POST /api/v1/auth/privacy/export` → `202 {export_id, status:processing}`
  * `GET /api/v1/auth/privacy/export/:id` (status, owner) → `200 {status, ready_at?, expires_at?}`
  * `GET /api/v1/auth/privacy/export/:id/download` (owner) → ZIP (+ `410` expirado)
  * `DELETE /:id` (owner, adelanta purga) → `200 {destroyed:true}`
* **Rate-limit:** `export:user` lógico 1/30d (`429 EXPORT_TOO_SOON {next_available}`) + `export:ip 10/hora` → `429`. `Cache-Control: no-store`.

```bash
curl -X POST http://localhost:8080/api/v1/auth/privacy/export -H "Authorization: Bearer <fresh>" -H "X-Step-Up-Token: <privacy:export>"
# 202 { "success": true, "data": { "export_id": "uuid", "status": "processing" } }
curl http://localhost:8080/api/v1/auth/privacy/export/<id>/download -H "Authorization: Bearer <A>" -o yo.zip
# 200 application/zip (export.json + sessions.csv) | 404 | 410 { "code": "EXPORT_EXPIRED" }
```

### Bundle `export.json` (schema `privacy/v1`, sin secretos)
```json
{ "version": "privacy/v1", "exported_at": "...", "user": {"id": "uuid", "email": "user@example.com", "roles": ["user"]},
  "federated": [{"provider": "google", "linked_at": "..."}], "mfa": {"enabled": true, "backup_remaining": 7},
  "consents": [{"doc": "terms", "version": "v2026.10", "at": "..."}], "sessions_truncated": false }
```
`sessions.csv`: `sid,device_label,ip_masked,created_at,last_seen_at`. Sin `password_hash, secret_enc, backup_hash, token, ip, lat/lon`.

## 2. Eventos Asíncronos (Kafka)

Vía outbox en sus Tx. Sin contenido (solo `export_id/bytes`). Key `user_id`.

* **Tópico:** `auth.privacy.export.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "export.requested", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "export_id": "uuid" } }
{ "event_id": "uuid", "event_type": "export.ready", "occurred_at": "...",
  "payload": { "user_id": "uuid", "export_id": "uuid", "bytes": 123456, "expires_at": "...+24h" } }
{ "event_id": "uuid", "event_type": "export.downloaded", "occurred_at": "...",
  "payload": { "user_id": "uuid", "export_id": "uuid" } }
{ "event_id": "uuid", "event_type": "export.destroyed", "occurred_at": "...",
  "payload": { "user_id": "uuid", "export_id": "uuid", "reason": "expired|user" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"privacy.export_*", export_id, result, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email `export_ready` (24h, sin adjunto) vía worker.
