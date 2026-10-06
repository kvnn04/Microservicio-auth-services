# Contratos de Integración: CU-CRYP-02

## 1. Contrato HTTP (API REST)

* **Rutas admin (Bearer `admin` + Step-Up `crypto:rotate`):**
  * `POST /api/v1/auth/admin/keys/rotate {reason?}` → `202 {old_kid, new_kid, overlap_until}` (async <30s)
  * `GET /api/v1/auth/admin/keys` → `200 [{kid, alg, created_at, overlap_until, retired_at}]` (pubs NO aquí; las pubs están en JWKS)
* **Rate-limit:** `keys:rotate 5/hora/admin` → `429`. `Cache-Control: no-store`.
* **JWKS durante overlap:** `max-age=60` (vs 600 normal) + `ETag` nuevo + `keys:[nuevo, viejo]` (vuelta a simple tras retiro).

```bash
curl -X POST http://localhost:8080/api/v1/auth/admin/keys/rotate -H "Authorization: Bearer <admin>" -H "X-Step-Up-Token: <crypto:rotate>" -d '{"reason":"scheduled-90d"}'
# 202 { "success": true, "data": { "old_kid": "2026-10-a", "new_kid": "2026-10-b", "overlap_until": "...+1h" } }
# 409 { "code": "ROTATION_IN_PROGRESS" } | 401 STEP_UP | 429 | 500 { "code": "KEY_CUSTODY_UNAVAILABLE" }
```

## 2. Eventos Asíncronos (Kafka + Pub/Sub)

Vía outbox en sus Tx (+ pub/sub Redis `keys.*` <1s multi-instancia). Sin material privado (solo `kid`s). Key `new_kid`.

* **Tópico:** `auth.keys.v1` — **Key:** `new_kid`
```json
{ "event_id": "uuid", "event_type": "keys.rotated", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "old_kid": "2026-10-a", "new_kid": "2026-10-b", "overlap_until": "...+1h", "trigger": "cron|manual" } }
{ "event_id": "uuid", "event_type": "keys.retired", "occurred_at": "...",
  "payload": { "kid": "2026-10-a", "archived": true } }
{ "event_id": "uuid", "event_type": "keys.extended", "occurred_at": "...",
  "payload": { "kid": "2026-10-a", "overlap_until": "...+2h", "reason": "kid-unknown-gateways" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"keys.rotate|retire|extend", old_kid, new_kid, trigger, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. SMTP técnico (due-7d, rotated, retired) vía worker.
