# Contratos de Integración: CU-SEC-04

## 1. Contrato HTTP (API REST)

* **Ruta nueva (lectura propia):** `GET /api/v1/auth/audit/me?cursor=<occurred_at,id>&limit=20` (Bearer ACTIVE, sin Step-Up).
* **Rate-limit:** `audit:me 60/min/user` → `429`. `Cache-Control: no-store`. `limit` clamp `1..100` (default 20); `cursor` vacío = primera página.
* **Escritura:** sin endpoint (los eventos nacen en las Tx negocio; esta es la única lectura).

```bash
curl "http://localhost:8080/api/v1/auth/audit/me?limit=20" -H "Authorization: Bearer <A>"
# 200 { "success": true, "data": { "events": [
#   {"event_id":"...","occurred_at":"...","action":"login.attempt","result":"success",
#    "device":"Chrome · Windows (a1b2c3d4)","data":{"method":"password"}} ], "next_cursor": "2026-10-05T12:00:00Z,0193..." } }
# 400 { "code": "INVALID_CURSOR" } | 401 | 429 | 500
```
`events` masked: sin `trace_id` completo? Sí lo lleva parcial? No: `me` incluye `trace_id` (útil soporte) pero sin `ip/hash/token/coords` (solo `device` label + `data` sanitizada). `next_cursor=null` = fin.

### Envelope `auth.audit.v1` v2 (bus + PG, BACKWARD con v1 por campo `v:2`)
```json
{ "event_id": "uuidv7", "v": 2, "occurred_at": "...", "received_at": "...",
  "actor": {"user_id": "uuid-or-null", "device_hash": "sha256:8"}, "action": "login.attempt",
  "result": "success", "trace_id": "...", "request_id": "...",
  "data": {"method": "password"}, "prev_hash": "hex", "hash": "hex" }
```

## 2. Eventos Asíncronos (Kafka)

* **Tópico:** `auth.audit.v1` (retención 1a, sin compactar) — envelope v2 (arriba) para TODAS las acciones (migra v1 con traductor 1 release). Key `actor.user_id` o `account_hash`.
* **Tópico (meta):** `auth.audit.ops.v1` — `chain_verified{month,events,ok}`, `audit_gap`, `audit_purged{month}` (key `month`). Schemas BACKWARD-compat (v1→v2), DLQ `auth.dlq.v1`. Sin SMTP propio (cada dominio envía sus avisos; el audit solo archiva).
