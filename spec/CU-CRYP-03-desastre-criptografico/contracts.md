# Contratos de Integración: CU-CRYP-03

## 1. Contrato HTTP (API REST)

* **Rutas admin rojo (Bearer `admin` + Step-Up `crypto:emergency`):**
  * `POST /api/v1/auth/admin/keys/emergency-revoke {kid, confirm:"REVOKE <kid>", reason, dry_run?}` → `202 {epoch, retired_kid, successor_kid}`
  * `GET /api/v1/auth/admin/keys/emergency/status` → `200 {epoch, emergency_active, sweep:{done,total}}`
* **Rate-limit:** global `1/hora` (no por admin) → `429 DOUBLE_FIRE` + P1. `Cache-Control: no-store`.
* **Verificadores post-fuego (todos):** `iat<epoch` → `401 {code:EMERGENCY_RELOGIN, message:"Re-autentícate (incidente de seguridad)."}` (banner front; única excepción opaco, justificada masiva).

```bash
curl -X POST http://localhost:8080/api/v1/auth/admin/keys/emergency-revoke -H "Authorization: Bearer <admin>" -H "X-Step-Up-Token: <crypto:emergency>" -d '{"kid":"2026-10-b","confirm":"REVOKE 2026-10-b","reason":"HSM tamper alert","dry_run":false}'
# 202 { "success": true, "data": { "status": "emergency_accepted", "epoch": "2026-10-05T12:00:00Z", "retired_kid": "2026-10-b", "successor_kid": "2026-10-c" } }
# 400 { "code": "CONFIRM_MISMATCH" } | 404 | 409 { "code": "ALREADY_RETIRED" } | 429 { "code": "DOUBLE_FIRE" } | 503 { "code": "DISABLED" }
```

## 2. Eventos Asíncronos (Kafka + Pub/Sub + Bulk)

Vía outbox en sus Tx (+ pub/sub Redis <1s + bulk-mail 10k/min). Sin material (solo `kid`s). Key `kid`/epoch.

* **Tópico:** `auth.keys.emergency.v1` — **Key:** `kid`
```json
{ "event_id": "uuid", "event_type": "keys.emergency", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "retired_kid": "2026-10-b", "successor_kid": "2026-10-c", "epoch": "2026-10-05T12:00:00Z",
    "dry_run": false, "admin": "uuid" } }
```
Más `crypto.epoch_bumped`, `session.revoked_all{reason:key_compromise}` (batched), `auth.audit.v1 {action:keys.emergency_revoke|drill}` P1. Schemas BACKWARD, DLQ `auth.dlq.v1`. Bulk `emergency_relogin` (sin links sesión) + pager P1 vía worker. Runbook `docs/key-emergency-runbook.md` (1 página).
