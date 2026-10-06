# Contratos de Integración: CU-SEC-07

## 1. Contrato HTTP (API REST)

* **Rutas nuevas (desafío y kill):**
  * `POST /api/v1/auth/device/verify {device_token?, code|token}` (sin Bearer; el challenge es la auth) → `200` sesión encadenada o `202` (si además MFA) o `401`
  * `GET|POST /api/v1/auth/device/kill?token=` (sin Bearer; el kill-token es la auth) → `200 killed|already_killed`
* **Injertos (sin rutas nuevas):** login/pless/federado con aparato nuevo responden `202 {status:"device_challenge", ...}` (no-MFA) o `202 mfa_required` (MFA, idéntico normal) además de sus `200` habituales.
* **Rate-limit:** `device:send 5/hora/user`, `device:verify:tok 5/min`, `kill:ip 30/min` → `429`. `Cache-Control: no-store`.

```bash
curl -X POST http://localhost:8080/api/v1/auth/device/verify -H "Content-Type: application/json" -d '{"code":"87654321"}'
# 200 { "success": true, "data": { "status": "active", ...cookies... } } (encadenado, sin re-login)
curl "http://localhost:8080/api/v1/auth/device/kill?token=<43ch>"
# 200 { "success": true, "data": { "status": "killed" } } | already_killed | 400
# 202 device_challenge: { "success": true, "data": { "status": "device_challenge", "message": "Revisa tu correo." } }
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox en sus Tx. Sin `fp/hmac/token` completos (solo `prefix(8)`+label). Key `user_id`.

* **Tópico:** `auth.device.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "device.unknown", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "fp_prefix": "a1b2c3d4", "label": "Chrome · Windows" } }
{ "event_id": "uuid", "event_type": "device.trusted", "occurred_at": "...",
  "payload": { "user_id": "uuid", "fp_prefix": "a1b2c3d4", "label": "Chrome · Windows", "via": "mfa|email" } }
{ "event_id": "uuid", "event_type": "device.killed", "occurred_at": "...",
  "payload": { "user_id": "uuid", "sid": "uuid", "fp_prefix": "a1b2c3d4" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"device.check|challenge|trusted|kill", fp_prefix, label, result, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Triple-SMTP (challenge-10min / MFA-nuevo / sesión-con-kill-24h) vía worker siempre.
