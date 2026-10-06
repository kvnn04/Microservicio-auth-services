# Contratos de Integración: CU-AUTH-03

## 1. Contrato HTTP (API REST)

* **Rutas (reuso + 1 nueva):**
  * `POST /api/v1/auth/mfa/verify` (reuso CU-AUTH-02; acepta TOTP o backup) — SIN Bearer, con `mfa_token`
  * `POST /api/v1/auth/mfa/backup-codes/regenerate` (nueva; Bearer ACTIVE + Step-Up 5min) → `200` 10 nuevos 1 vez
  * `GET /api/v1/auth/mfa/status` (reuso; añade `backup_remaining/warning`)
* **Rate-limit:** reuso `mfa:verify:*` (sin bucket que distinga) + `backup:regen 10/hora/user` → `429`.
* **Exhibición única:** planos solo en `enable` (CU-AUTH-02) y `regenerate` responses TLS. Nunca en `status`/emails/logs.

### Verify con backup (mismo endpoint)
```json
// request (alias backup_code o code 10ch autodetectado):
{ "mfa_token": "<jwt aud=mfa-challenge>", "backup_code": "K7Q2-M9XD4P" }
// 200 { "success": true, "data": { "status": "active", "message": "Sesión iniciada.", "backup_remaining": 9, "backup_warning": false } } + cookies
// 401 { "success": false, "error": { "code": "INVALID_MFA", "message": "Código inválido o expirado.", "details": [] } }
```
Mismo `401` para TOTP-malo/backup-miss/reusado/agotado/quemado. Con `remaining<=2` el `200` trae `"backup_warning":true`; con `0` tras consumir el último trae `"backup_exhausted":true`.

### Regenerate / Status
```bash
curl -X POST http://localhost:8080/api/v1/auth/mfa/backup-codes/regenerate -H "Authorization: Bearer <fresh>"
# 200 { "success": true, "data": { "backup_codes": ["...10 una vez..."], "remaining": 10 } }
curl http://localhost:8080/api/v1/auth/mfa/status -H "Authorization: Bearer <valid>"
# 200 { "success": true, "data": { "enabled": true, "methods": ["totp"], "backup_remaining": 9, "backup_warning": false } }
```
Stale regenerate → `401 STEP_UP_REQUIRED`. Sin valores planos en status.

## 2. Eventos Asíncronos (Kafka)

Vía outbox. Sin `backup_code` plano (solo `code_hash_prefix(8)`). Key `user_id`.

* **Tópico:** `auth.backup.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "backup.generated", "occurred_at": "...", "payload": { "user_id": "uuid", "count": 10 } }
{ "event_id": "uuid", "event_type": "backup.consumed", "occurred_at": "...", "payload": { "user_id": "uuid", "code_hash_prefix": "a1b2c3d4", "remaining": 9, "challenge_id": "uuid" } }
{ "event_id": "uuid", "event_type": "backup.regenerated", "occurred_at": "...", "payload": { "user_id": "uuid", "count": 10, "superseded": 7 } }
{ "event_id": "uuid", "event_type": "backup.failed", "occurred_at": "...", "payload": { "user_id": "uuid", "reason": "invalid|replay|exhausted" } }
```
Más `mfa.verified{method:"backup"}` en `auth.mfa.v1` (reuso CU-AUTH-02).
* **Tópico:** `auth.audit.v1` — `{action:"backup.generate|consume|regenerate", result, remaining?, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email alta prioridad `backup_consumed` (con `remaining`, IP/device, links regenerate/asegura) siempre vía worker SMTP.
