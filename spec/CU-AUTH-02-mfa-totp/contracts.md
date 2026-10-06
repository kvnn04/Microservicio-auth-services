# Contratos de Integración: CU-AUTH-02

## 1. Contrato HTTP (API REST)

* **Rutas:**
  * `POST /api/v1/auth/mfa/totp/setup` (Bearer ACTIVE + Step-Up 5min) → `200 {secret, otpauth, qr}`
  * `POST /api/v1/auth/mfa/totp/enable {code}` (misma sesión fresca) → `200 {enabled + backup_codes}`
  * `POST /api/v1/auth/mfa/verify {mfa_token, code}` (SIN Bearer; el pre-token es auth) → `200 active` + cookies
  * `DELETE /api/v1/auth/mfa/totp` (Bearer + Step-Up) → `200 disabled`
  * `GET /api/v1/auth/mfa/status` (Bearer normal) → `200 {enabled}`
* **Rate-limit:** `mfa:setup 10/hora/user`, `mfa:verify:challenge 5/min`, `mfa:verify:ip 20/min` → `429 + Retry-After`. Body ≤4KB.
* **Cookies:** Solo `verify-ok` setea sesión (CU-AUTH-04). `setup/enable` no cambian sesión.

### Setup / Enable
```bash
curl -X POST http://localhost:8080/api/v1/auth/mfa/totp/setup -H "Authorization: Bearer <fresh>" -H "X-Request-ID: <uuid>"
# 200 { "success": true, "data": { "secret_b32": "JBSW... (solo esta vez)", "otpauth_url": "otpauth://totp/Example:user@example.com?secret=...&issuer=Example&algorithm=SHA1&digits=6&period=30", "qr_svg": "<svg...>", "expires_in": 600 } }
curl -X POST http://localhost:8080/api/v1/auth/mfa/totp/enable -H "Authorization: Bearer <fresh>" -H "Content-Type: application/json" -d '{"code":"123456"}'
# 200 { "success": true, "data": { "status": "enabled", "backup_codes": ["...10 una vez..."] } }
```

### Verify / Disable / Status
```json
// POST /mfa/verify
{ "mfa_token": "<jwt aud=mfa-challenge 5min>", "code": "123456" }
// 200 { "success": true, "data": { "status": "active", "message": "Sesión iniciada." } } + cookies
// 401 { "success": false, "error": { "code": "INVALID_MFA", "message": "Código inválido o expirado.", "details": [] } }
```
Mismo `401 INVALID_MFA` para challenge expirado/quemado/código malo/replay/aud erróneo. `DELETE /totp` → `200 {status:disabled}` o `400 LAST_AUTH_FACTOR` / `401 STEP_UP_REQUIRED`. `GET /status` → `200 {enabled:true, methods:["totp"]}`.

## 2. Eventos Asíncronos (Kafka)

Vía outbox. Sin `secreto/código/mfa_token` (solo `challenge_id/counter`). Key `user_id`.

* **Tópico:** `auth.mfa.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "mfa.enabled", "occurred_at": "...", "payload": { "user_id": "uuid", "method": "totp" } }
{ "event_id": "uuid", "event_type": "mfa.verified", "occurred_at": "...", "payload": { "user_id": "uuid", "challenge_id": "uuid", "counter": 12345678 } }
{ "event_id": "uuid", "event_type": "mfa.failed", "occurred_at": "...", "payload": { "user_id": "uuid", "challenge_id": "uuid", "fails": 3 } }
{ "event_id": "uuid", "event_type": "mfa.replay_blocked", "occurred_at": "...", "payload": { "user_id": "uuid", "counter": 12345678 } }
{ "event_id": "uuid", "event_type": "mfa.disabled", "occurred_at": "...", "payload": { "user_id": "uuid" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"mfa.setup|enable|verify|disable", result, challenge_id?, counter?, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Emails `MFA activado/desactivado` siempre + `bloqueo MFA` throttle vía worker.
