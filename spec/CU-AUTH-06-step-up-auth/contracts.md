# Contratos de Integración: CU-AUTH-06

## 1. Contrato HTTP (API REST)

* **Ruta nueva:** `POST /api/v1/auth/step-up/challenge {scope, password?, code?}` (Bearer obligatorio) → `200 {step_up_token}`
* **Consumo:** ops críticas exigen `Authorization: Bearer` + (`auth_time` fresco ≤300s O `X-Step-Up-Token: <jwt step-up scope=op>`). Sin ninguno → `401 STEP_UP_REQUIRED {meta:{scope,max_age:300}}`.
* **Rate-limit:** `step-up:challenge:<user> 10/min`, `step-up:ip 30/min` → `429 + Retry-After`. Body ≤4KB. `Cache-Control: no-store`.

### Challenge
```bash
curl -X POST http://localhost:8080/api/v1/auth/step-up/challenge \
 -H "Authorization: Bearer <stale>" -H "Content-Type: application/json" -H "X-Request-ID: <uuid>" \
 -d '{"scope":"cred:change-password","password":"...","code":"123456"}'
# 200 { "success": true, "data": { "step_up_token": "eyJ...", "scope": "cred:change-password", "expires_in": 300 } }
# 401 { "success": false, "error": { "code": "INVALID_STEP_UP", "message": "No pudimos confirmarte.", "details": [] } }
```
`scope` ∈ `cred:change-password|cred:change-email|mfa:disable|mfa:rotate|federated:link|federated:unlink|backup:regenerate|apikeys:write|account:delete|roles:change`. `password` exigido si `password_hash` existe; `code` (TOTP 6d o backup 10ch, se consume si backup) exigido si `mfa_enabled`; federated-only stale sin nada → `401 STEP_UP_REQUIRES_RELOGIN`.

### Uso en op crítica
```bash
curl -X POST http://localhost:8080/api/v1/auth/change-password \
 -H "Authorization: Bearer <stale>" -H "X-Step-Up-Token: <step-up scope=cred:change-password>" -H "Content-Type: application/json" \
 -d '{...op...}'
# sin token y stale -> 401 { "code": "STEP_UP_REQUIRED", "meta": {"scope":"cred:change-password","max_age":300} }
# replay -> 401 { "code": "STEP_UP_REUSED" } | otra scope -> 401 INVALID_STEP_UP
```
`step_up_token` payload: `{aud:"step-up", scope, sub, jti, iat, exp:+300s, auth_time}` header `{EdDSA,kid}`. Un uso (quema al verificar), 5min, una op, nunca en negocio (`aud` lo `401`).

## 2. Eventos Asíncronos (Kafka)

Vía outbox (challenge) + audit en guards. Sin `password/code/token` (solo `jti/scope`). Key `user_id`.

* **Tópico:** `auth.stepup.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "stepup.passed", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "scope": "cred:change-password", "jti": "uuid" } }
{ "event_id": "uuid", "event_type": "stepup.failed", "occurred_at": "...",
  "payload": { "user_id": "uuid", "scope": "cred:change-password" } }
{ "event_id": "uuid", "event_type": "stepup.reused", "occurred_at": "...",
  "payload": { "user_id": "uuid", "scope": "cred:change-password", "jti": "uuid" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"stepup.challenge|check", scope, result:fast_pass|issued|used|required|invalid|reused, jti?, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`.
