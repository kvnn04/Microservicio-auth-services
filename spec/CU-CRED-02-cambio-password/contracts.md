# Contratos de Integración: CU-CRED-02

## 1. Contrato HTTP (API REST)

* **Ruta:** `POST /api/v1/auth/password/change {current_password?, new_password}` (Bearer ACTIVE obligatorio; federated-set además `X-Step-Up-Token` o fast-pass ≤5min).
* **Rate-limit:** `pwdchange:user 5/hora` → `429 + Retry-After`. Body ≤8KB. `Cache-Control: no-store`.
* **Sesión:** mantiene `sid` actual (cookies intactas); revoca pares (otras mueren).

```bash
curl -X POST http://localhost:8080/api/v1/auth/password/change \
 -H "Authorization: Bearer <A>" -H "Content-Type: application/json" -H "X-Request-ID: <uuid>" \
 -d '{"current_password":"Vieja!2024","new_password":"Nu3va!Valida-2026"}'
# 200 { "success": true, "data": { "status": "password_changed", "sessions_revoked": 2 } }
# federated-set (sin hash): -H "X-Step-Up-Token: <scope cred:change-password>" -d '{"new_password":"..."}'
```

### Errores
```json
{ "success": false, "error": { "code": "INVALID_CURRENT", "message": "La clave actual no es correcta.", "details": [] } } // 401 + cuenta a lock
{ "success": false, "error": { "code": "PASSWORD_POLICY_FAILED", "message": "La nueva clave no cumple la política.", "details": [{"field":"new_password","reason":"TOO_SHORT"}] } } // 400
{ "success": false, "error": { "code": "PASSWORD_REUSED", "message": "Elige una clave distinta a la actual.", "details": [] } } // 400
{ "success": false, "error": { "code": "PASSWORD_IN_HISTORY", "message": "Ya usaste esa clave recientemente.", "details": [] } } // 400 + meta.n=5
{ "success": false, "error": { "code": "STEP_UP_REQUIRED", "message": "Confirma tu identidad.", "details": [] } } // 401 federated-set sin token
{ "success": false, "error": { "code": "RATE_LIMITED", "message": "Demasiadas solicitudes.", "details": [] } } // 429
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox en la Tx rotate. Sin claves/hashes. Key `user_id`.

* **Tópico:** `auth.password.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "password.changed", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "via": "change", "password_ver": 4, "request_id": "550e8400-..." } }
```
`via`: `change|set` (set=federated primera).
* **Tópico:** `auth.session.revoked_peers.v1` — `{user_id, kept_sid, kept_family, count, trace_id}`.
* **Tópico:** `auth.audit.v1` — `{action:"password.change", result:success|invalid_current|policy|reused|history|rate_limited, peers_revoked, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email `password_changed` (peers+IP/hora) vía worker.
