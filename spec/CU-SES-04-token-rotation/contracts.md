# Contratos de Integración: CU-SES-04

## 1. Contrato HTTP (API REST)

* **Ruta:** `POST /api/v1/auth/refresh` (Refresh en cookie `refresh_token` o body `{refresh_token}`; sin Bearer).
* **Rate-limit:** `refresh:ip 30/min`, `refresh:fam 10/min` → `429 + Retry-After`. Body ≤4KB. `Cache-Control: no-store`.
* **Respuesta feliz:** `200 {access_token, expires_in:900, sid}` + `Set-Cookie: refresh_token=<nuevo>; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/refresh; Max-Age=<restante>` (MISMO Path que Issue).

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh -H "X-Request-ID: <uuid>" --cookie "refresh_token=<R3>"
# 200 { "success": true, "data": { "status": "rotated", "access_token": "eyJ...", "expires_in": 900, "sid": "..." } }
# 409 { "success": false, "error": { "code": "CONCURRENT_ROTATION", "message": "Reintenta con el nuevo token.", "details": [] } }
# 401 INVALID_REFRESH | SESSION_EXPIRED | FAMILY_REVOKED | SESSION_COMPROMISED (ver abajo)
```

### Errores
```json
{ "success": false, "error": { "code": "CONCURRENT_ROTATION", "message": "Reintenta con el nuevo token.", "details": [] } } // 409 race legítimo (re-lee jar + 1 reintento)
{ "success": false, "error": { "code": "SESSION_COMPROMISED", "message": "Detectamos uso indebido. Cerramos todo por seguridad.", "details": [] } } // 401 reuso (global + P1 + email)
{ "success": false, "error": { "code": "SESSION_EXPIRED", "message": "Sesión expirada. Inicia sesión de nuevo.", "details": [] } } // 401 absolute/sliding
{ "success": false, "error": { "code": "FAMILY_REVOKED", "message": "Sesión cerrada. Inicia sesión de nuevo.", "details": [] } } // 401 logout
{ "success": false, "error": { "code": "INVALID_REFRESH", "message": "Sesión inválida.", "details": [] } } // 401 miss
```

### Algoritmo cliente ante `409` (normativo)
```js
// 1. Re-lee el jar (el ganador rotó la cookie si ya volvió).
// 2. Espera 200ms. 3. Reintenta POST /refresh UNA vez con lo que haya en el jar.
// 4. Si otro 409 o 401 COMPROMISED -> muestra login + banner (no loop).
```

## 2. Eventos Asíncronos (Kafka)

Vía outbox en la Tx (rotate o global). Sin Refresh plano (solo `hash_prefix(8)`). Key `user_id`.

* **Tópico:** `auth.session.rotated.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "session.rotated", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "sid": "uuid", "family": "uuid", "counter": 4 } }
```
* **Tópico:** `auth.session.reuse_detected.v1` (P1) — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "session.reuse_detected", "occurred_at": "...",
  "payload": { "user_id": "uuid", "family": "uuid", "counter_presented": 3, "counter_current": 5,
    "device_presented": "sha256:...", "device_current": "sha256:..." } }
```
Más `session.revoked_all{reason:reuse_detected}` (reuso SES-02) y `auth.audit.v1 {action:session.rotate|reuse, ...}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email crítico (ambos devices/horas + `cambia tu clave`) + pager P1 vía worker.
