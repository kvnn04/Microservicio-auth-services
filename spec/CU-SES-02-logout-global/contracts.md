# Contratos de Integración: CU-SES-02

## 1. Contrato HTTP (API REST)

* **Ruta:** `POST /api/v1/auth/logout-global` (Bearer, cualquier edad; sin Step-Up).
* **Rate-limit:** `logout-global:user 5/hora`, `:ip 20/hora` → `429 + Retry-After`. `Cache-Control: no-store`.
* **Cookies:** Clear-Cookie refresh actual (MISMO Path). Otras mueren server-side.

```bash
curl -X POST http://localhost:8080/api/v1/auth/logout-global -H "Authorization: Bearer <A>" -H "X-Request-ID: <uuid>"
# 200 { "success": true, "data": { "status": "logged_out_global", "sessions_revoked": 3 } } + Clear-Cookie
# 401 / 429 / 500 estándar
```

## 2. Eventos Asíncronos (Kafka + Pub/Sub)

Vía outbox (durable) + `PUBLISH auth.session.revoked_all` (inmediato). Sin tokens. Key `user_id`.

* **Tópico:** `auth.session.revoked_all.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "session.revoked_all", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "sessions": 3, "families": 3, "valid_after": "2026-10-05T12:00:00Z", "reason": "user_request" } }
```
`reason`: `user_request|reuse_detected` (SES-04 invoca mismo efecto con otro audit).
* **Tópico:** `auth.audit.v1` — `{action:"session.logout_global", user_id, sessions, families, valid_after, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email `global_logout` (N+hora/IP) vía worker. Gateways: `iat<valid_after → 401` (cache 60s) + invalidación ~1s por pub/sub.
