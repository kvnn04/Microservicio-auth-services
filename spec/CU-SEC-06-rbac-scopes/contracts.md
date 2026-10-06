# Contratos de Integración: CU-SEC-06

## 1. Contrato HTTP (API REST)

* **Rutas admin (Bearer con `admin` + `admin:roles`, salvo bootstrap):**
  * `POST /api/v1/auth/admin/users/:id/roles {add?:[], remove?:[]} ?force=false` → `200 {roles, roles_ver}`
  * `POST /api/v1/auth/admin/bootstrap {email}` (sin auth, solo si 0 admins + enabled) → `202` opaco
  * `POST /api/v1/auth/admin/bootstrap/confirm {token}` → `200 {admin:true}`
* **Rate-limit:** `admin:roles 20/min/admin` → `429`. `Cache-Control: no-store`.
* **Gateway (recomendado satélites):** verificar firma + `aud/iss/exp` + `roles_ver` fresco (cache 60s + sub `roles.changed`) + `scope` de ruta (ej. `GET /admin/*` → `admin`, `GET /support/*` → `support_readonly|admin`). `roles_ver` viejo → `403 STALE_ROLES` (re-login).

```bash
curl -X POST http://localhost:8080/api/v1/auth/admin/users/<uuid>/roles -H "Authorization: Bearer <admin>" -H "Content-Type: application/json" -d '{"add":["support_readonly"]}'
# 200 { "success": true, "data": { "roles": ["user","support_readonly"], "roles_ver": 4 } }
# 403 { "code": "FORBIDDEN" } | 400 { "code": "UNKNOWN_ROLE|LAST_ADMIN" } | 404
```

### Access con RBAC (reuso CU-AUTH-04 + `roles_ver`)
```json
{ "sub": "uuid", "roles": ["user","support_readonly"], "scope": "openid profile api read:me write:me read:users:support",
  "roles_ver": 4, "scope_ver": 1 }
```

## 2. Eventos Asíncronos (Kafka + Pub/Sub)

Vía outbox en la Tx change. Key `user_id`.

* **Tópico:** `auth.roles.changed.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "roles.changed", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "added": ["support_readonly"], "removed": [], "roles": ["user","support_readonly"],
    "roles_ver": 4, "granted_by": "uuid", "force": false } }
```
Más `session.revoked_all{reason:roles_changed}` + `auth.audit.v1 {action:roles.grant|revoke|bootstrap}` + pub/sub Redis `roles.changed` (~1s). Schemas BACKWARD, DLQ `auth.dlq.v1`. Email `roles_changed` (roles nuevos) vía worker siempre.
