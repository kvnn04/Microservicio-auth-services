# Spec: CU-SEC-06 - Gestión de Roles y Alcances (RBAC / Scopes)

## 1. Contexto y Propósito
Cerrar el lazo que CU-AUTH-04 abrió (`roles[]` + `roles_ver` en el Access): catálogo mínimo (`user` default + `admin` + `support_readonly`), asignación solo-admin con bootstrap auditado, snapshot en Issue (Rotate preserva), y revoke-all inmediato ante cualquier cambio. Auth emite y los satélites enforzan por ruta. M2M queda en scopes directos (sin roles).

Decisiones (2026-10-05, todas Recommended):
- Q1 3 roles + scopes derivados versionados (`SCOPES_VER`), Q2 Admin + seed `SEED_ADMIN_EMAIL` (sin auto-promoción), Q3 Snapshot + preserva en Rotate, Q4 Todo cambio → revoke-all + `ver+1` + email, Q5 Emite/Enforzan (matriz recomendada), Q6 M2M scopes / humanos roles, Q7 Tablas + puertos + métricas/audit/eventos.

## 2. Actores y Precondiciones
* **Actores:** Admin (Bearer con `role=admin` + `scope admin:roles`), Usuario objetivo (ACTIVE), Microservicio Auth, Satélites/Gateway (enforzan).
* **Precondiciones:**
  * Bootstrap: si `user_roles` vacío de admins, `SEED_ADMIN_EMAIL` (env, una vez) puede auto-elevarse vía `POST /admin/bootstrap` con prueba posesión correo (link 15min, reuso CRED-reset pattern) + audit `bootstrap` (después se deshabilita con `BOOTSTRAP_ENABLED=false`).
  * Objetivo `ACTIVE` (si `DELETION_REQUESTED/ANONYMIZED` → `404/409` base, sin cambio).

## 3. Flujo Principal (Happy Path)
1. Admin envía `POST /api/v1/auth/admin/users/:id/roles {add?:["admin"], remove?:["support_readonly"]}` + Bearer admin + `X-Request-ID`. El back valida: llamante tiene `admin` + `admin:roles` (si no → `403 FORBIDDEN` genérico, sin distinguir qué le falta), `add/remove` ⊆ catálogo (si no → `400 UNKNOWN_ROLE`), no auto-degradarse el último admin (si `remove admin` a sí mismo y es el único admin → `400 LAST_ADMIN`; si hay otro admin → permitido + P1 audit).
2. Rate `admin:roles 20/min/admin` (anti-abuso privilegiado; excede → `429`).
3. En UNA Tx PG: `INSERT/DELETE user_roles(user_id, role, granted_by, granted_at)` (idempotente: `ON CONFLICT DO NOTHING` / `DELETE IF EXISTS`) + `UPDATE users SET roles_ver=ver+1` + `UPDATE families revoked ALL + DELETE sessions ALL` (revoke-all forzado, igual SES-02 pero `reason:roles_changed`) + `tokens_valid_after`? No global `valid_after` (mataría pre-tokens innecesariamente? El revoke-all de families+sessions ya mata lo que importa; los Access residuales ≤15min con `roles` viejos son el riesgo. Para cerrarlo: SÍ se bumpea `roles_ver` y el gateway DEBE chequear `roles_ver` contra cache (`roles_ver` por user cacheado 60s, igual `valid_after`). Decisión: bumpea AMBOS `roles_ver` y publica `roles.changed` para que gateways refresquen; los Access con `roles_ver` viejo se rechazan (`403 STALE_ROLES`, re-login). Documentado doble-capa.
4. Outbox (`roles.changed{added,removed,ver}` + `revoked_all{reason:roles_changed}` + audit `roles.grant|revoke` con `granted_by`) + Redis sweep (sess/fam + `roles:ver:<uid>` pub) + email al objetivo `Tus permisos cambiaron (roles: ...)`.
5. Retorna `200 {roles:[actuales], roles_ver:N}`. El objetivo re-loguea y recibe snapshot nuevo en Issue (`ScopeResolver(roles)→scopes+ver`); Rotate preserva el snapshot de su sesión (no re-resuelve) hasta el próximo login (tras revoke no hay sesión que preservar — todas murieron).
6. Satélites: en cada request verifican firma + `roles_ver` fresco (cache 60s o evento `roles.changed` pub/sub ~1s) + `scope` requerido de su ruta (matriz recomendada en contracts; cada servicio la adapta). Sin llamada a Auth por request (stateless + cache).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación/autorización:** sin Bearer/inválido → `401`; sin `admin`/`admin:roles` → `403 FORBIDDEN` (mismo body tenga o no la cuenta objetivo — sin oráculo); `role` desconocido → `400 UNKNOWN_ROLE`; auto-quitar último admin → `400 LAST_ADMIN`; objetivo inexistente/borrado → `404` (solo admins llegan aquí, sin oráculo externo).
* **4.2. Bootstrap:** `POST /admin/bootstrap {email}` (sin auth, rate 3/hora/IP, solo si `BOOTSTRAP_ENABLED=true` y 0 admins y email==SEED) → `202` opaco + link (si coincide) → `POST /bootstrap/confirm {token}` → `admin` + audit `bootstrap` + auto-deshabilita (`BOOTSTRAP_ENABLED` se ignora tras 1 admin). Fuera de condiciones → `202` opaco sin correo (igual reset-pattern).
* **4.3. Infra:** PG down → `500` (sin cambio parcial); Redis down → PG verdad + `WARN` (gateways usan PG-cache `roles_ver`, ventana igual ≤60s); Kafka down → `200` (outbox `roles.changed` pendiente; gateways siguen con snapshot viejo ≤60s-cache + evento al recuperar).
* **4.4. Rate:** `429 + Retry-After` (sin cambios).
* **4.5. M2M:** `client_credentials` con `scope` directo (CU-M2M-01) NO pasa por `user_roles` (tabla `m2m_clients` propia); el `ScopeResolver` comparte el catálogo de scopes (mismo `SCOPES_VER`) pero la asignación es por cliente, no rol. Sin `roles_ver` en M2M (solo `scope` + expiración corta).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Catálogo `user` (default al registro/federado, least-privilege: `read:me write:me`), `admin` (`*` + `admin:roles`), `support_readonly` (`read:users:support` masked, sin `write`, sin `admin:*`). `SCOPES_VER=1` (subir versión = migración config + re-Issue forzado vía `roles_ver` bump global? No global: solo nuevos Issues llevan nueva ver; viejos expiran en ≤15min/30d-rotate-preservado... Rotate preserva ver vieja hasta 90d — ventana larga con scopes viejos. Corrección: Rotate SÍ re-valida `roles_ver` (no los roles): si `roles_ver` actual ≠ snapshot, el rotate falla con `403 STALE_ROLES` (fuerza re-login). Documentado: Rotate preserva roles pero chequea versión.)
* **RN-02:** Solo `admin` con `admin:roles` asigna (ni siquiera `support_readonly` lee asignaciones ajenas salvo `GET /admin/users` con `support` scope — lectura soporte masked, documentada).
* **RN-03:** Todo cambio (add o remove) → revoke-all + `ver+1` + email (sin excepción upgrade). `LAST_ADMIN` protegido (siempre ≥1 admin).
* **RN-04:** Snapshot en Issue (`roles, scopes, ver`); Rotate preserva pero chequea `ver` (mismatch → `403` + re-login, sin auto-actualizar).
* **RN-05:** Gateway chequea `roles_ver` (cache 60s + pub/sub `roles.changed` ~1s). Ventana residual ≤60s con roles viejos (documentada; para `admin` revocado crítico existe `POST /admin/users/:id/revoke-now` = alias revoke-all inmediato + `valid_after` bump (cierra a ~0s) — incluido como acción del mismo endpoint con `?force=true`).
* **SEC-01:** Sin auto-promoción (el endpoint exige admin previo salvo bootstrap-único). `granted_by` obligatorio (trazabilidad quien-otorgó).
* **SEC-02:** `roles/scopes` en JWT son códigos (`admin`, `read:me`), sin PII. `roles_ver` entero monótono por user.
* **SEC-03:** Bootstrap un solo uso + link 15min + rate + auto-disable (no deja puerta trasera).

## 6. Requerimientos de Observabilidad
* **Métrica:** `role_changes_total{change="grant|revoke", role}` + `roles_ver_current` (gauge por user? No: cardinalidad — solo `roles_changed_total` + `stale_roles_rejections_total`) + `rbac_redis_fallback_total`.
* **Trazabilidad:** Raíces `UseCase.RoleChange`, `Guard.RolesVerCheck` (gateway-side doc) + `Issue.ResolveScopes`. Atributos `roles, ver`, nunca PII.
* **Auditoría:** `auth.audit.v1 {action:"roles.grant|revoke|bootstrap", target, roles, ver, granted_by, trace_id}` + eventos `roles.changed.v1` (key `user_id`) + `session.revoked_all{reason:roles_changed}`. Sin secretos.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Grant admin + revoke-all + snapshot nuevo**
  * **Dado** `U=user`, `A=admin`, `U` con 2 sesiones.
  * **Cuando** `POST /admin/users/U/roles {add:[support_readonly]}` con A.
  * **Entonces** `200 {roles:[user,support], ver+1}` + 0 sesiones U + Access viejos `403 STALE_ROLES` (gateway) + email U + `roles.changed` 1; re-login U → Access con `support` + `ver` nuevo; Rotate con Access viejo (si quedara) → `403` (no actualiza solo).
* **Escenario 2: Prohibiciones (último admin, sin permiso, rol raro)**
  * **Dado** único admin A; `S=support_readonly`; rol `super`.
  * **Cuando** A se quita `admin` / S intenta grant / grant `super` / grant a inexistente.
  * **Entonces** auto-quite → `400 LAST_ADMIN` (sigue admin); S → `403` (0 cambios); `super` → `400 UNKNOWN_ROLE`; inexistente → `404`. Ninguno revoca nada.
* **Escenario 3: Bootstrap + force + infra**
  * **Dado** 0 admins, `SEED_ADMIN_EMAIL=E`; Redis-down / Kafka-down.
  * **Cuando** `POST /bootstrap {E}` + confirm + `POST /roles?force=true`.
  * **Entonces** bootstrap `202` opaco + mail solo si E==SEED + confirm → `admin` + auto-disable (2º bootstrap → `202` sin correo); `force=true` además bumpea `valid_after` (cierre ~0s); Redis-down → `200` vía PG + `WARN`; Kafka-down → `200` + outbox pendiente (gateways ≤60s-cache).
