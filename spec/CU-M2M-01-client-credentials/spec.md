# Spec: CU-M2M-01 - Autenticación de Servicios Desatendidos (Client Credentials Grant)

## 1. Contexto y Propósito
Dar identidad a máquinas (daemons, satélites, terceros) vía OAuth2 Client Credentials: `client_id` prefijado + secreto 32B (hash-only) → Access JWT 5min con `aud` target y scopes ⊆ otorgados, sin Refresh (re-auth revalida). Abre el Módulo 6 con least-privilege, CIDR opcional y suspend anti-fuerza. Stateless puro (sin `sid/family/sesiones`).

Decisiones (2026-10-05, todas Recommended):
- Q1 Admin + seed, `svc_<slug>`, 1 exhibición + `SHA-256+pepper` + rotación solape 24h, Q2 Access 5min `aud` target sin `sid/family`, sin refresh, Q3 `POST /oauth2/token` Basic+body + opaco (dummy si id malo), Q4 Subset estricto (vacío=default mínimo), Q5 CIDR check en emisión + audit (gateway-futuro), Q6 10 fails/15min → suspend 15min + `401` opaco + unlock admin, Q7 Tabla + puertos + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Servicio Cliente (daemon con `id/secret` en vault), Microservicio Auth, Admin (provisiona).
* **Precondiciones:**
  * `m2m_clients(client_id PK `svc_*`, secret_hash, scopes[], cidrs[], status=active, created)` provisionado (admin/seed) + secreto vigente (no expirado/rotado-fuera-solape).
  * Scopes pedidos ⊆ catálogo `SCOPES_VER` (si no → `400` en emisión, no en provision).

## 3. Flujo Principal (Happy Path)
### A. Provision (una vez por cliente)
1. Admin envía `POST /api/v1/auth/admin/m2m/clients {slug, scopes[], cidrs[], description}` + Bearer admin (`admin` + `admin:m2m` scope — nuevo scope admin, documentado en matriz SEC-06 como extensión) + `X-Request-ID`. Valida `slug^[a-z0-9-]{3,32}` (→ `client_id=svc_<slug>`), `scopes` ⊆ catálogo M2M permitido (si no → `400 UNKNOWN_SCOPE`), `cidrs` válidas (si no → `400 INVALID_CIDR`), rate `admin:m2m 20/min`.
2. Genera `secret=32B CSPRNG b64url 43ch`, guarda `secret_hash=hex(SHA-256(secret+pepper))` (pepper `M2M_PEPPER` reuso `PASSWORD_PEPPER` si no hay propio) + `prev_hash=NULL` + `status=active` + outbox (`m2m.client_created` + audit `granted_by`) en Tx. Retorna `201 {client_id, client_secret (1 vez), scopes, cidrs}` (el secreto NUNCA se re-emite; si se pierde → rotación CU-M2M-02/rotación aquí con solape: `POST /admin/m2m/clients/:id/rotate` → nuevo secret + `prev_hash`=viejo válido 24h + outbox).
### B. Token (cada 5min por cliente)
3. Daemon envía `POST /api/v1/auth/oauth2/token` `Content-Type: application/x-www-form-urlencoded` con `grant_type=client_credentials&scope=<espaciados>&audience=<svc>` + auth `Authorization: Basic base64(id:secret)` (primario) o `client_id+client_secret` en body (fallback; si ambos → Basic manda; si ninguno → `401` sin lookup).
4. El back valida forma (`grant_type` exacto, `audience` en allowlist `M2M_AUDIENCES`, `scope` parseado; malforma → `400 INVALID_REQUEST`, sin contar fails cliente).
5. Rate `m2m:token:ip 30/min` + `m2m:token:client 10/min` (excede → `429`, sin contar fails). Lookup `m2m_clients(id)` (miss → dummy `SHA-256` + delay 20-50ms + `401 INVALID_CLIENT` opaco + audit `no_client`, sin revelar; SIN fails a cuenta inexistente salvo bucket ciego anti-flood).
6. Chequea `status==active` (si `suspended` por fails o admin → `401` opaco igual, + audit `suspended`; NO `423`) + `ConstantTimeCompare(hash entrante, stored)` (y `prev_hash` en ventana solape 24h post-rotate → acepta + header `Warning: rotating` + métrica). Si falla → `RecordFail(client)` (INCR `m2m:fails:<id> EX 900`; a 10 → `status=suspended, suspended_until=+15min` + email técnico + `suspend_total` +1) + `401 INVALID_CLIENT` opaco (mismo body/tiempo que miss/suspendido/CIDR-fail).
7. Chequea CIDR (si `cidrs` non-empty y `ip∉cidrs` → `401` opaco + audit `cidr_deny`, sin distinguir) + scopes (`pedidos ⊆ granted`? si no → `400 INVALID_SCOPE` con `details` (aquí SÍ se distingue: el cliente autenticado con secreto válido merece saber qué scope le falta; si el secreto era malo ya falló en 6 con `401` — no hay oráculo porque el `400` exige secreto OK)).
8. Emite Access JWT `Ed25519` (mismo signer): `header{EdDSA,kid}` + `payload{iss, aud=<audience>, sub=<client_id>, azp=<client_id>, scope="<intersección>", client=true, iat, exp=+300s, jti}` (sin `sid/family/amr/roles`; `scope_ver=SCOPES_VER`). Sin Refresh, sin cookie, sin sesión (no toca `sessions/families`). Outbox `mfa?` No: `m2m.token_issued` + audit. Retorna `200 {access_token, token_type:Bearer, expires_in:300, scope}` (`no-store`).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** `grant_type` distinto, `audience` fuera de allowlist, `scope` malformado, body >4KB → `400 INVALID_REQUEST/SCOPE` (sin fails). `client_id` sin prefijo `svc_` → `400` en provision (en token, miss → `401` opaco).
* **4.2. Auth fallida (opaca):** id inexistente, secret malo, suspendido (fails o admin), CIDR-deny → `401 {code:INVALID_CLIENT, message:"Cliente inválido."}` idéntico (mismo body + delay 20-50ms en miss/suspend/CIDR para no filtrar por tiempo; el secreto-malo ya paga `SHA-256` real). 10º fail/15min → suspend 15min + 1 email técnico (throttle 1/hora por cliente).
* **4.3. Infra:** PG down → `500` (sin token); Redis down → PG verdad + fail-open rate local + `WARN` (fails a PG? No: fails efímeros se pierden sin Redis — ventana aceptada + alerta si >5min); KMS/clave ausente → `500` fail-fast (nunca `none`); Kafka down → `200` + outbox pendiente.
* **4.4. Rate:** `429 + Retry-After` (sin fails). Sin locks de cuenta humana (esto es cliente; el suspend es por `client_id`, no por IP).
* **4.5. Rotación:** `prev_hash` válido 24h post-rotate (ambos aceptan; el viejo emite con `Warning` + `rotating=true` en audit para migrar daemons sin caída). Tras 24h el viejo → `401` (como malo). Unlock suspend: `POST /admin/m2m/clients/:id/unlock` (admin) o auto-expira (status vuelve `active`, `fails` reseteados, `suspend_count` conserva día para escalar? No escala: siempre 15min (daemons legítimos con secret viejo no deben sufrir backoff largo; documentado).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** `client_id=svc_[a-z0-9-]{3,32}` único global (no colisiona con `user_id` UUID — namespaces separados; el `sub` JWT distingue por `client:true`).
* **RN-02:** Secreto 32B, `SHA-256+pepper` + `ConstantTime`, 1 exhibición, rotación solape 24h (`prev_hash`), suspend 10/15min + unlock admin/auto.
* **RN-03:** Access 300s, `aud` obligatorio de allowlist (rechaza `aud` libre; multi-aud con espacios si el cliente los pide y todos permitidos), `scope` = intersección pedida∩granted (vacío pedido → default mínimo del cliente `default_scopes[0:1]`, documentado), sin Refresh/sesión/family.
* **RN-04:** CIDR allowlist opcional (`[]`=any); check en emisión + `ip_hash` en audit; claim sin `cnf` en MVP (gateway-futuro documentado).
* **RN-05:** Least-privilege provision (scopes mínimos + justificación `description` obligatoria + `granted_by`; revisión trimestral documentada como proceso, no código).
* **SEC-01:** `client_secret` solo vault del daemon + TLS (nunca URL/logs: Basic va en header, también sensible — el access-log debe enmascarar `Authorization` (documentado `mask_auth_log=true`)).
* **SEC-02:** Sin `sid/family` (stateless; la revocación es por `suspend` + expiración 5min + `kid` rotation; no hay logout M2M — el daemon descarta el token).
* **SEC-03:** `azp` = `sub` (confirma intención), `client:true` (satélites distinguen humano/máquina sin tabla).

## 6. Requerimientos de Observabilidad
* **Métrica:** `m2m_token_total{result="ok|invalid_client|suspended|invalid_scope|cidr_deny|rate_limited|error", aud}` + `m2m_issue_duration_seconds` + `m2m_suspend_total` + `m2m rotating_use_total` (viejo en solape).
* **Trazabilidad:** Raíz `UseCase.M2MToken` (hijos: `ratelimit`, `db.client.lookup`, `crypto.compare`, `cidr.check`, `scope.check`, `crypto.sign`, `outbox.insert`). Atributos `client_id, aud`, nunca secreto.
* **Auditoría:** `auth.audit.v1 {action:"m2m.token|provision|rotate|suspend", client_id, aud, scope, result, ip_hash, trace_id}` + eventos `m2m.client_created|token_issued|suspended` (key `client_id`). Sin secreto (solo `hash_prefix(8)` en DEBUG).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Provision + token + scopes subset**
  * **Dado** admin crea `svc-facturas` con `scopes=[invoices:read]` + `cidrs=[10.0.0.0/8]`, secret 1 vez.
  * **Cuando** daemon `POST /token` Basic OK `scope=invoices:read` `audience=billing` desde `10.1.2.3`.
  * **Entonces** `200` Access verificable (`aud=billing`, `sub=svc-facturas`, `exp-iat=300`, `scope` exacto, sin `sid`) + `m2m_token_total{ok}` +1; `scope=invoices:write` → `400 INVALID_SCOPE`; `audience=otro-no-permitido` → `400`; DB guarda solo hash (inspección: sin secreto).
* **Escenario 2: Opacos (id-malo/secret-malo/suspendido/CIDR) + suspend**
  * **Dado** 4 casos: id inexistente, secret malo ×10, suspendido, IP fuera CIDR.
  * **Cuando** `POST /token` cada uno.
  * **Entonces** 4× `401 INVALID_CLIENT` idénticos (p50 ±25ms, sin `423`); tras 10º malo → `suspended 15min` + 1 email (11º con bueno también `401` hasta expirar; unlock admin o espera → `200`). `prev_hash` en solape → `200` + `Warning`.
* **Escenario 3: Sin refresh + nativo + infra**
  * **Dado** token M2M en satélite; `POST /refresh` con Access M2M; PG/Redis/KMS down.
  * **Cuando** satélite valida 5min/6min + refresh + chaos.
  * **Entonces** ≤5min `200` satélite, >5min `401` (re-auth, sin refresh que valga); `/refresh` con M2M → `401` (no es Refresh); PG-down → `500` (0 tokens); Redis-down → `200` vía PG + `WARN`; sin clave → `500` (0 `none`).
