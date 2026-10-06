# Spec: CU-M2M-02 - Creación, Rotación y Revocación de Claves de API (API Keys)

## 1. Contexto y Propósito
Dar a desarrolladores credenciales delegadas longevas pero controladas: `ak_live_<id>.<secreto>` de una exhibición, validación directa por request (hash + Redis, sin JWT), rotación con solape 24h y revoke inmediato propagado. Cierra el Módulo 6 separando API-keys humanas (owner admin) de clients M2M-01 (servicios).

Decisiones (2026-10-05, todas Recommended):
- Q1 `ak_live_<8>.<43>` (regex escaneable) + `SHA-256+pepper` + 1 vez, Q2 Owner propio (sin delegar), Q3 Directa por request (sin JWT/sesión), Q4 Solape 24h con lineage + auto-revoke, Q5 Revoke inmediato + lista masked, Q6 TTL máx 1a / default 90d + purga (forense 30d), Q7 Tabla + puertos + `1000/min/key` + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Usuario Administrador (Bearer con permiso `apikeys:write` — scope nuevo, cierra la lista Q1 CU-AUTH-06 con 11 scopes), Microservicio Auth, Integradores (portan `X-API-Key`), Gateway (valida).
* **Precondiciones:**
  * Creador `ACTIVE` + Step-Up? Crear key delega poder duradero: exige Step-Up `apikeys:write` (fast-pass o token, igual que `roles:change` exige rigor; documentado).
  * Scopes ⊆ catálogo (si no → `400`); `exp` ≤1a (si no → `400`); `cidrs` válidas.

## 3. Flujo Principal (Happy Path)
### A. Crear
1. Admin envía `POST /api/v1/auth/api-keys {name, scopes[], expires_at?, cidrs[]}` + Bearer + Step-Up (`apikeys:write`) + `X-Request-ID`. Valida: `name 3..64` (único por owner), `scopes ⊆ catálogo` + ⊆ propios del creador (no puede delegar lo que no tiene — least-privilege transitivo; si pide de más → `403 DELEGATION_DENIED`), `expires_at` (default +90d, máx +1a; pasado → `400`), rate `apikeys:admin 20/min`.
2. Genera `prefix_id=8ch base62 CSPRNG` (reintenta colisión `UNIQUE`) + `secret=32B b64url` + `full=ak_live_<id>.<secret>`, guarda `prefix PK, secret_hash=SHA-256(secret+pepper), owner, name, scopes, cidrs, exp, lineage UUIDv7 (nuevo), created` + outbox (`apikey.created` + audit) en Tx. Retorna `201 {prefix, api_key (1 vez), expires_at, warning:"Guárdala. No la mostramos más."}`.
### B. Usar (por request, sin sesión)
3. Integrador envía `X-API-Key: <full>` (o `Authorization: ApiKey <full>`; si ambos → X-API-Key manda; sin ninguna → gateway `401` por su cuenta o delega a Auth verify endpoint). Gateway/Auth: parsea `prefix.secret` (malforma → `401 INVALID_API_KEY` sin lookup), rate `apikey:use:<prefix> 1000/min` (excede → `429`), lookup Redis `ak:<prefix>` (hit con `{hash,scopes,exp,revoked,owner}`) → fallback PG (`SELECT ... WHERE prefix`, miss → `401` + audit `no_key`).
4. Verifica `!revoked && now<exp` + `ConstantTime(hash entrante, stored)` (falla → `401` + `fails` (10/15min → auto-suspend 15min + email owner, paralelo M2M-01) + audit) + `CIDR` (si lista y fuera → `401` + audit `cidr`) + `scope` requerido de la ruta (el gateway compara `key.scopes ⊇ route.scope`; si no → `403 INSUFFICIENT_SCOPE` — único `403` con distinción, justificado: el portador autenticado con key válida merece saber qué le falta).
5. Actualiza `last_used=now` (debounce Redis `ak:touch:<prefix> EX 300`, flush async a PG cada toque válido dentro de debounce — documentado eventual ≤5min) + métrica `apikey_used_total` + audit muestreado (10% usos ok para no saturar bus; 100% fallos/revokes).
### C. Rotar / revocar / listar
6. Rotate: `POST /api-keys/:prefix/rotate` (owner, Step-Up) → crea sucesora (mismo `name/scopes/cidrs` heredados, `exp` nueva (default 90d desde ahora), `lineage` = lineage vieja, `prev_prefix` = vieja) + vieja queda válida 24h (`superseded_until=now+24h`, responde con ambas en `rotate`? No: la vieja ya la tiene; retorna solo NUEVA 1 vez + `old_valid_until`) + outbox (`rotated`) → worker auto-revoca vieja a las 24h (`revoked=rotated`, + evento). Lista muestra ambas con `superseded:true` en la vieja.
7. Revoke: `DELETE /api-keys/:prefix` (owner, Step-Up) → Tx `revoked=true` + Redis `DEL ak:<prefix>` + pub `apikey.revoked` (gateways purgan cache ~1s) + outbox + `200 revoked`. `GET /api-keys` (owner) → `[{prefix, name, scopes, exp, last_used, revoked, superseded}]` (nunca secreto).
8. Expirada: `now≥exp` → `401 EXPIRED_API_KEY` (distinto de `INVALID` para que el integrador rote, no reintente; justificado: el poseedor válido merece el hint) + worker purga `revoked/expired>30d` (forense 30d, luego `DELETE` metadata salvo audit).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación/autorización:** sin Bearer/inválido → `401`; sin `apikeys:write` → `403` (gestión) — distinto del `403 INSUFFICIENT_SCOPE` de uso (documentado); `name` duplicado propio → `409 KEY_NAME_TAKEN`; scopes ajenos → `403 DELEGATION_DENIED`; `exp`>1a → `400`; body >4KB → `413`.
* **4.2. Uso inválido (opaco salvo scope/exp):** `401 INVALID_API_KEY` único para miss/hash-malo/revoked/suspendido/CIDR-deny (mismo body/tiempo ±jitter; el `403 INSUFFICIENT_SCOPE` y `401 EXPIRED_API_KEY` son las únicas distinciones, ambas post-autenticación válida).
* **4.3. Infra:** PG down → `500` (gestión) / gateway `500` o `cached-allow`? No: sin PG y sin Redis-hit → `500` fail-closed (una key no verificable no abre; documentado fail-closed aquí — distinto del login fail-open, porque las keys son de alta potencia y el cache Redis 5min TTL cubre caídas cortas). Redis down → PG verdad + `WARN` + rehidrata (cache `ak:<prefix> EX 300` en cada uso válido). Kafka down → `200/201` + outbox pendiente (revoke se publica al recuperar; gateways con cache 300s pueden tardar ≤5min — documentado + pub/sub Redis compensa ~1s donde suscrito).
* **4.4. Rate:** `1000/min/key` uso + `20/min` gestión + suspend 10/15min por key (paralelo M2M-01) → `429/401` según caso.
* **4.5. Leak/scanning:** regex pública `ak_(live|test)_[A-Za-z0-9]{8}\.[A-Za-z0-9_-]{43}` documentada para pre-commit/scanners (contracts la publica); si un secret aparece en repo, el dueño revoca (flujo normal) + audit `revoked{reason:leak}` manual.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Formato `ak_(live|test)_<8>.<43>` (`test` para `ENV!=prod`, aceptado igual pero audit `env=test`). `prefix` PK global, `secret_hash` UNIQUE global (colisión imposible + garantizada).
* **RN-02:** 1 exhibición (el secreto plano existe solo en la response TLS de create/rotate; jamás en `GET`/logs/audit/DB).
* **RN-03:** Owner propio (sin crear para otro `user_id` en MVP). `name` único por owner. Delegación transitiva vetada (no puede dar lo que no tiene).
* **RN-04:** TTL `default 90d, máx 365d`; expirada → `401 EXPIRED` + purga metadata a los 30d (forense) + audit conserva.
* **RN-05:** Solape 24h exactas (`superseded_until`), auto-revoke worker (sin intervención), lineage trazable (`prev_prefix`, mismo `lineage`).
* **RN-06:** Revoke inmediato (PG + Redis DEL + pub ~1s + outbox). `last_used` eventual ≤5min (debounce, no crítico).
* **SEC-01:** `SHA-256(secret+pepper)` + `ConstantTime` + `APIKEY_PEPPER` (reuso `M2M_PEPPER` si ausente) + dummy si miss + jitter 20-50ms en `401` uso.
* **SEC-02:** Step-Up `apikeys:write` en create/rotate/revoke (scope 11º de CU-AUTH-06, añadido aquí como extensión documentada).
* **SEC-03:** Sin sesiones/families/JWT (bearer directo longevo; la revocación es por `revoked` + cache TTL 300s, no por expiración corta — el riesgo se compensa con scopes mínimos + exp ≤1a + rate/key + suspend).
* **SEC-04:** `X-API-Key` nunca en URL/logs (header; access-log lo enmascara igual que `Authorization`).

## 6. Requerimientos de Observabilidad
* **Métrica:** `apikey_total{op="create|use_ok|rotate|revoke|list", result}` + `apikey_use_total{result="ok|invalid|expired|insufficient|rate|suspended"}` + `apikey_suspend_total` + `apikey_redis_fallback_total`.
* **Trazabilidad:** Raíces `UseCase.ApiKey*` + `Gateway.VerifyApiKey` (hijos: `ratelimit`, `cache.lookup`, `db.key.*`, `crypto.compare`, `cidr/scope.check`, `touch`). Atributos `prefix` (público, no secreto).
* **Auditoría:** `auth.audit.v1 {action:"apikey.create|use|rotate|revoke|suspend", prefix, owner, result, trace_id}` (usos ok muestreados 10%) + eventos `apikey.*` (key `prefix`). Sin secreto (solo `hash_prefix(8)` DEBUG).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Crear + usar + lista sin secreto**
  * **Dado** admin con `apikeys:write` + Step-Up fresco.
  * **Cuando** `POST /api-keys {name:facts, scopes:[invoices:read]}` → `201` + `GET /api-keys` + `GET /recurso` con `X-API-Key`.
  * **Entonces** `201` trae `full` 1 vez (DB: solo hash; `GET` no la trae) + uso `200` gateway (scopes ok) + `last_used` ≤5min + `use_total{ok}` +1. `GET` lista `prefix/name/scopes/exp` sin secreto.
* **Escenario 2: Rotate solape + revoke inmediato**
  * **Dado** key K1 válida.
  * **Cuando** `POST /:K1/rotate` → nueva K2 + uso K1 y K2 en 12h + uso K1 en 25h + `DELETE /:K2`.
  * **Entonces** rotate `200` K2 1 vez + K1 y K2 válidas 12h (`rotating` audit) + K1 a las 25h `401` (auto-revoked) + `DELETE K2` → `401` inmediato (≤1s pub/sub, ≤5min cache) + email/lista actualizada.
* **Escenario 3: Scope/exp/CIDR + rate + suspend**
  * **Dado** key `read`-only con CIDR `10/8`, exp mañana.
  * **Cuando** ruta `write` + ruta tras exp + IP fuera + flood 1100/min + 10 secretos malos.
  * **Entonces** `write` → `403 INSUFFICIENT_SCOPE`; post-exp → `401 EXPIRED`; fuera CIDR → `401` opaco; flood → 1001º `429`; 10 malos → suspend 15min (buena también `401`) + email owner + unlock (rotate o espera) → `200`.
* **Escenario 4: Infra + leak-regex**
  * **Dado** PG-down / Redis-down / Kafka-down; secreto pegado en README de prueba.
  * **Cuando** uso/gestión + scanner regex.
  * **Entonces** PG-down sin cache → `500` fail-closed (con cache-hit 300s → `200` + `WARN`); Redis-down → PG verdad + `200`; Kafka-down → `200/201` + outbox pendiente (revoke ≤5min-cache); regex del contracts detecta el leak en CI (`audit_pii_scan` extendido).
