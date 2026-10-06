# Spec: CU-SES-01 - Cierre de Sesión Individual (Logout)

## 1. Contexto y Propósito
Matar el par actual (`sid`) a pedido: revoca Refresh family + borra sesión + denylistea el `jti` del Access hasta su expiración natural, y ordena limpiar cookies. Las demás sesiones viven (global en SES-02, selectiva en SES-03). Sin Step-Up (autodefensa, no mutación ajena), idempotente y rápido.

Decisiones (2026-10-05, todas Recommended):
- Q1 `POST /logout` con Bearer (firma válida, sin frescura/Step-Up), Q2 Solo actual (family+sess+jti), Q3 `200 already_logged_out` idempotente si revocado-no-expirado (`401` si inválido/expirado; Refresh posterior `401` revoked-no-robo), Q4 Clear-Cookie + drop-Access, Q5 Sin Step-Up + rate 30/min/user, Q6 Redis denylist corto + PG durable, Q7 Métricas/audit/eventos sin PII.

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado (Bearer con `sid+jti`, vigente o recién-revocado-no-expirado), Microservicio Auth.
* **Precondiciones:**
  * Access verifica firma/`iss/aud`/`kid` (gateway-style) aunque esté revocado; `exp` debe ser futuro para identificar `sid` (expirado → `401`, no hay nada que matar que el tiempo no haya matado).
  * Rate `logout:user 30/min` + `logout:ip 60/min` libre.

## 3. Flujo Principal (Happy Path)
1. Cliente envía `POST /api/v1/auth/logout` + `Authorization: Bearer <Access actual>` (+ `X-Request-ID`; refresh cookie/body OPCIONAL — si viene se usa para localizar family exacta, si no se deriva de `sid`).
2. El back valida JWT (firma Ed25519 `kid`, `iss/aud`, `exp>now`, `sub/sid/jti` presentes; NO exige `auth_time` fresco, NO exige Step-Up, NO exige `valid_after`/denylist para entrar — el logout debe funcionar aunque el token esté en denylist por logout previo (idempotencia) o el user tenga `valid_after` nuevo por otra op (el logout del sid viejo debe limpiar igual)).
3. Rate-check (si excede → `429`, sin revocar).
4. En UNA Tx PG + write-through Redis: `UPDATE refresh_families SET revoked=true WHERE family=(SELECT family FROM sessions WHERE sid=$sid AND user_id=$sub)` (si 0 filas → ya muerto → `already_logged_out`, igual `200`) + `DELETE sessions WHERE sid` + `INSERT outbox(session.logged_out)` + audit. Redis: `DEL sess:<sid> + DEL fam:<family>` + `SET jti:<jti> revoked EX=max(1, exp-now)` (denylist corta ≤15min).
5. Retorna `200 {status:logged_out}` (o `{status:already_logged_out}` si ya estaba, mismo `200`) + `Set-Cookie: refresh_token=; Max-Age=0; Path=/api/v1/auth/refresh; HttpOnly; Secure; SameSite=Lax` + `Cache-Control: no-store`. El front DEBE borrar Access de memoria y redirigir a login (contracts lo norman); nativo borra keystore ambos.
6. Efecto: Access actual → gateways lo rechazan por denylist `jti` hasta `exp` (≤15min); Refresh actual → `POST /refresh` da `401 FAMILY_REVOKED` (SES-04 lo distingue de robo: revoked-por-logout no dispara alarma global, solo `401` + audit).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** sin Bearer/malformado/firma mala/`kid` desconocido/`aud/iss` malos/`exp` pasado/`sid/jti` ausentes → `401 UNAUTHORIZED` (estándar, sin revocar nada). Body irrelevante (se ignora; ≤4KB).
* **4.2. Ya revocado (idempotencia):** firma OK + `exp` futuro + `sid` sin `sessions` ni `family` viva (ya logout, o evicted LRU, o SES-02/03 lo mató) → `200 {status:already_logged_out}` (mismo Clear-Cookie). No es error ni cuenta como fallo.
* **4.3. Infra:** PG down → `500` (sin Clear-Cookie mentiroso? Sí se envía Clear-Cookie igual? No: si no revocó en PG, limpiar cookie local sin revocar servidor dejaría Refresh vivo en PG pero sin cookie — en web es logout efectivo local pero Refresh huérfano 30d. Decisión: si PG falla → `500` SIN Clear-Cookie (el cliente reintenta; no finge). Redis down → PG verdad + `WARN` (denylist `jti` se guarda en PG `revoked_jtis` fallback con `exp`; gateway lo lee si Redis miss — documentado) + `200` igual. Kafka down → `200` igual (outbox pendiente).
* **4.4. Rate:** `429 + Retry-After` (sin revocar). Sin locks de cuenta (logout no autentica secreto, no alimenta brute-force).
* **4.5. Refresh huérfano:** si el cliente perdió el Access pero conserva Refresh cookie (ej. Access en memoria voló), `POST /logout` sin Bearer no puede identificar `sid` → `401`; debe llamar `POST /refresh` (falla?) No: el camino es `DELETE /sessions/current`? No existe. Documentado: el front guarda `sid` en `localStorage` no-sensible (solo `sid`, no tokens) para logout sin Access? Alternativa aceptada: `POST /logout` acepta `{refresh_token}` en body como identificador alternativo (lo hashea y localiza family→sid→revoca). Implementación vinculante en plan (soporta ambos identificadores).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Solo `sid` del Bearer (o del Refresh alternativo). Nunca `valid_after` global, nunca otras `sid` (SES-02/03).
* **RN-02:** Sin Step-Up ni frescura (el poseedor del Access puede matarlo; robar Access 15min para desloguear a la víctima es DoS menor sin robo de datos — aceptado; el Refresh no se expone en logout salvo optativo).
* **RN-03:** Denylist `jti EX=exp-now` (1..900s) + `families revoked` + `sessions DEL` (triple capa: gateway-corto, refresh-duro, sesión).
* **RN-04:** Idempotencia: mismo Access revocado-no-expirado → `200 already`; RequestID 24h replay → mismo `200` sin doble-outbox (dedup por `jti` + idempotency).
* **RN-05:** Clear-Cookie con MISMO `Path/Domain/SameSite` que Issue (si no coincide el navegador no la borra — test e2e lo verifica).
* **SEC-01:** `jti/sid/family` en denylist/DB, nunca Access/Refresh plano en logs/eventos/audit (solo `jti/sid`).
* **SEC-02:** Logout no revela otras `sid` (lista en SES-03, no aquí). `already` no distingue si lo mató SES-01/02/03/evicción (mismo `200`).
* **SEC-03:** `POST` (no `GET`) anti-CSRF por método + `Authorization` header (no cookie sola) — el navegador no puede ser engañado a desloguear por `<img>` (el front SPA lo llama con Bearer explícito).

## 6. Requerimientos de Observabilidad
* **Métrica:** `logout_total{result="ok|already|invalid|rate_limited|error"}` + `logout_duration_seconds` + `logout_denylist_size_gauge` (aprox `DBSIZE jti:*` muestreado).
* **Trazabilidad:** Raíz `UseCase.Logout` (hijos: `jwt.verify`, `ratelimit`, `db.session.revoke (Tx)`, `cache.revoke+denylist`, `outbox.insert`). Atributos `sid`, nunca tokens.
* **Auditoría:** `auth.audit.v1 {action:"session.logout", user_id, sid, family, jti, result:ok|already, trace_id}` + evento `session.logged_out.v1` (key `user_id`). Sin tokens.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Logout mata par actual, resto vive**
  * **Dado** 2 sesiones (A actual, B), ambas vivas.
  * **Cuando** `POST /logout` con Access A.
  * **Entonces** `200 logged_out` + Clear-Cookie + `sessions` sin A (B intacta) + `families(A)` revoked + `jti(A)` denylisteado (gateway mock rechaza A pero acepta B) + Refresh A en `/refresh` → `401 FAMILY_REVOKED` (no alarma robo) + `logout_total{ok}` +1. Access A reusado en API → `401` hasta `exp`.
* **Escenario 2: Idempotente + sin Bearer alternativo**
  * **Dado** A ya logout (no expirado).
  * **Cuando** repite `POST /logout` mismo Access, y `POST /logout` sin Bearer con `{refresh_token:A}` (si lo guardó), y `POST /logout` sin nada.
  * **Entonces** replay → `200 already_logged_out`; con Refresh → `200` (revoca por family igualmente); sin nada → `401`. Refresh A tras todo → `401` siempre.
* **Escenario 3: Expirado/inválido + rate + PG-down**
  * **Dado** Access expirado hace 1h, firma mala, flood 40/min/user, PG down.
  * **Cuando** logout cada caso.
  * **Entonces** expirado/malo → `401` (0 cambios); flood → 31º `429`; PG-down → `500` SIN Clear-Cookie (reintentable) + 0 filas tocadas. Redis-down → `200` vía PG-fallback + `WARN`.
