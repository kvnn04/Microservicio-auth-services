# Spec: CU-SEC-02 - Control de Tasa de Peticiones (Rate Limiting y Throttling)

## 1. Contexto y Propósito
Topar el tráfico por IP/ruta (y cuenta donde aplique) con ventana deslizante exacta, headers estándar y fail-open. Cubre a TODOS los endpoints (matriz única fuente de verdad que absorbe los buckets definidos en CUs previos sin cambiar sus valores) y se separa de CU-SEC-01 (cuenta/credencial). Sin este CU, un barrido o DoS barato degradaría login/registro.

Decisiones (2026-10-05, todas Recommended):
- Q1 Matriz única (hereda valores previos), Q2 Sliding Lua ZSET exacto, Q3 IETF `RateLimit-*` en 200/429 + `Retry-After` en 429 + body uniforme, Q4 Fail-open local 2x + WARN, Q5 IP por RemoteAddr salvo `TRUSTED_PROXIES` para XFF, Q6 `/healthz|/metrics` exentos, Q7 Middleware+puerto central + config hot-reload + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Cliente de Red (legítimo o flooder), Microservicio Auth, Redis.
* **Precondiciones:**
  * `TRUSTED_PROXIES` configurado (CIDRs env; default `127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`).
  * Matrix cargada (config `ratelimit.yaml` o env; hot-reload `SIGHUP` o poll 30s; si config inválida → conserva última válida + `ERROR`).

## 3. Flujo Principal (Happy Path)
1. Cada request (salvo exentos) pasa el middleware rate ANTES de auth/lógica (fail-fast barato): resuelve `clientIP` (RemoteAddr; si `peer ∈ TRUSTED_PROXIES` y `X-Forwarded-For` presente → primer XFF válido) + `routeKey` (método+ruta template, ej. `POST /api/v1/auth/login`, no path con IDs crudos) + `accountKey` si la regla lo exige (`sha256(email)` o `sub` cuando identificable sin auth? Sin auth solo IP; con Bearer se añade scope cuenta).
2. Ejecuta Lua `sliding_allow.lua` (1 round-trip): `ZREMRANGEBYSCORE key 0 (now-window)` → `ZCARD` → si `count<limit` → `ZADD now` + `EXPIRE window*2` → `allow:true, remaining, reset` sino `allow:false, retryAfter=(oldest+window-now)`. Clave `rl:<route>:<scope>:<id>` con TTL auto.
3. Si `allow` → inyecta `RateLimit-Limit/Remaining/Reset` y continúa (el handler NO re-chequea; el servicio no implementa buckets propios — llama al puerto solo en tests).
4. Si `deny` → corta con `429 {code:RATE_LIMITED}` + `Retry-After: <s>` + mismos `RateLimit-*` (`Remaining:0`) + audit `rate_limited` + métrica (sin tocar lógica/DB). El `429` de tráfico SÍ lleva `Retry-After` (a diferencia del lock-cuenta SEC-01 que nunca lo lleva — split observable y documentado).

## 4. Flujos Alternativos y Excepciones
* **4.1. Matriz (vinculante, hereda CUs previos; ventana = 60s salvo indicado):**
  | Ruta | Scope | Límite | Notas |
  |---|---|---|---|
  | `POST /register` | IP 10/min; email_hash 3/hora | heredado REG-01/03 | + progresivo IP 50×429→block 15min (REG-03) |
  | `POST /login` | IP 10/min; account 5/min | AUTH-01 + fails SEC-01 aparte | lock-cuenta NO da 429 |
  | `POST /verify-email`, `/resend-verification` | IP 10/min; tok 5/min | REG-02 | resend + 3/hora email |
  | `POST /password/reset/*`, `/passwordless/*` | IP 10/hora; email 3/hora | CRED-01/AUTH-05 (emisoras correo, más duras) | quota send aparte |
  | `POST /mfa/verify`, `/step-up/challenge` | challenge 5/min; IP 20-30/min | AUTH-02/06 | queman challenge, no solo 429 |
  | `GET /federated/*/authorize|callback`, `/link*` | 20/min IP; 10/min IP cb | REG-04/06 | state 5/min aparte |
  | `POST /refresh` | IP 30/min; fam 10/min | SES-04 | sin Bearer |
  | `POST /logout*` | user 30/min; global 5/hora | SES-01/02 | global dura |
  | `GET /sessions`, `/linked`, `/mfa/status` | 60/min user | lecturas | generosas |
  | `GET /legal/active`, `/.well-known/jwks.json` | 60-100/min IP | públicas cacheables | + `Cache-Control` |
  | `GET /healthz`, `/metrics` | exentos | Q6 | nunca 429 |
  Cambiar un valor = enmendar ESTA tabla (los CUs previos la referencian; no se duplican números).
* **4.2. Redis down:** fail-open memoria por instancia (`map[key][]{timestamps}` cap 2×límite, purga lazy) + `WARN` + `rate_redis_fallback_total` + headers `RateLimit-*: degraded`? No: mismos headers (el front no distingue; solo logs/métricas internas). Al volver, Redis manda (la memoria local se abandona, acepta sub-conteo transitorio).
* **4.3. Reloj/skew:** usa `TIME` Redis (no local) en Lua para no bifurcar por skew entre réplicas (documentado).
* **4.4. XFF spoof:** XFF ignorado salvo peer confiable (Q5); `X-Real-IP` nunca (solo XFF tras proxy). IPv6 normalizada (minúsculas, sin zona).
* **4.5. Progresivos:** `announcer:ip` (cuenta 429s; 50/15min → `blocked:ip EX 900` que responde `429` largo a TODO auth salvo healthz) + `blocked` bypass? No hay bypass (ni admin local) en MVP.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Rate = tráfico (IP/ruta, y cuenta como scope anti-barrido por email), Brute (SEC-01) = credencial (fails/lock). Un `429` es tráfico; un lock es `401` opaco. Nunca se mezclan códigos.
* **RN-02:** Ventana deslizante exacta (ZSET), 1 Lua atómica, TTL `2×window`. Sin fixed-window (ráfaga borde vetada).
* **RN-03:** Headers IETF siempre (`Limit/Remaining/Reset` en 200 y 429; `Retry-After` solo 429). Body `429` único `RATE_LIMITED` (sin `route` en body — el front ya sabe la ruta; evita fingerprint extra).
* **RN-04:** Exentos solo `healthz/metrics` (ni siquiera admin-key en MVP). Todo lo demás limitado (incluido JWKS público, generoso).
* **RN-05:** Config hot-reload sin restart (última-válida si la nueva falla parse). Cambios de matriz llevan `config_version` en `/metrics` (gauge) + audit `ratelimit.reloaded`.
* **SEC-01:** Claves `rl:<route>:<scope>:<idhash>` (`idhash=ip` cruda en key operativa + `/24`-hash en logs; `email→sha256`). Sin PII en keys persistentes salvo IP operativa TTL-corta (documentado base legítima anti-abuso, retención = TTL).
* **SEC-02:** `POST` sensibles sin `GET` equivalente que evada (los alias GET verify/passwordless comparten bucket `tok` con el POST — mismo contador).

## 6. Requerimientos de Observabilidad
* **Métrica:** `rate_limited_total{route, scope="ip|account|token"}` + `rate_allow_total` (muestreado 1% en rutas hot para no duplicar tráfico) + `rate_redis_fallback_total` + `rate_config_version`.
* **Trazabilidad:** Hijo `Defense.RateCheck` PRIMERO en cada `UseCase.*` (hijos: `ip.resolve`, `redis.lua`). Atributos `route, limit, remaining`, nunca IP completa (hash).
* **Auditoría:** `auth.audit.v1 {action:"rate.limited", route, scope, ip_hash, trace_id}` (muestreo 10% en flood para no saturar bus — documentado; P1 si `blocked:ip` se crea → evento `rate.ip_blocked` siempre).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Estricta frena y cabeceras**
  * **Dado** `POST /login` 10/min-IP.
  * **Cuando** 11º en 60s misma IP (tras proxy confiable).
  * **Entonces** `429 RATE_LIMITED` + `Retry-After` + `RateLimit-Remaining:0` + los 10 previos llevaban `Remaining 9..0` decreciente; 12º con IP distinta (XFF spoofeado directo sin proxy) → `200/401` normal (spoof ignorado) + audit. Con `TRUSTED_PROXIES` + XFF válido → cuenta la XFF.
* **Escenario 2: Sliding exacto sin ráfaga borde**
  * **Dado** fixed-window vetado.
  * **Cuando** 10 reqs en segundo 59 + 10 en segundo 61 (caballo de ventana).
  * **Entonces** las segundas 10 → `429` (sliding las ve; fixed las dejaría pasar). Test k6 con timestamps controlados lo prueba deterministamente (mock `TIME`).
* **Escenario 3: Fail-open + exentos + progresivo**
  * **Dado** Redis down 60s; `GET /healthz` flood; IP con 50×429/15min.
  * **Cuando** tráfico normal + probes + más flood.
  * **Entonces** Redis-down → `200/401` normales (límite local 2x, `WARN`) + 0 `500` por rate; `/healthz` flood 1000/min → `200` siempre; IP flodder → `blocked:ip` 15min (`429` largo en todo auth) + evento `rate.ip_blocked` + email? No (es IP, no cuenta; solo audit/P1 si DDoS).
