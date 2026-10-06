# Spec: CU-AUTH-01 - Autenticación Estándar

## 1. Contexto y Propósito
Validar `email + password` contra el repositorio y, solo si la cuenta está `ACTIVE` y sin bloqueos, bifurcar a sesión directa (sin MFA) o a desafío MFA (con MFA). Es el portón del Módulo 2: todo `401` es opaco e indistinguible (OVERVIEW prudente), todo éxito delega emisión a CU-AUTH-04 y todo intento alimenta defensa brute-force (anticipa CU-SEC-01/02) sin oracular.

Decisiones (2026-10-05, todas Recommended):
- Q1 `POST /login` 200 sesión / 202 MFA, Q2 `401 INVALID_CREDENTIALS` opaco total + dummy + jitter + test timing, Q3 Solo ACTIVE emite (resto 401, LOCKED también 401), Q4 Pre-token MFA `mfa_challenge` 5min, Q5 `login:ip 10/min + login:account 5/min →429`, 5 fallos/15min → bloqueo exponencial 15/30/60 + email pero responde 401, fail-open local, Q6 Delega a `SessionIssuer` CU-AUTH-04, Q7 4 puertos + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Usuario (con password), Microservicio Auth, Worker (emails/eventos), Store Redis (contadores/bloqueos).
* **Precondiciones:**
  * Cuenta pudo nacer clásica (hash Argon2id) o federada (`password_hash` NULL → nunca valida password aquí).
  * MFA flag `users.mfa_enabled` + secreto TOTP (CU-AUTH-02 lo gestiona; aquí solo se lee).
  * Redis con buckets login + bloqueos; Postgres `users` con índice `email_normalized`.

## 3. Flujo Principal (Happy Path)
1. Usuario envía `POST /api/v1/auth/login {email, password}` + `X-Request-ID` (body ≤32KB, `Content-Type: application/json`).
2. El back valida forma (email normaliza igual CU-REG-01; password `1..128` runas non-empty — validación laxa aquí, la estricta fue en registro; malforma → `400 VALIDATION_FAILED` rápido sin contadores de cuenta).
3. Rate-limit: `login:ip:<ip>` 10/min (sliding Redis) y `login:account:<sha256(email_normalized)>` 5/min → si excede `429 RATE_LIMITED + Retry-After` fast-reject (sin hash, sin revelar).
4. Lookup `SELECT * FROM users WHERE email_normalized=$1` (guarda `found`, no ramifica respuesta aún). Chequea bloqueo cuenta: `login:lock:<user_id|email_hash>` si `locked_until>now` → marca `locked=true` internamente pero NO cambia respuesta (sigue 401 opaco, ver 4.2).
5. Camino homogéneo SIEMPRE: `Argon2id.Verify` real si `found && hash non-null`, sino `Argon2id.Hash(dummy 12ch)` real descartado + `jitter 80-120ms`. `ConstantTime` donde compare. Tiempo éxito/fallo indistinguible.
6. Evalúa en memoria (sin filtrar): `ok = found && !locked && hash non-null && Verify==true && status==ACTIVE`. Si `!ok` → `RecordFail` (INCR `fails:<id>` 15min, si llega a 5 → `SET lock EX exponencial` + encola email aviso throttled) + `401` opaco (ver 4.2) + audit `failed`.
7. Si `ok` y `mfa_enabled=false` → `ResetFails` (DEL fails/lock) + llama `SessionIssuer.Issue(user, device{ip/24_hash, ua_hash})` (CU-AUTH-04: Access 15min + Refresh rotado HttpOnly Secure Lax + guarda sesión) → `200 {status:active}` + cookies + `Cache-Control: no-store`.
8. Si `ok` y `mfa_enabled=true` → `ResetFails` + emite pre-token `mfa_challenge` (JWT/opaco `aud=mfa-challenge`, `sub`, `methods:[totp]`, `challenge_id UUIDv7`, `exp=now+5min`, single-audience, firmado con clave sesiones pero distinto `aud/scope`, NUNCA aceptado en APIs negocio) + `202 {status:mfa_required, mfa_token, methods}`. El login completa en CU-AUTH-02. Sin sesión aún.

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * Email malformado/>254, password vacía/>128 runas/>512B, JSON roto, sin `X-Request-ID` (se genera pero sin idempotencia estricta), body >32KB → `400 VALIDATION_FAILED` con `details[field]`. No toca contadores cuenta (solo `login:ip` si pasó), no hash dummy pesado (rápido permitido, por forma no por secreto).
* **4.2. Credencial inválida / cuenta no-ACTIVE (núcleo anti-oráculo):**
  * Condición ÚNICA para: no-existe, pass-mala, `PENDING` (aunque password correcta — debe verificar CU-REG-02 por `/resend`, no aquí), `LOCKED`/`lock_until` vigente, `SOFT_DELETED`, `federated_only` sin password (intento password sobre cuenta Google), `password_hash` NULL/corrupto.
  * Respuesta SIEMPRE `401 {code:INVALID_CREDENTIALS, message:"Credenciales incorrectas."}` byte-idéntica (mismo schema/headers, sin `user_id`, sin `status`, sin `locked`, sin `verify_hint`), con dummy+jitter del paso 5. `LOCKED` responde igual 401 (NO `423`; el `Retry-After` solo aparece en `429` IP, nunca en bloqueo-cuenta para no distinguir). Concurrencia: 5 logins simultáneos misma cuenta mala → 5×401 + 5 fails (el 5º dispara lock, el 6º sigue 401).
  * PENDING con password correcta NO recibe `403 VERIFY_REQUIRED` ni reenvío auto (falla igual 401; el front ofrece "reenviar verificación" por vía separada sin saber si existe — anti-enumeración CU-REG-03).
* **4.3. Falla de servicio externo o infraestructura:**
  * Postgres down/timeout 2s → `500 INTERNAL_ERROR` (sin distinguir found), sin contadores (no INCR sin verdad), `login_total{error}`.
  * Redis down → fail-open local (bucket memoria 2x + `WARN`, fails/locks best-effort en memoria con expiración; NO bloquea logins legítimos; al recuperar rehidrata desde PG `audit` reciente si se implementa reconciliación — documentado best-effort).
  * Kafka/SMTP down → no afecta `200/202/401` (outbox `login.*` + email aviso-bloqueo pendientes, backoff/DLQ heredados).
  * HIBP no aplica aquí (solo registro).
* **4.4. Rate-limit / bloqueo:**
  * `429` solo por `login:ip` / `login:account` por minuto (fast, sin hash) + `Retry-After` + `X-RateLimit-Remaining:0`. Bloqueo cuenta (5/15min → 15/30/60 exponencial por reincidencia, `locked_until`, email `Tu cuenta se bloqueó temporalmente` throttle 1/h) responde `401` (no 429/423) hasta expirar; el contador `fails` es por `user_id` si found sino por `email_hash` (evita envenenar a otro con mismo casing).
* **4.5. Federado-only y PENDING borde:**
  * `password_hash IS NULL` → `Verify` imposible → dummy + `401` (nunca `400 PASSWORD_NOT_SET` que filtraría tipo cuenta). PENDING federada no-verificada con password? No existe (federada no tiene password salvo que luego seteó una — si la seteó y PENDING, igual 401 hasta ACTIVE).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Solo `ACTIVE` + `Verify==true` + `!locked` emite (sesión o pre-token). Todo lo demás 401 opaco.
* **RN-02:** `mfa_enabled=true` (bool + secreto TOTP presente, gestionado CU-AUTH-02) → `202 mfa_required`, nunca sesión directa. `false`/NULL → `200` vía Issuer.
* **RN-03:** Pre-token `aud=mfa-challenge`, TTL 300s exactos, un solo `challenge_id`, single-use lógico (CU-AUTH-02 lo consume; reuso → `401` allí). Firmado con misma infra sesiones pero rechazado fuera de `/mfa/verify` por `aud/scope`.
* **RN-04:** Fails/locks: `fails:<key> INCR EX 900`, a 5 → `lock:<key> SET locked_until=now+15/30/60min EX` (exponencial por `lock_count`), `fails` resetea al éxito (`DEL`), email aviso `security.login_lock` throttle 1/h. Claves por `user_id` si found sino `acct:<sha256(email)>` (nunca email plano).
* **RN-05:** Idempotencia `X-Request-ID` 24h solo para no duplicar side-effects (fails/outbox) en retries cliente; la respuesta es determinista igual (401/200/202) así que replay es seguro.
* **SEC-01 (Timing/enumeración):** `Verify` real o dummy Argon2id `m=65536,t=3,p=4` + jitter 80-120ms en TODO `401` por secreto/estado (no en `400/429` por forma/cuota). `ConstantTimeCompare` en hashes/comparaciones. Test bloqueante `|p50(ok)-p50(bad)|<80ms` y `|p50(nonexist)-p50(wrongpass)|<80ms`.
* **SEC-02 (Mensajes):** Catálogo cerrado: `INVALID_CREDENTIALS` único para todo fallo auth; prohibido `USER_NOT_FOUND, WRONG_PASSWORD, NOT_VERIFIED, LOCKED, NO_PASSWORD` hacia cliente (solo `audit` interno distingue `reason`).
* **SEC-03 (Password handling):** Password solo memoria request (string zeroizable si runtime lo permite, nunca log), `MaxBytes 32KB`, sin `password` en spans/logs/eventos (solo `email_hash/domain`). `Verify` con pepper si `PASSWORD_PEPPER` configurado (igual CU-REG-01).
* **SEC-04 (Sesión delegada):** Este CU nunca firma Access/Refresh ni toca `tokens_valid_after`; llama `SessionIssuer` (CU-AUTH-04). Pre-token tampoco es sesión (scope aislado).
* **SEC-05 (Device):** Calcula `device{ip_hash(/24), ua_family_hash}` y lo pasa al Issuer + audit (base SES-03/SEC-07 futuros), sin bloquear por dispositivo aquí.

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `login_total{result="success|mfa_required|invalid|rate_limited|error"}` + `login_duration_seconds` Histogram + `login_failures_total{reason_internal="bad_password|no_user|not_active|locked|no_password"}` (INTERNA, no al cliente) + `login_locks_total` + `login_lock_emails_total{throttled}`.
* **Trazabilidad:** Raíz `UseCase.Login` (hijos: `ratelimit.check`, `db.user.select_by_email`, `crypto.argon2.verify|dummy`, `lock.check|record`, `mfa.branch`, `session.issue|mfa.issue` (éxito), `outbox.insert`). Atributos `email.domain`, `mfa_enabled`, nunca password/hash.
* **Auditoría:** `auth.audit.v1 {action:"login.attempt", email_hash, user_id?, result, reason_internal?, ip_hash, device_hash, mfa:=bool, trace_id}` + si éxito `auth.login.success.v1` / si MFA `auth.login.mfa_challenged.v1` (key `user_id`). Sin password ni tokens.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Login sin MFA → sesión**
  * **Dado** ACTIVE clásica `mfa=false`, password correcta, sin locks, Redis sano.
  * **Cuando** `POST /login` válido.
  * **Entonces** `200 {status:active}` + cookies sesión (formato CU-AUTH-04) + fails reseteados + `login_total{success}` +1 + audit success. p95 <500ms (Argon2 incluido).
* **Escenario 2: Login con MFA → 202 pre-token sin sesión**
  * **Dado** ACTIVE `mfa=true`, password correcta.
  * **Cuando** `POST /login`.
  * **Entonces** `202 {status:mfa_required, mfa_token (aud=mfa-challenge 5min), methods:[totp]}` sin cookies sesión, el `mfa_token` es rechazado en APIs negocio (`401` allí) y aceptado solo en `POST /mfa/verify` (CU-AUTH-02). `login_total{mfa_required}` +1.
* **Escenario 3: Fallos indistinguibles + timing**
  * **Dado** 4 casos: email inexistente, password mala, PENDING con buena, federated-only con password cualquiera.
  * **Cuando** se loguean los 4 (+ LOCKED vigente como 5º).
  * **Entonces** los 5 retornan `401 INVALID_CREDENTIALS` byte-idénticos (salvo RequestID) con p50 mutuo `±40ms` (n=100 c/u, k6), 0 sesiones/pre-tokens, fails/lock solo internos. Atacante no distingue.
* **Escenario 4: Brute-force bloquea opaco + rate-limit explícito**
  * **Dado** cuenta sin lock, atacante prueba 6 malas en 15min (misma IP).
  * **Cuando** 6º intento (5º disparó lock 15min + email 1º).
  * **Entonces** 1º-6º todos `401` idénticos (6º no dice bloqueada), 7º con buena dentro del lock → igualmente `401` (no 200) hasta expirar; IP que supera 10/min → `429 + Retry-After` (único caso con header). Tras expirar, buena → `200/202`. `locks_total` +1, email 1 (2º bloque en 1h throttled).
* **Escenario 5: Infra degradada**
  * **Dado** Redis down (o Kafka down).
  * **Cuando** login bueno/malo.
  * **Entonces** Redis-down → `200/202/401` correctos con p95 <800ms (fail-open) + `WARN`, sin `500` espurio; Kafka-down → `200/202` inmediatos + outbox pendiente (<60s lag al recuperar). PG-down → `500` genérico sin side-effects.
