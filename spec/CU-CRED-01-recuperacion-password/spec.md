# Spec: CU-CRED-01 - Recuperación de Contraseña ("Olvidé mi contraseña")

## 1. Contexto y Propósito
Permitir a un usuario que olvidó su clave restablecerla con un link de un solo uso al correo, sin oracular existencia y revocando todo lo anterior. Solo `ACTIVE` con password recibe correo; el consumo exige la misma policy de registro + clave distinta a la actual, y termina en corte global de sesiones (re-login obligatorio). Reutiliza el patrón endurecido verify/passwordless (Redis verdad + PG backup + outbox) con tabla propia y sin OTP débil.

Decisiones (2026-10-05, todas Recommended):
- Q1 TTL 15min 1 activo 1 uso, Q2 Solo `ACTIVE+password_hash` recibe link (federated-only aviso `usa Google` al dueño) + `202` opaco, Q3 Solo link 32B (sin OTP), Q4 Misma policy CU-REG-01 + distinta a actual (historial N en CRED-02), Q5 Revoca todo + relogin (sin auto-login), Q6 ctx-binding alerta + 3 burns + quotas + Redis/PG, Q7 `start` + `confirm` (+GET form) + tabla/métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Usuario Anónimo (dueño o atacante), Microservicio Auth, Worker SMTP.
* **Precondiciones:**
  * Elegibilidad envío: `users.status=ACTIVE AND password_hash IS NOT NULL` (clásicas; federated-only con password seteada después también elegible; federated pura → aviso alternativo, ver 3).
  * Sin sesión requerida (si trae Bearer se ignora; el token reset es la auth).
  * ≤1 activo por `user_id` (`reset:active:<uid>` + `UNIQUE(user_id) WHERE !consumed` lógico vía supersede).

## 3. Flujo Principal (Happy Path)
1. Usuario envía `POST /api/v1/auth/password/reset/start {email}` + `X-Request-ID` (≤2KB). Valida forma (normaliza igual registro; malforma → `400 VALIDATION_FAILED` rápido).
2. Rate `pwdreset:start:ip 10/hora` + `pwdreset:start:email_hash 3/hora` → excede `429 + Retry-After` (sin revelar).
3. Lookup `users by email_normalized` (guarda `eligible = ACTIVE && hash non-null`); dummy CSPRNG + `jitter 60-100ms` ambas ramas (sin Argon2 aquí — no hay que igualar tiempo de Verify, solo homogeneizar lookup).
4. Si `eligible` + quotas (`reset:sent:<uid>>60s`? no, `<60s` bloquea; `reset:count:<uid:day><5`) → genera `token 32B CSPRNG b64url`, `hash=SHA-256`, `exp=now+15min`, `attempts 0/3`, `ctx{ip/24,ua}`, dual-write Redis (`pwdreset:t:<hash>`, `pwdreset:active:<uid>` supersede previo EX 900) + PG Tx (`password_reset_tokens` + outbox `password.reset_requested`) y encola SMTP (link `https://front/reset?token=` + `expira 15min` + `si no fuiste tú ignora + asegura`). Si federated-only ACTIVE (sin password) → encola aviso alternativo `Usa Google para entrar (no tienes contraseña)` (mismo `202`, throttle igual, sin link reset). Si no eligible/throttled → nada (solo audit).
5. Retorna `202 {status:if_exists_sent}` idéntico siempre.
6. Usuario abre `GET /password/reset?token=` (solo muestra form si el hash existe y vive — responde `200 {valid:true}` genérico? No: para no oracular, el GET valida formato pero NO revela validez sin consumir? Decisión vinculante: `GET` retorna `200` con form siempre si formato OK (aunque el token sea inválido; el error aparece al confirmar). Así el link nunca es oráculo por GET).
7. Envía `POST /password/reset/confirm {token, new_password, new_password_confirm?}` (el front pide 2 campos iguales localmente; el back exige `new_password` + opcional `confirm` match si viene). El back valida forma token 32B + policy nueva clave (igual CU-REG-01: 12ch/clases/HIBP + `Verify(new, oldHash)==false` → si igual → `400 PASSWORD_REUSED` — único `400` que distingue reutilización, permitido porque solo lo ve quien posee el link + sabe la actual? No: el link prueba posesión del correo, así que revelar `reused` no oracula a terceros. Documentado).
8. Lookup Redis→PG read-through, `ConstantTime` + `delay 40-80ms` en `400`; si vivo: Tx atómica PG: `UPDATE users SET password_hash=<Argon2id nuevo>, password_algo, updated_at, tokens_valid_after=now` + `UPDATE password_reset_tokens SET consumed` + supersede resto + `UPDATE refresh_families SET revoked + DELETE sessions user` (corte global) + `DELETE` Redis (`pwdreset:*`, `sess:<uid>:*`, `fam:*`) + outbox (`password.changed` + `session.revoked_all` + audit + email `Cambiaste tu clave` con IP/hora + `si no fuiste tú recupera de nuevo`). Retorna `200 {status:password_changed, message:"Inicia sesión con tu nueva clave."}` SIN auto-login ni tokens (debe `POST /login`).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** email/token/new_password malforma (policy con `details[field]`), `confirm` mismatch, body >8KB → `400 VALIDATION_FAILED/PASSWORD_POLICY_*` (policy detalla campo sin revelar existencia; token malformo no consume intento).
* **4.2. Inválido/expirado/consumido/quemado (opaco):** miss Redis+PG, `exp`, `consumed`, `attempts>=3` (cada `confirm` con token bien-formado pero hash mismatch imposible por lookup — el conteo aplica a `confirm` con token válido-formato contra registro vigente pero `new_password` inválida? No: policy-fail no quema token (permite corregir clave sin pedir nuevo link). Quema solo: `confirm` con token inexistente no quema registro (sin registro); con registro vigente, 3 `confirm` con `new_password` válida pero Tx fallida? Raro. Definición vinculante en plan: `attempts` incrementa en cada `confirm` con token EXISTENTE y vivo pero que falla por `PASSWORD_REUSED` o Tx-conflicto, y en cada `GET-verify` falso? Simplificado: `attempts` cuenta confirms con token hallado pero consumido/expirado reintentado (abuso), a 3 → `burned` + exige `start` nuevo. Todo `400 INVALID_OR_EXPIRED` idéntico (salvo `PASSWORD_REUSED/POLICY` que son de clave, no de token).
* **4.3. Infra:** PG down → `500` (sin crear/consumir); Redis down → PG verdad + fail-open rate + `WARN`; Kafka/SMTP down → `202/200` igual (outbox pendiente); HIBP timeout → fallback lista local + `WARN` (igual registro).
* **4.4. Rate/quota:** `429` start/confirm buckets (con `Retry-After`); quota `60s/5-24h` → `202` genérico + `throttled` (no `429` que distinguiría elegibilidad).
* **4.5. Federated-only y PENDING:** federated pura → `202` + email alternativo (throttle) sin link; PENDING con password (no verificada) → `202` sin correo (debe verificar primero CU-REG-02; el `confirm` con token inexistente da `400` igual). LOCKED/borrada → `202` sin correo.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Solo link 32B (`43ch b64url`, `SHA-256` guardado), TTL `900s`, 1 activo (supersede), 1 uso, `attempts≤3`.
* **RN-02:** Elegibilidad envío `ACTIVE + hash non-null`. El `confirm` exige registro vivo + `users` aún `ACTIVE` (si se bloqueó/borró entre start y confirm → `400` opaco, sin cambiar clave).
* **RN-03:** Policy nueva = CU-REG-01 + `≠ actual` (`Argon2id.Verify(new, old)` debe ser `false`; si `true` → `400 PASSWORD_REUSED`). Historial N>1 en CRED-02 (aquí no).
* **RN-04:** Consumo atómico + corte global (`tokens_valid_after=now`, `families revoked`, `sessions DEL`, Redis+PG) + email aviso siempre. Sin auto-login (el `confirm` no emite `Issue`).
* **RN-05:** Idempotencia RequestID 24h (`start` mismo RequestID no re-emite; `confirm` mismo RequestID replay → mismo `200` sin re-hashear si ya consumido por ese RequestID, sino `400`).
* **SEC-01:** Opaco total (`202` start + `400` confirm idénticos, `ConstantTime`, hashes, `delay`, sin `user_id/email` en errores; `PASSWORD_REUSED/POLICY` solo tras probar posesión del link).
* **SEC-02:** Contexto `ip/24+ua` ligado con `risk` (permite + alerta `context_mismatch` si high, igual passwordless; no bloquea VPN).
* **SEC-03:** Solo hashes en DB (`SHA-256` link), plano solo SMTP TLS (link una vez) + memoria request; `new_password` nunca log/span/evento (solo `policy_ok` bool); `Argon2id m=64MB,t=3,p=4` igual registro + pepper.
* **SEC-04:** GET form nunca consume ni revela validez (solo formato); el `confirm` quema al primer uso válido (replay → `400`).

## 6. Requerimientos de Observabilidad
* **Métrica:** `password_reset_total{op="start|confirm", result="sent|throttled|not_eligible|federated_hint|success|invalid|reused|policy_failed|rate_limited|error"}` + duración + `pwdreset_mismatch_total{risk=high}` + `pwdreset_redis_fallback_total`.
* **Trazabilidad:** Raíces `UseCase.PasswordResetStart/Confirm` (hijos: `ratelimit`, `db.user.lookup`, `crypto.rand`, `cache+db.save|lookup|consume`, `crypto.policy+hibp`, `crypto.argon2.hash`, `db.password.update+revoke`, `ctx.compare`, `outbox.insert`). Atributos `risk`, nunca secreto/clave.
* **Auditoría:** `auth.audit.v1 {action:"password.reset_start|confirm", email_hash, user_id?, result, risk?, trace_id}` + eventos `password.reset_requested|changed` + `session.revoked_all` + `security.context_mismatch?` (key `user_id`/`email_hash`). Sin token/clave.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Reset completo con corte**
  * **Dado** ACTIVE clásica (2 sesiones vivas), quotas libres.
  * **Cuando** `POST /start {email}` → `202` + Mailhog link + `POST /confirm {token, new_password:Válida-2026!}` <15min.
  * **Entonces** `200 password_changed`, `password_hash` nuevo verifica (vieja no), `tokens_valid_after≈now`, 0 `sessions/families` vivas, Access viejos rechazados (gateway `valid_after`), email `Cambiaste tu clave`, `reset_total{sent,success}` +1. `POST /login` vieja → `401`; nueva → `200/202`.
* **Escenario 2: Opacos (inexistente/PENDING/federated) + federated-hint**
  * **Dado** `inexistente`, `PENDING` con password, federated-only.
  * **Cuando** `start` los 3.
  * **Entonces** 3× `202` idénticos (p50 ±40ms); Mailhog: 0, 0, 1 (federated-hint `usa Google`, sin link); ninguno habilita `confirm` (tokens aleatorios → `400`). Federated con password seteada después SÍ recibe link normal.
* **Escenario 3: Token expirado/consumido/reusado + policy/reused**
  * **Dado** token expirado (16min), consumido ayer, aleatorio; y token vivo con `new_password` débil o igual a actual.
  * **Cuando** `confirm`.
  * **Entonces** 3× `400 INVALID_OR_EXPIRED` idénticos; débil → `400 POLICY_*` con `details` (sin quemar token, permite corregir); igual-actual → `400 PASSWORD_REUSED`; 3º abuso → `burned` + exige `start` nuevo.
* **Escenario 4: High-risk + infra**
  * **Dado** emitido `IP-A`, confirmado `IP-B/16` distinto.
  * **Cuando** `confirm` válido + Redis-down / Kafka-down / PG-down.
  * **Entonces** `200` + email `context_mismatch` + audit `high`; Redis-down → `200` vía PG; Kafka-down → `200` + outbox pendiente; PG-down → `500` sin cambiar clave ni revocar.
