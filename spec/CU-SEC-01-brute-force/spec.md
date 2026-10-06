# Spec: CU-SEC-01 - Bloqueo por Intentos Fallidos (Brute Force Defense)

## 1. Contexto y Propósito
Frenar adivinanza de secretos por cuenta con bloqueo exponencial, sin oracular (todo `401` opaco) y con aviso al dueño. Política transversal que formaliza lo que CU-AUTH-01/02/06 ya usan vía `AttemptTracker`: 5/15min → 15-30-60-120min, por cuenta global (login+MFA+step-up), Redis TTL + fail-open, email throttled. Separa de CU-SEC-02 (tráfico por IP/ruta).

Decisiones (2026-10-05, todas Recommended):
- Q1 5/15min exp 15-30-60-cap120 deslizante + reset éxito, por cuenta (+IP señal), Q2 `401` opaco (sin 423/Retry-After en lock), Q3 login+MFA-verify+step-up (+backup) con lock cuenta global, Q4 Auto TTL + email 1er+1/hora (sin unlock manual MVP), Q5 Redis + fail-open (keys user_id o email_hash), Q6 Split cuenta/IP + reuso `AttemptTracker`, Q7 Email dueño 1/hora (inexistente solo audit).

## 2. Actores y Precondiciones
* **Actores:** Atacante/Usuario (con o sin credencial válida), Microservicio Auth, Worker SMTP, Redis.
* **Precondiciones:**
  * Flujos cubiertos instrumentados (`login`, `mfa_verify` (TOTP+backup), `step_up_challenge`, `password_change current` — los 4 alimentan el mismo tracker; `passwordless/reset` usan sus quotas propias + también alimentan fails cuenta si el email mapea a user conocido? No: para no crear oráculo por timing de conteo, los flujos anónimos opacos NO incrementan fails de cuenta inexistente salvo bucket `acct:email_hash` ciego (sin lock con email al dueño pues no hay dueño). Documentado).
  * Redis con `fails/locks/count/notify` (TTL auto); PG solo audit.

## 3. Flujo Principal (Happy Path — defensa)
1. Intento con secreto en flujo cubierto: el servicio valida forma (malforma → `400`, sin contar) y rate IP/ruta CU-SEC-02 (excede → `429`, sin contar fails cuenta).
2. Resuelve `accountKey = user_id si found else acct:<sha256(email_normalized)>` + `ipKey`. Chequea `lock:<accountKey>` (`locked_until>now` → marca `locked=true` interno, SIGUE al paso 3 con camino homogéneo — no cortocircuita rápido para no filtrar por tiempo salvo que el lock-check sea O(1) Redis igual en ambos casos; documentado: el check es 1 GET siempre, sin rama temporal distinguible).
3. Ejecuta verificación real o dummy (cada flujo su dummy: login Argon2, MFA TOTP-constant, step-up igual login) + jitter propio (80-120 login, 20-50 MFA/step-up) SIEMPRE.
4. Si éxito y `!locked` (imposible estar locked y éxito el mismo intento? Si el lock expiró entre check y verify (race ms) se permite — el `ResetOnSuccess` borra fails/lock y emite normal. Si `locked` vigente, el éxito NO se evalúa (ni siquiera se verifica el secreto: se hace dummy para timing y se retorna `401` — el dueño debe esperar; documentado para evitar que el atacante con la buena durante lock la use para sondear fin de lock por tiempo? El tiempo de expiración es fijo, sondearlo no revela secreto. Pero verificar la buena durante lock costaría Argon2 gratis al atacante como oráculo de carga? No: el dummy cuesta igual. Se hace dummy).
5. Si fallo o `locked`: `RecordFail(accountKey, ipKey, flow)` → `INCR fails:<acct> EX 900` (+ `INCR fails:ip:<ip> EX 900` señal, sin bloquear por sí sola aquí — la IP la bloquea CU-SEC-02) → si `fails>=5` → `lock:<acct> SET {until=now+backoff(lock_count)} EX=backoff` + `INCR lock_count:<acct> EX 86400` + si `notify:<acct>` ausente → `SET NX EX 3600` + encola email (solo si `user_id` conocido; si `acct:hash` sin user → solo audit) + `locks_total` +1.
6. Responde el `401` opaco del flujo (`INVALID_CREDENTIALS` / `INVALID_MFA` / `INVALID_STEP_UP` — cada flujo su código opaco habitual, SIN `423`, SIN `Retry-After` por lock; el `429` solo aparece por CU-SEC-02 IP, nunca por lock-cuenta) + audit `failed{locked:true, fails, backoff}` + métricas. Backoff: `15min × 2^(lock_count-1)` cap `120min` (`lock_count` = locks en 24h; `EX 86400` lo resetea diario).
7. Al éxito real (sin lock): `DEL fails/lock` (NO resetea `lock_count` 24h — la reincidencia tras éxito rápido sigue escalando dentro del día; documentado) + emite normal + email? No (éxito no avisa; el aviso fue al bloquear).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación/rate previos:** `400` forma / `429` IP (CU-SEC-02) no cuentan fails cuenta (evitan envenenar al dueño con tráfico ajeno malformado) pero SÍ cuentan para IP (señal).
* **4.2. Lock vigente con credencial buena:** `401` opaco igual (no `200`, no hint `espera X`). El dueño legítimo que olvidó y acertó durante lock debe esperar (UX documentada en email: `podrás intentar a las HH:MM` — el email SÍ dice la hora (al dueño por canal verificado, no al atacante por HTTP). HTTP nunca dice hora.
* **4.3. Inexistente:** `acct:<hash>` acumula fails y puede "bloquearse" (lock ciego sin email). Responde igual `401`. Sin dueño no hay aviso (solo audit `no_user`). El lock ciego expira igual (no afecta a nadie real; si luego se registra ese email, el `lock_count` ciego previo podría bloquear al nuevo? Limpieza: al registrar (CU-REG-01 éxito) se hace `DEL fails/lock/count` de `acct:<hash>` (vinculante en plan).
* **4.4. Redis/PG/Kafka down:** Redis down → fail-open (contadores memoria local 2x + `WARN` + `brute_redis_fallback_total`; NO se bloquea a nadie sin verdad compartida; al volver se rehidrata desde PG audit reciente? No: fails son efímeros, se pierden (ventana aceptada ≤ minutos, documentada) + alerta si down >5min). PG down → el flujo ya da `500` (sin contar). Kafka/SMTP down → `401` igual + email pendiente (outbox).
* **4.5. Conteo por flujo vs global:** `fails` globales por cuenta (suma login+MFA+step-up+pwdchange-current), NO por flujo (el atacante rotando flujos no evade). Buckets adicionales por flujo solo métricas (`failed_attempts_total{flow}`), no decisiones.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Umbral `5` en ventana `900s` deslizante (Redis `INCR EX 900` con sliding real? `INCR` no desliza sin `EXPIRE` renovado: implementación Lua sliding-window por timestamps (ZADD) O fixed-window `INCR EX` — decisión vinculante: fixed-window `EX 900` (simple, suficiente; el borde de ventana permite 10 en 2s a caballo — aceptado, el rate IP lo contiene). Documentado.
* **RN-02:** Backoff `15,30,60,120,120...` min (`cap 120`), `lock_count EX 86400` (reincidencia diaria escala; día limpio resetea escalada pero NO perdona fails activos).
* **RN-03:** Reset al éxito (`DEL fails/lock`, conserva `lock_count` del día). Registro nuevo limpia ciego (`DEL acct:<hash>*`).
* **RN-04:** Respuesta lock = `401` opaco del flujo (nunca `423/429` por lock; `Retry-After` solo CU-SEC-02). Email al dueño SÍ dice `hasta HH:MM` (canal verificado).
* **RN-05:** Email 1er lock + throttle `3600s` (`notify:<acct> NX EX 3600`), con IP/UA/hora + links `login/forgot` + `si no fuiste tú` (sin token). Inexistente → sin email.
* **SEC-01:** Keys por `user_id` (`fails:user:<uuid>`) si known sino `acct:<sha256>` (nunca email plano en key/log). IP completa en key Redis (operativo) pero `/24`+hash en logs.
* **SEC-02:** Sin `valid_after`/revoke en lock (el lock no mata sesiones vivas — solo frena nuevos auth; si hay sesión robada viva, el dueño usa SES-02; documentado split).
* **SEC-03:** `AttemptTracker` único (sin duplicar contadores por flujo/CU; CU-AUTH-01/02/06, CRED-02 lo inyectan, no lo reimplementan).

## 6. Requerimientos de Observabilidad
* **Métrica:** `failed_attempts_total{flow="login|mfa|stepup|pwdchange", locked="true|false"}` + `brute_locks_total{flow_first}` + `brute_lock_duration_seconds` Histogram + `brute_redis_fallback_total` + `lock_notify_emails_total{throttled}`.
* **Trazabilidad:** Hijo `Defense.BruteCheck` en cada `UseCase.*` cubierto (hijos: `lock.check`, `fails.record|reset`, `notify.check`). Atributos `fails, backoff, locked` (internos), nunca secreto.
* **Auditoría:** `auth.audit.v1 {action:"brute.check", account_hash, user_id?, flow, fails, locked, backoff_until?, trace_id}` + eventos `brute.locked.v1` (key `user_id` o `account_hash`) + email `security.brute_lock`. Sin secretos.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: 5 fallos → lock 15min opaco + email**
  * **Dado** cuenta sin fails, atacante prueba 5 malas/15min (login).
  * **Cuando** 5º fallo + 6º intento (buena o mala).
  * **Entonces** 1º-6º todos `401 INVALID_CREDENTIALS` idénticos (p50 ±40ms, sin `423/Retry-After`), tras 5º `lock_until=+15min` + 1 email (6º no re-email por throttle) + `locks_total` +1 + audit `locked`. Buena durante lock → `401` (no entra).
* **Escenario 2: Backoff + reset + registro-limpia**
  * **Dado** `lock_count=1` (ayer 1 lock, aún en 24h).
  * **Cuando** 5 fallos más hoy + luego éxito tras expirar + registro de email ciego bloqueado.
  * **Entonces** 2º lock = `30min` (backoff), `lock_count=2`; éxito post-expiración → `DEL fails/lock` (siguiente racha parte de 0 pero `lock_count=2` → próximo lock `60min`); registro email ciego → `DEL acct:hash*` (nuevo dueño limpio).
* **Escenario 3: Multi-flujo suma + inexistente + Redis-down**
  * **Dado** 2 fails login + 2 MFA + 1 step-up (misma cuenta) y email inexistente con 5 fails.
  * **Cuando** 6º intento cualquiera en la cuenta + 6º en inexistente + fails con Redis down.
  * **Entonces** cuenta real bloqueada (suma global 5, no por-flujo) + `401`s idénticos; inexistente bloqueado ciego sin email (solo audit); Redis-down → `401`s correctos sin locks (`WARN` + fallback, 0 bloqueos injustos) + al volver cuenta desde 0 (ventana aceptada).
