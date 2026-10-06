# Spec: CU-REG-02 - Verificación de Identidad Obligatoria

## 1. Contexto y Propósito
Activar cuentas creadas en CU-REG-01 (estado `PENDING_VERIFICATION`) exigiendo prueba de posesión del correo antes de otorgar cualquier sesión. Sin esta verificación nadie opera en la plataforma (OVERVIEW: registro verificado obligatorio). Convierte `PENDING_VERIFICATION → ACTIVE` de forma atómica, destruyendo el secreto de un solo uso e integrando el canal email al camino asíncrono (nunca bloquea registro/login).

Decisiones acordadas (2026-10-05):
- Q1 Ambos dual (OTP 8 dígitos + Magic Link 32B, un solo uso, 15min), Q2 POST unificado + GET alias con error genérico único, Q3 3 fallos queman + cooldown 60s + máx 5 reenvíos/24h + solo 1 activo, Q4 Tx atómica idempotente, Q5 Redis como verdad + Postgres backup, Q6 ConstantTime + delay 40-80ms + rate-limit dual, Q7 TTL 15min + métricas/eventos propuestos.

## 2. Actores y Precondiciones
* **Actores:** Usuario (anónimo con link/código), Microservicio de Autenticación, Worker (reenvío SMTP), Proveedor SMTP.
* **Precondiciones:**
  * Existe `users.id` en `PENDING_VERIFICATION` con al menos un registro de verificación vigente o expirado recientemente (ventana reenvío 24h).
  * Registro de verificación vigente: tupla `{token_hash (SHA-256 de 32B CSPRNG), otp_hash (SHA-256 de 8 dígitos CSPRNG), user_id, expires_at = created + 15min, attempts <3, consumed=false}` en Redis (verdad rápida, TTL 15min) + copia durable en Postgres `verification_tokens`.
  * El usuario no está autenticado (no requiere Bearer; el secreto es el bearer efímero).

## 3. Flujo Principal (Happy Path)
1. El usuario abre el Magic Link `GET /api/v1/auth/verify-email?token=<base64url 43ch>` (enviado por SMTP desde CU-REG-01) o envía `POST /api/v1/auth/verify-email` con `{"token":"<base64url>"}` o `{"code":"12345678"}` + `X-Request-ID`.
2. El sistema aplica rate-limit (Redis `verify:ip:<ip>` 10/min, `verify:tok:<hash>` 5/min; si excede → `429` fast-reject sin tocar DB).
3. El sistema normaliza entrada: `token` = trim, base64url decode estricto → debe ser exactamente 32B; `code` = trim, debe ser `^[0-9]{8}$`. Otro formato → `400 VALIDATION_FAILED` (única excepción al mensaje genérico, por formato no por existencia).
4. El sistema calcula `SHA-256(plain)` hex, busca en Redis: `verify:t:<hash>` o `verify:o:<hash>`. Si miss en Redis → fallback a Postgres `verification_tokens WHERE token_hash=$1 OR otp_hash=$2` (read-through: si Postgres lo tiene vigente, rehidrata Redis con TTL restante y continúa; si Postgres lo tiene expirado/consumido → trata como inválido genérico).
5. Si encuentra registro y `consumed=false` y `expires_at > now` y `attempts <3`: compara con `subtle.ConstantTimeCompare(stored_hash, computed_hash)` (defensa aunque el índice ya filtró). Si OK:
   a. En UNA transacción Postgres: `UPDATE users SET status='ACTIVE' WHERE id=$1 AND status='PENDING_VERIFICATION'` + `UPDATE verification_tokens SET consumed=true, consumed_at=now WHERE (token_hash=$1 OR otp_hash=$2) AND consumed=false` + `DELETE` lógico de otros tokens activos del usuario (solo 1 activo: `UPDATE ... SET consumed=true, superseded=true WHERE user_id=$1 AND consumed=false AND token_hash<>$1`) + `INSERT outbox(auth.user.activated.v1, auth.audit.v1)`.
   b. Invalida en Redis atómicamente (Lua): `DEL verify:t:<hash> + DEL verify:o:<otp_hash> + DEL verify:active:<user_id> + DEL contadores`.
   c. Retorna `200 OK {success:true, data:{status:"active", message:"Cuenta verificada. Ya puedes iniciar sesión."}}` + `Cache-Control: no-store`. Emite vía outbox/worker `auth.user.activated.v1` y `auth.audit.v1`. Usuario ya puede loguearse (CU-AUTH-01).
6. El token/OTP queda destruido: ningún reuso posterior otorga nada nuevo (ver 4.2 idempotencia).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * Condición: `token` no base64url 32B, `code` no 8 dígitos, ambos ausentes o ambos presentes, JSON malformado, body >4KB, `Content-Type` inválido.
  * Respuesta: `400` `VALIDATION_FAILED` con `details[].field=token|code`. No toca contadores de intentos (no consume intento). No revela existencia.
* **4.2. Conflicto o unicidad (token inválido / expirado / consumido / ya ACTIVE):**
  * Condición: hash no existe en Redis ni Postgres, o `expires_at <= now`, o `consumed=true`, o `attempts>=3`, o usuario ya `ACTIVE` por otro token.
  * Respuesta: manejo ANTI-ORÁCULO obligatorio — siempre `400` idéntico `{"success":false,"error":{"code":"INVALID_OR_EXPIRED","message":"El enlace o código es inválido o expiró. Solicita uno nuevo."}}`. Nunca `404` ni `410`. Aplica delay uniforme 40-80ms + `ConstantTimeCompare` contra hash señuelo para homogeneizar. Incrementa `attempts` SOLO si el registro existe y está vigente (fallo de secreto erróneo con formato válido pero valor incorrecto no es posible por lookup directo — ver 5/SEC-02 para conteo exacto). Casos:
    * Reapertura del MISMO link que activó (idempotencia): si `users.status=ACTIVE` Y el token presentado es el que la activó (`consumed=true` + `activated_by_token_hash` match) → retorna `200 {status:"already_verified"}` idempotente (permite doble-clic / prefetch). Cualquier otro token viejo en cuenta ACTIVE → `400` genérico.
    * Concurrencia: 2 POST simultáneos mismo token válido → uno gana la Tx (`UPDATE ... WHERE consumed=false` afecta 1 fila), el otro ve `consumed=true` → `400` genérico (o `200 already_verified` si es el mismo dispositivo reintentando tras éxito — distingue por `request_id` idempotente 24h).
* **4.3. Falla de servicio externo o infraestructura:**
  * Condición: Postgres caído, Redis caído/evicción, Kafka caído, SMTP caído (solo afecta reenvío).
  * Respuesta:
    * Postgres caído → `500 INTERNAL_ERROR` genérico, sin trazas. No cambia estado. Métrica `result=error`.
    * Redis caído → degradación a Postgres como verdad (failover automático, sin bloquear). Rate-limit fail-open local 2x + `WARN`. Intentos se cuentan en Postgres (`attempts++` en Tx). Al recuperar Redis, rehidrata desde Postgres. Nunca retorna `400` falso por miss de caché sin chequear Postgres primero.
    * Redis evicción prematura (TTL perdido) → fallback Postgres lo rescata si `expires_at` aún vigente (read-through). Solo si ambos miss → `400` genérico.
    * Kafka caído → NO afecta `200` (outbox ya en Tx). Worker reintenta backoff 5s/30s/5min/30min, DLQ `auth.dlq.v1`, alerta si `outbox_lag>60s`.
    * SMTP caído → `POST /resend-verification` retorna `202` aceptado igualmente (outbox pendiente), el envío se reintenta async.
* **4.4. Rate-limit / reintentos agotados:**
  * `429` si IP >10/min o token_hash >5/min (`Retry-After` + `RATE_LIMITED`, sin consumir intento).
  * 3er fallo con secreto válido-formato pero registro vigente y hash mismatch imposible por diseño lookup — el conteo real aplica a: OTP/code erróneo que colisiona en formato pero no en hash no incrementa (es `400` genérico sin registro); el contador `attempts` incrementa cuando el atacante prueba códigos aleatorios contra el endpoint sin token (fuerza bruta OTP): cada `POST {code}` que no matchea ningún `otp_hash` NO incrementa un registro puntual sino el bucket `verify:tok`/`verify:ip`; cuando un registro SÍ es localizado pero la comparación ConstantTime falla (caso borde HMAC) o cuando se implementa verificación por `user_id+code` (fallback), `attempts++`, al llegar a 3 → `consumed=true, burned_reason=max_attempts` + exige reenvío. Implementación vinculante en plan.md.
* **4.5. Reenvío (resend):**
  * `POST /api/v1/auth/resend-verification {email}` → SIEMPRE `202 {success:true, data:{status:"if_exists_verification_sent"}}` genérico (anti-enumeración, igual exista o no, igual ACTIVE o PENDING). Internamente: si PENDING y `last_sent_at >60s` atrás y `resends_24h <5` → invalida anterior (supersede), genera nuevo par token+OTP (mismo formato), dual-write Redis+Postgres, encola email. Si cooldown o cuota excedida → igualmente `202` genérico (sin revelar), pero no envía + log `WARN resend_throttled`. Si ya ACTIVE → `202` genérico sin enviar (o email informativo "tu cuenta ya está activa" solo si política lo permite — por defecto NO enviar para no oracular; configurable).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Solo `PENDING_VERIFICATION → ACTIVE`. Nunca `ACTIVE → ACTIVE` por verify salvo idempotencia `already_verified` del token activador. `LOCKED/SOFT_DELETED` nunca se activan por este endpoint (`400` genérico).
* **RN-02:** Un solo secreto activo por usuario (`verify:active:<user_id>`). Cada emisión/reenvío supersede el anterior atómicamente.
* **RN-03:** TTL 15min exactos (`expires_at = created_at + 15min`), reloj UTC. Expirado = inválido, sin gracia. Reenvío crea nuevo TTL, no extiende el viejo.
* **RN-04:** Un solo uso. `consumed=true` irreversible + borrado Redis. Replay = `400` (o `200 already_verified` solo para el token activador).
* **RN-05:** Idempotencia `X-Request-ID` 24h en verify y resend (misma key = misma respuesta sin re-ejecutar Tx).
* **SEC-01 (Oráculo/timing):** Mensaje único `INVALID_OR_EXPIRED` para no-existe/expirado/consumido/quemado/ACTIVE-ajeno. `ConstantTimeCompare` + delay 40-80ms en todo `400` por secreto. Sin `user_id/email` en errores. Comparación de hashes, nunca de planos.
* **SEC-02 (Fuerza bruta OTP 8 dígitos ~26.6 bits):** Rate-limit duro `verify:ip` 10/min + `verify:tok` 5/min + `verify:otp_global` 100/min/instancia + 3 intentos queman + reenvío con cooldown/cuota. OTP 8 dígitos (no 6) + token 32B como vía principal (el link es la vía recomendada en el email, el OTP es alternativa manual).
* **SEC-03 (Almacenamiento):** Nunca persiste ni loguea token/OTP plano. Solo `SHA-256 hex` en Redis/Postgres/Kafka-trazas. Token 32B `crypto/rand`, OTP `crypto/rand` int 0..99.999.999 con zero-pad 8. Email de verificación contiene link `https://<front>/verify?token=<b64url>` + código legible, expira en texto, un solo intento visible.
* **SEC-04 (Prefetch email):** Los clientes de correo pre-abren links (GET). Por eso `GET` es idempotente y seguro (no muta más de una vez, segundo GET → `already_verified`), y el `POST` es la vía canónica desde el front. Opción endurecida (futura): GET solo muestra página confirmación que hace POST (se documenta, no se impone en este CU).
* **SEC-05 (PII):** Logs/eventos sin `token/code/email` plano salvo evento dirigido al mailer (igual que CU-REG-01). Auditoría usa `user_id + email_hash`. Claves Redis son hashes, nunca emails.

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `email_verification_total{result="success|already_verified|invalid_or_expired|validation_failed|rate_limited|resend_queued|resend_throttled|error"}` Counter + `email_verification_duration_seconds` Histogram + `verification_resends_total` + `verification_attempts_burned_total` + `verify_redis_fallback_total{reason="miss|down"}`.
* **Trazabilidad:** Span raíz `UseCase.VerifyEmail` (+ `UseCase.ResendVerification` para reenvío). Hijos: `cache.verify.lookup`, `db.token.select|consume` (Tx), `crypto.compare`, `outbox.insert`, `kafka.produce` (worker). Atributos: `token.type=link|otp`, nunca el secreto.
* **Auditoría:** Evento `auth.audit.v1 {action:"user.verify|user.verify_failed|user.verification_resent", user_id?, email_hash, result, attempts_left?, trace_id}` a `auth.audit.v1`. Éxito además `auth.user.activated.v1 {user_id, activated_at, method:link|otp}`. Sin token/code plano.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Magic link válido activa**
  * **Dado** usuario PENDING con token vigente (creado hace 2min, attempts=0) en Redis+Postgres.
  * **Cuando** `GET /verify-email?token=<b64url 32B>` o `POST {token}`.
  * **Entonces** `200 {status:active}`, Postgres `users=ACTIVE` + `verification_tokens.consumed=true` + outbox 2 eventos, Redis claves borradas, `email_verification_total{success}` +1, y `POST /login` posterior ya permite desafío (CU-AUTH-01).
* **Escenario 2: OTP válido activa e invalida link**
  * **Dado** mismo registro vigente.
  * **Cuando** `POST {code:"87654321"}` correcto.
  * **Entonces** `200 active`, el Magic Link del mismo registro queda quemado (reuso → `400` o `200 already_verified` si es el activador según 4.2), ambos hashes marcados consumed.
* **Escenario 3: Token expirado/consumido/inexistente indistinguibles**
  * **Dado** tres casos: token aleatorio 32B nunca emitido, token expirado hace 1h, token ya consumido ayer.
  * **Cuando** se verifican los tres.
  * **Entonces** los tres retornan `400 INVALID_OR_EXPIRED` con body byte-idéntico (salvo `X-Request-ID` echo) y latencias p50 dentro de ±40ms (n=100, k6), sin revelar cuál es cuál.
* **Escenario 4: 3 fallos queman + reenvío con cooldown/cuota**
  * **Dado** registro vigente con attempts=2.
  * **Cuando** falla una vez más (lógica de conteo plan.md) y luego se intenta con el secreto correcto original.
  * **Entonces** el 3er fallo marca `burned`, el secreto correcto posterior da `400`; `POST /resend` antes de 60s da `202` genérico sin enviar (throttled); tras 60s da `202` y llega nuevo email con nuevo par que sí activa, invalidando el anterior.
* **Escenario 5: Redis caído no bloquea ni falsifica**
  * **Dado** Redis caído (connection refused) pero Postgres sano con registro vigente.
  * **Cuando** se verifica con link válido.
  * **Entonces** retorna `200 active` en <800ms p95 vía fallback Postgres + rehidrata Redis al recuperar, `verify_redis_fallback_total{reason=down}` +1, sin `400` falso. Y con Kafka caído igualmente `200` inmediato + outbox pendiente que se publica al recuperar (<60s lag).
