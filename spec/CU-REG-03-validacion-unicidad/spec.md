# Spec: CU-REG-03 - Validación de Unicidad en Tiempo Real

## 1. Contexto y Propósito
Garantizar que la comprobación de existencia de un correo sea instantánea para el flujo legítimo pero inútil como oráculo para atacantes. Es el blindaje anti-enumeración de CU-REG-01 (`POST /register`) y CU-REG-02 (`POST /resend-verification`): ambas reutilizan esta lógica transversal para responder de forma idéntica exista o no la cuenta, y notificar al dueño legítimo sin bloquear el request.

Decisiones acordadas (2026-10-05, todas Recommended):
- Q1 Transversal sin endpoint público nuevo, Q2 Respuesta bit-idéntica + hash dummy + jitter 80-120ms + test p50 diff <80ms, Q3 Email seguridad 1/hora con links login/forgot vía outbox, Q4 Heredado 10/min/IP + 3/hora/email + bloqueo progresivo IP 50x429/15min, Q5 Siempre Postgres (índice único, sin Bloom/cache existencia), Q6 Sin tablas nuevas (reuso repositorio + publisher), Q7 Métrica interna + alerta barrido >100 shadow/min/subnet.

## 2. Actores y Precondiciones
* **Actores:** Usuario Anónimo (legítimo o atacante automatizado), Microservicio de Autenticación, Worker SMTP/Kafka.
* **Precondiciones:**
  * Normalización canónica idéntica a CU-REG-01 disponible (`email_normalized`: trim, lowercase folding, punycode, ≤254, regex).
  * Postgres con constraint `UNIQUE(email_normalized)` + Redis para contadores (no para verdad de existencia).
  * Plantilla SMTP `security.registration_attempted` versionada y aprobada (con links `/login` y `/forgot-password`).

## 3. Flujo Principal (Happy Path)
1. El actor invoca `POST /api/v1/auth/register` o `POST /api/v1/auth/resend-verification` con un `email` (cualquier casing/espacios).
2. El sistema normaliza a `email_normalized` (misma función `domain/user/email.go` de CU-REG-01; Unicode/IDN → punycode; formato inválido → `400 VALIDATION_FAILED` sin chequear existencia ni consumir cuota de existencia).
3. El sistema chequea rate-limit (Redis `register:ip` / `register:email_hash`, ver SEC-03) antes de tocar Postgres. Si excede → `429` fast-reject (sin hash dummy, sin revelar nada).
4. El sistema ejecuta `SELECT id, status FROM users WHERE email_normalized=$1` (índice único, `statement_timeout=2s`). Guarda `found=true/false` solo en memoria/span, nunca en respuesta.
5. Ambas ramas ejecutan camino homogéneo: `PasswordHasher.Hash(dummy 12ch)` Argon2id `m=65536,t=3,p=4` + `sleep jitter uniforme 80-120ms` (CSPRN G). El tiempo total observado (DB + hash + jitter) debe ser indistinguible (criterio 7).
6. Si `found=false`: continúa flujo normal CU-REG-01 (crea PENDING + outbox `user.registered`) o CU-REG-02-resend (no-op genérico si PENDING inexistente → igualmente `202`).
7. Si `found=true`: NO crea ni muta nada de negocio; en la MISMA Tx lógica (no bloqueante para HTTP) encola vía outbox `auth.security.registration_attempted.v1` + `auth.audit.v1` (con throttling 1/hora, ver 4.2); retorna respuesta idéntica al caso `found=false`:
   * register → `201 {success:true, data:{status:"pending_verification", message:"Si el email es válido recibirás instrucciones..."}}` (sin `user_id`).
   * resend → `202 {success:true, data:{status:"if_exists_verification_sent"}}`.
8. El worker, fuera del request (<30s, reintentos backoff), envía al dueño el email de seguridad (si throttling lo permite) con links de acceso/recuperación.

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * Condición: email malformado, >254, control/null, body >32KB, Content-Type inválido.
  * Respuesta: `400 VALIDATION_FAILED` con `details[field=email]`. No ejecuta SELECT ni hash dummy ni outbox. No consume cuota de existencia (solo cuenta para `register:ip` si pasó rate-limit). Tiempo <50ms (único caso rápido permitido, por formato no por existencia).
* **4.2. Conflicto o unicidad (email existente — caso central):**
  * Condición: `email_normalized` existe en `ACTIVE`, `PENDING_VERIFICATION`, `LOCKED` o `SOFT_DELETED` en gracia.
  * Respuesta: OBLIGATORIO indistinguible del éxito (ver 3.7). Prohibido `409`, `422`, mensajes `already exists`, diferencias de schema, headers extra o tiempos sistemáticamente distintos. Concurrencia (5x mismo email simultáneo): `ON CONFLICT DO NOTHING` → todos shadow. Throttling email seguridad: clave `notify:email_hash:<sha256>` en Redis `SET NX EX 3600`; si ya existe → no encola email (solo audit `throttled`), pero igualmente `201/202` genérico. Cuota adicional `notify:day:<hash>` máx 3/día (si excede, solo audit).
  * Contenido email dueño (único lugar donde se revela existencia, solo al dueño por canal verificado): asunto `Intentaron registrar tu dirección`, cuerpo con fecha UTC, IP-hash parcial (/24 anonimizada), user-agent familia, botones `Iniciar sesión` + `Cambiar contraseña` + `Ignorar si fuiste tú`, nota anti-phishing (nunca pide password). Sin token de verificación.
* **4.3. Falla de servicio externo o infraestructura:**
  * Postgres caído/timeout → `500 INTERNAL_ERROR` genérico (ambas ramas igual, no revela). Sin outbox. Métrica `uniqueness_probes_total{outcome=error}`.
  * Redis caído → fail-open local (token bucket en memoria 2x límite) + `WARN`, NUNCA fail-closed en MVP; contadores de notify pasan a Postgres (`SELECT COUNT(*) FROM audit_log WHERE ... 1h`, best-effort) o se permite 1 email sin throttle + alerta (decisión documentada, sin bloquear `201`).
  * Kafka/SMTP caído → no afecta `201/202` (outbox pendiente, backoff 5s/30s/5min/30min, DLQ `auth.dlq.v1`, alerta lag >60s). El email puede llegar tarde, el HTTP nunca.
* **4.4. Rate-limit / barrido automatizado:**
  * `10 req/min/IP` en `/register`, `3/hora/email_hash`, `10/hora/IP` en `/resend` → `429 + Retry-After` genérico (sin hash dummy). Contador progresivo: ` announcer:ip:<ip>` cuenta `429`s; a 50 en 15min → bloqueo `blocked:ip:<ip> EX 900` (todos los endpoints auth → `429` con `Retry-After` largo). Desbloqueo automático, sin intervención. Legítimo afectado ve el mismo `429` que atacante (sin distinción).
* **4.5. Entradas extremas / Unicode / harvesting:**
  * IDN/emoji/control → normaliza o `400` (4.1). Plus-tag y puntos se preservan (no colapsan identidades distintas en Gmail-style). Body harvesting (lista de 10k emails): cada uno paga hash dummy + jitter → costo ~150ms CPU-cliente-servidor por probe + rate-limit lo frena a ~10/min/IP → barrido masivo inviable (>16h por 10k/IP) + alerta `>100 shadow/min//24` dispara dashboard/pager.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Prohibido endpoint dedicado de disponibilidad en MVP. Cualquier `GET /check-email`, `HEAD`, o campo `available:true/false` está vetado hasta nuevo CU con captcha + auth (si se propone, debe volver a `asistente_de_preguntas`).
* **RN-02:** Unicidad sobre `email_normalized` únicamente. `email_original` nunca se usa para lookup.
* **RN-03:** Throttling notify: 1/hora + 3/día por `email_hash`. El exceso solo genera audit `throttled`, nunca `429` distinto ni email extra.
* **RN-04:** `SOFT_DELETED` en gracia se trata como existente (shadow), nunca como libre (evita re-registro que resucite datos en borrado).
* **SEC-01 (Enumeración/timing — núcleo):** Mismo schema JSON (claves, orden, longitudes aproximadas; `user_id` nunca), mismos headers (salvo `X-Request-ID` echo), hash dummy Argon2id real (no `sleep` solo) + jitter 80-120ms en AMBAS ramas, `ConstantTime` donde compare. Test bloqueante p50 diff <80ms (n=100 c/u).
* **SEC-02 (Mensajes):** Catálogo cerrado de mensajes register/resend (ver contracts CU-REG-01/02). Prohibidas cadenas `exists`, `taken`, `already`, `duplicate` hacia cliente (solo en logs internos `WARN duplicate_shadow` sin email plano).
* **SEC-03 (Perímetro):** Buckets Redis `register:ip 10/min (sliding window Lua)`, `register:email_hash 3/hora`, `resend:ip 10/hora`, `blocked:ip` tras 50x429/15min EX 900. Claves con `SHA-256(email_normalized)` + IP completa (IP no se hashea en clave pero sí en logs: `/24` + hash). Fail-open local 2x si Redis down.
* **SEC-04 (PII/forense):** Logs `INFO` con `email_domain` + `email_hash` + `ip_hash`, nunca email completo (salvo `DEBUG` local). Evento mailer lleva email plano solo al worker SMTP (canal interno). Audit lleva `email_hash + user_id? + ip_hash + result=shadow_duplicate`.
* **SEC-05 (Abuso notify):** El email al dueño nunca contiene token de verificación ni link de activación (solo login/forgot). Máx 3/día evita que un atacante spamee al dueño como vector de acoso (si se detecta patrón, el 4º+ se silencia + alerta `notify_abuse`).

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `uniqueness_probes_total{outcome="unique|shadow_duplicate|throttled_notify|error"}` Counter (INTERNA, nunca expuesta al cliente; Prometheus + dashboard privado) + `user_registration_total{status=duplicate_shadow}` (ya existe CU-REG-01, se reutiliza) + `notify_owner_enqueued_total{throttled="false|true"}` + `ip_blocks_total`.
* **Trazabilidad:** Span hijo `Domain.CheckUniqueness` dentro de `UseCase.RegisterUser` / `UseCase.ResendVerification` (no span raíz propio). Atributos: `email.domain`, `found=true/false` (solo interno, muestreado), `notify.throttled`. Hijos: `db.user.select_by_email`, `crypto.argon2id.dummy_hash`, `outbox.insert(security_attempted)?`.
* **Auditoría:** Evento `auth.audit.v1 {action:"uniqueness.probe", email_hash, user_id?, found, result:shadow|unique, ip_hash, trace_id}` + si shadow y no throttled `auth.security.registration_attempted.v1 {email_hash, user_id, ip_hash}` (el worker lo convierte en SMTP). Retención inmutable 1 año. Sin email plano en audit.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Email nuevo prosigue**
  * **Dado** `nuevo@example.com` no existe.
  * **Cuando** `POST /register` válido.
  * **Entonces** `201` genérico + fila PENDING + outbox `user.registered`, `uniqueness_probes_total{unique}` +1.
* **Escenario 2: Email existente indistinguible + notify throttled**
  * **Dado** `existe@example.com` en ACTIVE.
  * **Cuando** `POST /register` con mismo email normalizado (distinto casing/espacios) y password válida.
  * **Entonces** `201` con body byte-idéntico al éxito (excepto `X-Request-ID`), 0 filas nuevas, 0 cambios password, outbox `security.registration_attempted` + SMTP al dueño (1º/hora sí, 2º/hora solo audit throttled), `uniqueness_probes_total{shadow_duplicate}` +1, y test timing n=100: `|p50(unique)-p50(shadow)| <80ms` o el CU no se da por pasado.
* **Escenario 3: Barrido automatizado frenado y alertado**
  * **Dado** IP que prueba 60 emails distintos en 2min.
  * **Cuando** supera 10/min.
  * **Entonces** desde el 11º `429 + Retry-After`, a los 50x429 la IP queda bloqueada 15min (`ip_blocks_total` +1), dashboard alerta `>100 shadow/min//24` si distribuido, ningún `429` revela cuáles existían.
* **Escenario 4: Infra degradada no oracula**
  * **Dado** Redis caído (o Kafka caído).
  * **Cuando** se registra email nuevo y email existente.
  * **Entonces** ambos retornan `201` genérico con p95 <800ms (fail-open + outbox), 0 `400/409` espurios, `verify_redis_fallback`-análogo `uniqueness_redis_fallback_total` +1, y al recuperar no hay duplicados ni doble-notify fuera de throttle.
