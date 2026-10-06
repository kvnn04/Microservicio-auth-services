# Spec: CU-REG-01 - Registro Clásico con Credenciales

## 1. Contexto y Propósito
Permitir a un usuario anónimo crear una cuenta con correo electrónico y contraseña de forma segura, verificable y sin fricción innecesaria. Es la puerta de entrada al ecosistema Auth & Identity: toda identidad nace aquí en estado `PENDIENTE_DE_VERIFICACION` y ningún derecho de sesión se otorga hasta completar CU-REG-02. Aporta valor al negocio garantizando unicidad real sin revelar existencia de cuentas y desacoplando el envío de correos del camino crítico (OVERVIEW: nunca bloquear login por tareas secundarias).

Decisiones acordadas con usuario (2026-10-05):
- Q1 Estricta recomendada, Q2 Respuesta genérica idéntica, Q3 Argon2id, Q4 Outbox + worker, Q5 POST /api/v1/auth/register, Q6 4 puertos, Q7 TTL 15min / 3 intentos.

## 2. Actores y Precondiciones
* **Actores:** Usuario Anónimo, Microservicio de Autenticación, Worker asíncrono (email / Kafka), Proveedor SMTP.
* **Precondiciones:**
  * El usuario no cuenta con sesión iniciada (sin `Authorization: Bearer` válido).
  * Versiones legales activas disponibles (terms_version, privacy_version) para vincular consentimiento mínimo de registro (enlace con CU-REG-05, no bloquea este CU si CU-REG-05 aún no existe: se registra `terms_accepted_at` + versión).
  * Infraestructura nominal: Postgres alcanzable, Redis alcanzable (rate-limit), Kafka alcanzable o degradable vía outbox.

## 3. Flujo Principal (Happy Path)
1. El actor envía `POST /api/v1/auth/register` con `{email, password, terms_accepted: true, terms_version, privacy_version}` + header `X-Request-ID: UUIDv4`.
2. El sistema aplica rate-limit por IP (Redis, ver SEC-04) y valida sintaxis/presencia de campos. Si excede, `429`.
3. El sistema normaliza email: `trim` espacios, `lowercase` completo (Unicode Simple Case Folding), valida longitud ≤254, valida formato RFC 5322 simplificado `^[^\s@]+@[^\s@]+\.[^\s@]{2,}$`, rechaza caracteres de control / nulos. NO elimina `+tag` ni puntos locales (se preservan). Guarda `email_normalized` como clave de unicidad y `email_original` para display.
4. El sistema valida password: longitud 12..128 caracteres (conteo en runas, no bytes), al menos 1 mayúscula, 1 minúscula, 1 dígito, 1 símbolo (`[^A-Za-z0-9]`), sin espacios de control, sin secuencias triviales de más de 3 repetidos. Calcula chequeo HIBP k-anonymity (prefijo SHA-1 5 chars) o, si HIBP no disponible, rechaza contra lista local top-10k + `password == email_local_part` normalizado.
5. El sistema ejecuta mitigación de enumeración: busca `email_normalized` en repositorio. Si existe o no existe, el camino computacional es idéntico: ejecuta `PasswordHasher.Hash(dummy_password)` con mismos parámetros Argon2id y aplica delay aleatorio uniforme 80-120ms para homogeneizar tiempo.
6. Si no existía: genera `user_id = UUIDv7`, `password_hash = Argon2id(password, salt 16B aleatorio CSPRNG, m=65536 KiB, t=3, p=4, hash 32B, encoding PHC $argon2id$v=19$...)`, crea entidad `User{status=PENDING_VERIFICATION, password_algo=argon2id, terms_version, created_at=now UTC}` y persiste en Postgres + inserta fila outbox `auth.user.registered.v1` en la MISMA transacción.
7. Genera token de verificación opaco 32B (CSPRN G, base64url sin padding) con `expires_at = now + 15min`, `max_attempts=3`, `attempts=0`, `consumed=false`, persiste hash SHA-256 del token (nunca el token plano) ligado a `user_id`.
8. Retorna `201 Created` con body genérico (idéntico al caso duplicado salvo `user_id` interno no revelador — ver 4.2) y publica vía outbox/worker los eventos `auth.user.registered.v1` y `auth.email.verification_requested.v1`. El envío SMTP lo hace el worker, nunca el request HTTP.
9. La cuenta queda en `PENDING_VERIFICATION`: cualquier intento de login emite error genérico y reenvía recordatorio de verificación sin otorgar tokens (ver CU-AUTH-01).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * Condición: email malformado, >254, password <12 o sin clases, `terms_accepted=false`, `X-Request-ID` ausente/inválido, JSON malformado, Content-Type != application/json.
  * Respuesta: `400 Bad Request` con payload estándar `{"success":false,"error":{"code":"VALIDATION_FAILED","message":"...","details":[{"field":"email|password|terms_accepted","reason":"..."}]}}`. No indica si el email existe. Tiempo de respuesta <50ms sin hash dummy.
* **4.2. Conflicto o unicidad (cuenta ya existente):**
  * Condición: `email_normalized` ya registrado en cualquier estado (`PENDING_VERIFICATION`, `ACTIVE`, `LOCKED`, `SOFT_DELETED` dentro de gracia).
  * Respuesta: manejo defensivo OBLIGATORIO — `201 Created` idéntico al éxito con mismo schema `{success:true, data:{status:"pending_verification", message:"Si el email es válido recibirás instrucciones"}}`, sin `user_id` real (se devuelve UUID señuelo o se omite; contrato define no exponer `user_id` en este endpoint — solo `status`). Ejecuta hash dummy + delay 80-120ms. Asíncronamente envía email de seguridad al dueño legítimo ("alguien intentó registrar esta dirección, si fuiste tú ignora / si no fuiste tú accede o cambia clave") vía Kafka. NUNCA `409 Conflict` en este CU (reservado para CU-REG-03 interno, no expuesto).
  * Concurrencia: 5 invocaciones simultáneas mismo email → constraint único `UNIQUE(email_normalized)` + `INSERT ... ON CONFLICT DO NOTHING` + idempotencia por `X-Request-ID` (tabla `idempotency_keys` TTL 24h en Postgres/Redis). Todas retornan misma respuesta genérica.
* **4.3. Falla de servicio externo o infraestructura:**
  * Condición: Postgres caído / timeout >2s, Redis caído, Kafka caído, HIBP timeout >800ms, SMTP caído.
  * Respuesta:
    * Postgres falla → `500 Internal Server Error` `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"No pudimos procesar tu solicitud"}}` sin trazas, sin SQL state. No se crea usuario.
    * Redis caído → degradación fail-open a memoria local (token bucket local por instancia, límite 2x) + log WARN, NO bloquear registro. Fail-closed solo si `ENV=production-strict`.
    * Kafka caído → NO rollback (outbox ya persistido). Request retorna `201` normalmente; worker reintenta con backoff exponencial 5s, 30s, 5min, 30min (máx 24h, DLQ `auth.dlq.v1`). Métrica `outbox_lag_seconds` alerta si >60s.
    * HIBP timeout → fallback a lista local top-10k + permite continuar + log WARN + métrica `hibp_fallback_total`.
    * SMTP caído → irrelevante para HTTP (async worker lo reintenta).
* **4.4. Rate-limit excedido:**
  * Condición: >10 req/min/IP en `/register` o >3 req/hora mismo email_normalized (ventana deslizante Redis).
  * Respuesta: `429 Too Many Requests` + header `Retry-After: <segundos>` + `X-RateLimit-Remaining: 0`. Body `RATE_LIMITED`. No distingue existencia.
* **4.5. Payload extremo / Unicode:**
  * Email con Unicode (IDN): se convierte a punycode (UTS-46) antes de validar, límite 254 en ASCII. Emojis/control → `400`. Password con Unicode: se permite (NFKC normalize), conteo en runas, bytes ≤512. Body >32KB → `413 Payload Too Large`.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Toda cuenta nace en `PENDING_VERIFICATION`. Prohibido emitir Access/Refresh tokens hasta `ACTIVE` (verificación CU-REG-02).
* **RN-02:** Unicidad canónica sobre `email_normalized`. `email_original` solo display, nunca clave.
* **RN-03:** `terms_accepted=true` + `terms_version` + `privacy_version` obligatorios; se persiste `terms_accepted_at`, `ip_address` (anonimizada /24), `user_agent_hash`. Sin consentimiento no hay INSERT.
* **RN-04:** Token de verificación: opaco 32B, TTL 15min exactos, un solo uso, máximo 3 intentos; al 3er fallo se invalida y exige reenvío (CU-REG-02).
* **RN-05:** Idempotencia por `X-Request-ID` UUIDv4 24h; reintento mismo key retorna misma respuesta sin duplicar usuario/evento.
* **SEC-01 (Enumeración/timing):** Respuesta éxito/duplicado bit-idéntica en schema y tiempo (hash dummy Argon2id + jitter 80-120ms). Mensajes nunca dicen "email ya registrado". Error login posterior también genérico.
* **SEC-02 (Hashing):** Argon2id `m=65536 (64 MiB), t=3, p=4, salt 16B CSPRNG, output 32B, formato PHC`. Nunca loguear password, hash, token plano. Comparación con `subtle.ConstantTimeCompare` donde aplique. `pepper` opcional vía HSM/env `PASSWORD_PEPPER` (32B) concatenado pre-hash si está configurado.
* **SEC-03 (Fuerza bruta):** Rate-limit Redis `register:ip:<ip>` 10/min, `register:email:<hash>` 3/hora, bloqueo progresivo (ver CU-SEC-01/02). Contadores en Redis con TTL automático, claves con hash SHA-256 del email, nunca email plano en Redis keys logs.
* **SEC-04 (Inyección/Masivo):** Validación estricta Content-Type, límite body 32KB, escape parametrizado SQL (pgx prepared), sin concatenación. Normalización NFKC previa a validación para evitar bypass Unicode.
* **SEC-05 (PII):** Logs y eventos nunca contienen `password`, `password_hash`, token plano. Email solo en evento de verificación dirigido al dueño; evento de auditoría usa `user_id` + `email_hash (SHA-256)` no reversible.

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `user_registration_total{status="success|validation_failed|rate_limited|duplicate_shadow|error"}` (Counter, Prometheus). Adicionales: `user_registration_duration_seconds` (Histogram buckets 0.05,0.1,0.2,0.5,1,2), `hibp_fallback_total`, `outbox_lag_seconds`, `registration_email_enqueued_total`.
* **Trazabilidad:** Span raíz `UseCase.RegisterUser` (OpenTelemetry). Hijos obligatorios: `db.user.insert` (Postgres, incluye `db.statement` sanitizada sin PII), `crypto.argon2id.hash` (atributo `argon2.memory=65536`), `cache.ratelimit.check`, `outbox.insert`, `kafka.produce` (solo en worker, no bloquea HTTP). Propagación `trace_id` + `X-Request-ID` en logs.
* **Auditoría:** Evento obligatorio `auth.audit.v1` con `{action:"user.register", user_id, email_hash, ip_hash, user_agent_hash, terms_version, result, trace_id, occurred_at}` a tópico `auth.audit.v1`. Retención inmutable. Prohibido `password`, `token`, `email` plano en audit (solo hash).
* **Logs estructurados:** JSON con `level, trace_id, request_id, use_case=RegisterUser, action, duration_ms, status`. `INFO` éxito, `WARN` rate-limit/duplicate-shadow/fallback, `ERROR` postgres/outbox fail con `error.code` sin stack al cliente.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Ejecución exitosa**
  * **Dado** que no existe `Test@Example.com` (normalizado `test@example.com`) y el payload es `{email:"Test@Example.com ", password:"Str0ng!Passw0rd-2026", terms_accepted:true}` con `X-Request-ID` nuevo.
  * **Cuando** se procesa `POST /api/v1/auth/register`.
  * **Entonces** retorna `201` con `{success:true,data:{status:"pending_verification"}}`, en Postgres existe fila `users(status=PENDING_VERIFICATION, email_normalized=test@example.com, algo=argon2id)` + fila outbox, Argon2 verifica password, y en Kafka (vía worker) aparecen `auth.user.registered.v1` y `auth.email.verification_requested.v1` en <30s, sin otorgar tokens de sesión.
* **Escenario 2: Intento con datos duplicados (defensivo)**
  * **Dado** que `test@example.com` ya existe en `ACTIVE`.
  * **Cuando** se solicita registro con mismo email (cualquier casing/espacios) y password válida distinta.
  * **Entonces** retorna `201` con body indistinguible del éxito (mismo schema, sin `user_id`), latencia dentro de ±60ms del éxito (p50, n=100), no crea segunda fila, no cambia password existente, y se encola email de seguridad al dueño. Un atacante con timing no distingue (test k6: p95 diff <80ms).
* **Escenario 3: Validación fallida**
  * **Dado** payload `{email:"no-es-email", password:"123"}`.
  * **Cuando** se procesa la solicitud.
  * **Entonces** retorna `400 VALIDATION_FAILED` con `details[2]` (email, password), no toca Postgres (0 inserts), no emite eventos, métrica `user_registration_total{status="validation_failed"}` +1.
* **Escenario 4: Kafka caído no bloquea registro**
  * **Dado** que Kafka está caído (broker unreachable) pero Postgres sano.
  * **Cuando** se registra un email nuevo válido.
  * **Entonces** retorna `201` en <500ms p95, usuario en `PENDING_VERIFICATION` + outbox `pending`, worker reintenta y al recuperar Kafka el evento se publica sin duplicar usuario (idempotencia por `event_id` + `dedupe_key=user_id`).
* **Escenario 5: Rate-limit**
  * **Dado** que una IP ya hizo 10 POST /register en 60s.
  * **Cuando** hace el 11º intento.
  * **Entonces** retorna `429 RATE_LIMITED` + `Retry-After`, no ejecuta hash Argon2 (fast-reject), métrica `status="rate_limited"` +1.
