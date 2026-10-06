# Spec: CU-AUTH-02 - Autenticación Multifactor (MFA / TOTP)

## 1. Contexto y Propósito
Completar el login iniciado en CU-AUTH-01 cuando `mfa_enabled=true` y gestionar el ciclo de vida TOTP (setup/enable/verify/disable). El pre-token `aud=mfa-challenge` de 5min es el único pase al `POST /mfa/verify`; la sesión final la emite CU-AUTH-04. Sin este CU, el `202 mfa_required` sería un callejón. Compatible con apps estándar (RFC6238 SHA1 6 dígitos 30s).

Decisiones (2026-10-05, todas Recommended):
- Q1 Completo SHA1 6/30 secreto 20B ventana ±1, Q2 Pre-token 5min single-use por `challenge_id`, Q3 ±1 + replay-cache 90s + 5 fallos queman, Q4 Step-Up 5min + secreto cifrado AES-GCM + enable con 1 código + disable respeta último-factor, Q5 Ventana absorbe skew + fail-closed reuso, Q6 4 rutas + 401 genérico, Q7 3 puertos + métricas/audit sin secreto.

## 2. Actores y Precondiciones
* **Actores:** Usuario (con app TOTP), Microservicio Auth, Worker (eventos/emails).
* **Precondiciones:**
  * Verify: `users.status=ACTIVE`, `mfa_enabled=true` (o `pending_enable` con secreto staged, ver setup), posee `mfa_token` vigente no quemado (emitido <5min por CU-AUTH-01).
  * Setup/enable/disable/list: Bearer `ACTIVE` + Step-Up `auth_time≤5min` (igual CU-REG-06; `GET` estado MFA permite Bearer normal).
  * Relojes con NTP (skew >30s se absorbe por ventana, >90s falla cerrado).

## 3. Flujo Principal (Happy Path)
### A. Setup + Enable (enrollment, una vez por activación)
1. Usuario (sesión fresca) llama `POST /api/v1/auth/mfa/totp/setup` (auth+Step-Up). El back genera `secreto=20B CSPRNG` (160-bit), lo cifra `AES-256-GCM (KMS/env MFA_SECRETS_KEY, nonce 12B, AAD=user_id)` y lo guarda staged `mfa_totp_secrets(user_id, secret_enc, staged=true, verified=false)` + `otpauth://totp/<issuer>:<email>?secret=<b32>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30` (+ `qr_svg` data-uri opcional generado server-side sin secreto en logs). Retorna `200 {secret_b32 (solo esta vez), otpauth_url, qr_svg?, expires_in:600}` (staged TTL 10min; si no hace enable, expira y se purga).
2. Usuario escanea QR y llama `POST /totp/enable {code:6d}` (misma sesión fresca). El back descifra staged, valida TOTP ventana ±1 ConstantTime (ver 5), si OK marca `verified=true, enabled=true`, setea `users.mfa_enabled=true`, genera backup codes (delega a CU-AUTH-03: crea 10 hashes, los retorna SOLO aquí una vez), quema staged→activo, outbox `mfa.enabled` + audit. Retorna `200 {status:enabled, backup_codes:[...]}` (única exhibición).
### B. Verify (cada login con MFA)
3. Usuario envía `POST /api/v1/auth/mfa/verify {mfa_token, code:6d}` (SIN Bearer; el `mfa_token` es la auth) + `X-Request-ID`.
4. El back valida `mfa_token`: firma, `aud==mfa-challenge`, `exp`, `sub` existe ACTIVE, `challenge_id` no quemado (Redis `mfa:challenge:<id>` debe existir; si miss/expirado → `401 MFA_CHALLENGE_EXPIRED` genérico — mismo body que código malo, ver 4.2). Rate-limit `mfa:verify:challenge 5/min` + `mfa:verify:ip 20/min` antes de cripto (excede → `429`).
5. Calcula `counter=floor((now+5s leeway)/30)` y valida `code` contra `counter-1,0,+1` con secreto descifrado (HMAC-SHA1 Dynamic Truncation RFC4226, `ConstantTimeCompare` por candidato). Si ningún candidato → `RecordFail` (INCR `mfa:fails:<challenge>`; a 5 → quema challenge `DEL + denylist 5min` + `401` igual) + `401 INVALID_MFA` + audit.
6. Anti-replay: `replayed = EXISTS mfa:used:<user_id>:<counter_matched>` (Redis `SET NX EX 90`); si ya existe → `401 INVALID_MFA` aunque el código sea correcto (quemado) + audit `replay`. Si no, `SET NX` lo marca consumido (DB fallback `mfa_used_counters(user_id,counter)` UNIQUE si Redis down — ver 4.3).
7. Éxito: quema challenge (`DEL mfa:challenge:<id>` + denylist), `ResetFails`, llama `SessionIssuer.Issue` (CU-AUTH-04) → `200 {status:active}` + cookies sesión (igual login sin MFA). Outbox `mfa.verified` + audit. El `mfa_token` no sirve para nada más (reuso → `401`).
### C. Disable / estado
8. `DELETE /totp {current_password?}` (auth+Step-Up; si es último factor sin password → `400 LAST_AUTH_FACTOR`, igual CU-REG-06) → borra secreto + `mfa_enabled=false` + quema backup restantes (CU-AUTH-03) + email aviso + `200 {status:disabled}`. `GET /mfa/status` (auth normal) → `{enabled, methods:[totp]}` sin secreto.

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * `code` no `^[0-9]{6}$`, `mfa_token` ausente/malformado, setup sin Step-Up, body >4KB → `400 VALIDATION_FAILED` o `401 STEP_UP_REQUIRED / MFA_CHALLENGE_EXPIRED` según caso (forma nunca consume intento challenge; Step-Up no crea staged).
* **4.2. Código/challenge inválido (opaco):**
  * Challenge expirado (>5min), quemado (ya usado o 5 fallos), `aud` erróneo, Bearer normal en `/verify`, código erróneo, código reusado en misma ventana, `counter` fuera de ±1 (reloj muy desviado) → SIEMPRE `401 {code:INVALID_MFA, message:"Código inválido o expirado."}` idéntico (sin distinguir expirado/malo/replay/quemado). No incluye `attempts_left`. Delay 20-50ms uniforme en `401` verify (jitter ligero, no Argon2 aquí). 5º fallo quema igual con mismo `401` (no avisa que quemó).
* **4.3. Falla de servicio externo o infraestructura:**
  * Postgres (secretos) down → `500 INTERNAL_ERROR` (sin emitir sesión, sin quemar challenge en éxito imposible; fails no se cuentan sin verdad).
  * Redis down: challenge single-use pasa a DB (`mfa_challenges(challenge_id PK, consumed)`; si DB confirma no-consumido permite 1 vez); replay-cache pasa a `mfa_used_counters UNIQUE(user_id,counter)` (fail-closed reuso: si no puede comprobar, el PRIMER uso permite con `WARN`, el REUSO sospechoso → `500 REPLAY_UNCHECKABLE` en vez de `401` para no enmascarar riesgo — documentado, único `500` con código distinto). Rate-limit fail-open local 2x.
  * Kafka down → `200` igual (outbox `mfa.*` pendiente). KMS/env key ausente al arrancar → el servicio no levanta (`fail-fast`, sin modo plano).
* **4.4. Rate-limit:** `mfa:verify:challenge` 5/min, `mfa:verify:ip` 20/min, `setup/enable` 10/hora/user → `429 + Retry-After`. Sin distinguir staged/no-staged.
* **4.5. Bordes enrollment:** setup con MFA ya `enabled` → `400 MFA_ALREADY_ENABLED` (debe disable primero o regenerar vía `POST /totp/rotate`, mismo flujo setup con Step-Up que supersede staged). Enable sin staged o staged expirado (10min) → `400 NO_STAGED_SECRET`. Enable con código válido pero de otro secreto (staged superseded) → `401`. Disable del único factor → `400 LAST_AUTH_FACTOR` (igual CU-REG-06).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** TOTP `SHA1, 6 dígitos (mod 10^6, zero-pad), step 30s, secreto 20B, ventana ±1 (3 counters), leeway +5s`. `issuer` configurable (`MFA_ISSUER=Example`), label `issuer:email_normalized`.
* **RN-02:** Pre-token `aud=mfa-challenge` TTL 300s, `challenge_id` UUIDv7 single-use (Redis `mfa:challenge:<id> EX 300` creado al emitir en CU-AUTH-01; verify lo `DEL`). Nunca aceptado fuera de `/mfa/verify` (middleware negocio lo `401` por `aud`).
* **RN-03:** Anti-replay `(user_id, counter)` UNIQUE lógico 90s (Redis `mfa:used:<u>:<c> NX EX 90` + tabla `mfa_used_counters` fallback). Reuso → `401` aunque cripto OK.
* **RN-04:** 5 fallos por challenge → quema (`DEL challenge + denylist:<id> EX 300`) + exige nuevo login (nuevo pre-token). Fails por `challenge_id` (no por cuenta global; el bloqueo cuenta global lo hace CU-AUTH-01/SEC-01).
* **RN-05:** Setup staged 10min (`mfa_totp_secrets.staged=true, staged_expires_at`); enable lo promueve (`staged=false, verified=true, enabled_at`) y setea `users.mfa_enabled=true` en la misma Tx + crea backups (CU-AUTH-03). Solo 1 staged activo (nuevo supersede anterior).
* **RN-06:** Disable exige Step-Up + respeta último-factor (password o federado restante, igual CU-REG-06); al deshabilitar quema `used` futuros no (counters pasados expiran solos) + revoca staged + email aviso siempre.
* **SEC-01:** Secreto cifrado `AES-256-GCM` (`key 32B` env/KMS `MFA_SECRETS_KEY`, `nonce 12B` aleatorio por fila, `AAD=user_id`, `ciphertext+nonce` en `secret_enc`). Nunca en logs/spans/eventos/QR-logs (solo `secret_b32` una vez en `setup` response por TLS). Descifrado solo memoria request.
* **SEC-02:** `ConstantTimeCompare` en códigos; `code` solo memoria (nunca log, `password`-like); `otpauth_url` no se persiste (se regenera); QR SVG sin secreto en nombre archivo.
* **SEC-03:** Step-Up `auth_time≤300s` en setup/enable/disable (no en verify — allí el pre-token ES la frescura). `current_password` NO se exige aquí (el usuario ya probó password hace <5min en login; setup con sesión vieja larga sí exigiría re-login, documentado).
* **SEC-04:** `mfa_token` y `code` nunca en URL (solo body POST; los GET están vetados en este CU salvo `GET /status` sin secretos).

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `mfa_total{op="setup|enable|verify|disable|status", result="ok|already|invalid|expired|replay|locked_challenge|rate_limited|last_factor|error"}` + `mfa_verify_duration_seconds` + `mfa_challenges_burned_total{reason="consumed|fails|expired"}` + `mfa_replay_blocked_total`.
* **Trazabilidad:** Raíces `UseCase.MFASetup`, `UseCase.MFAEnable`, `UseCase.MFAVerify`, `UseCase.MFADisable` (hijos: `auth.stepup.check`, `mfa.secret.generate|encrypt|decrypt`, `mfa.challenge.validate|burn`, `crypto.totp.validate (counters tried)`, `replay.check|mark`, `db.mfa.upsert|promote|delete`, `session.issue` (verify-ok), `outbox.insert`). Atributos `counters_tried, window`, nunca secreto/código.
* **Auditoría:** `auth.audit.v1 {action:"mfa.setup|enable|verify|disable", result, counter?, challenge_id?, trace_id}` + eventos `mfa.enabled|verified|disabled|failed|replay_blocked` (key `user_id`). Sin `secret/code/token`.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Enrollment + primer verify**
  * **Dado** ACTIVE sin MFA, sesión fresca.
  * **Cuando** `POST /setup` → `200 {secret, otpauth}` + genera código app del `counter` actual + `POST /enable {code}`.
  * **Entonces** `200 {enabled + backup_codes×10 (una vez)}`, `mfa_enabled=true`, secreto cifrado en DB (inspección: `secret_enc` no contiene `secret_b32`), siguiente `POST /login` password OK → `202 mfa_required` (no 200).
* **Escenario 2: Verify OK emite sesión y quema**
  * **Dado** MFA enabled + `mfa_token` fresco (<5min) + código válido inédito.
  * **Cuando** `POST /verify {mfa_token, code}`.
  * **Entonces** `200 active` + cookies (CU-AUTH-04), challenge quemado (replay mismo body → `401`), mismo código en misma ventana → `401 replay` aunque cripto OK, `mfa_token` en API negocio → `401`.
* **Escenario 3: Ventana ±1 y relojes**
  * **Dado** códigos de `counter-1` y `counter+1` (simula ±30s skew) inéditos.
  * **Cuando** se verifican con challenges frescos distintos.
  * **Entonces** ambos `200` (tolerancia); código de `counter-2` → `401`. Con `counter` correcto pero challenge con 5 fallos previos → `401` quemado + exige nuevo login.
* **Escenario 4: Step-Up y último-factor**
  * **Dado** sesión de 30min (stale), cuenta solo-password+MFA (sin federados).
  * **Cuando** `POST /setup` stale y `DELETE /totp` fresco siendo MFA el 2º factor (queda password) vs cuenta solo-MFA-sin-password.
  * **Entonces** setup stale → `401 STEP_UP_REQUIRED`; disable con password restante → `200 disabled` + email; disable siendo único factor → `400 LAST_AUTH_FACTOR` + 0 cambios.
* **Escenario 5: Infra degradada**
  * **Dado** Redis down / Kafka down.
  * **Cuando** verify válido.
  * **Entonces** Redis-down primer uso → `200` vía DB fallback + `WARN` (reuso inmediato → `500 REPLAY_UNCHECKABLE` documentado, no `401` silencioso); Kafka-down → `200` + outbox pendiente (<60s). PG-down → `500` sin sesión.
