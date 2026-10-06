# Spec: CU-AUTH-06 - Autenticación Reforzada (Step-Up Authentication)

## 1. Contexto y Propósito
Exigir revalidación fresca y scopeada antes de mutaciones de alto impacto en sesión. Cierra el Módulo 2 y formaliza el `fast-pass 5min` que CU-REG-06/MFA/backup usaban simplificado: ahora `auth_time≤5min` exime sin token, si no `POST /step-up/challenge` (password + 2º factor si MFA) emite `step_up_token` de un uso, 5min, una operación. Sin este CU, una sesión desatendida podría cambiar credenciales, quitar MFA o borrar la cuenta.

Decisiones (2026-10-05, todas Recommended):
- Q1 8 ops con scope (`change-password/change-email/mfa-disable/mfa-rotate/federated-link/federated-unlink/backup-regenerate/api-keys/delete-account/roles-change`), Q2 Fast-pass 5min o token scopeado, Q3 Doble (password si existe + TOTP/backup si MFA; federated-only re-login fresco), Q4 `aud=step-up` 1 uso 5min una op, Q5 Reuso locks + buckets + fail-closed sin Redis, Q6 `POST /challenge` + header `X-Step-Up-Token`, Q7 Puertos + métricas + migración viejos a token (compat fast-pass).

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado ACTIVE (Bearer válido, cualquier edad), Microservicio Auth.
* **Precondiciones:**
  * Bearer `ACTIVE` (si PENDING/LOCKED → `401/403` base, sin challenge).
  * Op objetivo ∈ lista cerrada (otra → `400 UNKNOWN_STEP_UP_SCOPE`; negocio normal nunca pide Step-Up).
  * Redis para single-use `jti` + fails; PG `users` (hash) + `mfa/backup` (2º factor); misma clave firma sesiones (Ed25519, `aud` distinto).

## 3. Flujo Principal (Happy Path)
1. Usuario intenta op crítica enviando Bearer + (si cree estar fresco, nada más). El guard de la op evalúa `now - auth_time ≤300s`: si fresco → ejecuta directo (fast-pass, sin token, audit `step_up=fast_pass`). Si viejo/ausente → `401 STEP_UP_REQUIRED {meta:{scope:<op>, max_age:300, challenge:"POST /step-up/challenge"}}` sin ejecutar nada.
2. Usuario llama `POST /api/v1/auth/step-up/challenge {scope:<op>, password?, code?}` con Bearer + `X-Request-ID`. El back valida: `scope` conocido; rate `step-up:challenge:<user> 10/min` (+ `step-up:ip 30/min`) → `429` si excede; `AttemptTracker` cuenta (reuso CU-AUTH-01: 5 fails/15min → lock cuenta exponencial, responde `401` opaco igual).
3. Valida desafíos según factores (DOBLE si ambos existen):
   * Si `password_hash` non-null exige `password` (Argon2id Verify + pepper, `ConstantTime`; malforma/vacía → `400`; errónea → `RecordFail` + `401 INVALID_STEP_UP` opaco).
   * Si `mfa_enabled` exige además `code` (TOTP 6d ventana ±1 o backup 10ch single-use-pero-sin-quemar-sesión: aquí el backup valida sin consumirlo? No: Step-Up con backup SÍ lo consume (single-use global) + alerta, documentado — usar TOTP preferente).
   * Si federated-only sin password ni MFA → el `auth_time` fresco YA es el desafío (re-login IdP reciente); con stale no hay desafío local posible → exige re-login (retorna `401 STEP_UP_REQUIRES_RELOGIN`, único caso distinto, sin emitir token).
4. Si todo OK (dummy+jitter si falla password para timing, igual login): genera `step_up_token` JWT `header{EdDSA,kid}` + `payload{sub, jti UUIDv7, aud:step-up, scope:<op exacta>, iat, exp=+300s, auth_time:now, amr_usado}` firmado, guarda `stepup:jti:<jti> EX 300` (single-use) + `ResetFails`, outbox `stepup.passed` + audit. Retorna `200 {step_up_token, scope, expires_in:300}` (solo por TLS, nunca en URL).
5. Usuario reintenta la op con `Authorization: Bearer` + `X-Step-Up-Token: <jwt>`. El guard verifica: firma/`aud=step-up`/`exp`/`sub==Bearer.sub`/`scope==op`/`jti` no usado (GET+DEL atómico; reuso → `401 STEP_UP_REUSED` — único `401` con código distinto para distinguir replay de inválido en auditoría, mismo tiempo). Si OK quema `jti` (DEL) y ejecuta la op (la op hace su Tx + su outbox + audit `step_up=token`). Sin token/fast-pass → `401`.

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** `scope` ausente/desconocido → `400 UNKNOWN_SCOPE`; `password/code` malforma según factor exigido → `400 VALIDATION_FAILED` (sin `RecordFail` si malforma, igual login); body >4KB → `413`; sin Bearer → `401 UNAUTHORIZED` (no challenge).
* **4.2. Desafío fallido / token inválido:** password mala, TOTP/backup malo o reusado, challenge con 5 fails previos (quemado lógico por lock), `step_up_token` expirado (>5min), `aud/scope/sub` mismatch, `jti` reusado, op distinta → `401 INVALID_STEP_UP` (o `STEP_UP_REUSED` solo en reuso detectado, `STEP_UP_REQUIRES_RELOGIN` solo federated-stale, `STEP_UP_REQUIRED` solo fast-pass vencido sin token). Todos sin distinguir qué factor falló (password vs TOTP mismo `401`, sin `attempts_left`). Delay 40-80ms en `401` challenge (jitter, sin Argon2 extra salvo el Verify real).
* **4.3. Infra:** PG down → `500` (sin token, sin quemar fails sin verdad); Redis down → fail-closed (no emite ni acepta tokens: `500 STEP_UP_UNAVAILABLE`, única excepción documentada + alerta; fast-pass `auth_time` local SÍ sigue (verificable offline por JWT, sin Redis) para no bloquear todo); Kafka down → `200` igual (outbox `stepup.*` pendiente); KMS/clave ausente → `500` fail-fast (nunca `none`).
* **4.4. Rate/lock:** `429` challenge por buckets (con `Retry-After`); lock cuenta 5/15min → challenges `401` opacos (igual password mala) hasta expirar + email (reuso CU-AUTH-01, throttle 1/h).
* **4.5. Migración viejos:** CU-REG-06/MFA/backup aceptaban `fast-pass` implícito; desde este CU aceptan `fast-pass` O `X-Step-Up-Token` scopeado (`federated-link`, `mfa-disable`, `backup-regenerate`, etc.). Durante 1 release aceptan ambos (compat), después solo token si `ENFORCE_STEP_UP_TOKEN=true` (documentado, no rompe MVP).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Scopes cerrados: `cred:change-password, cred:change-email, mfa:disable, mfa:rotate, federated:link, federated:unlink, backup:regenerate, apikeys:write, account:delete, roles:change` (exactos; otros → `400`).
* **RN-02:** Fast-pass `300s` (`now-auth_time`, reloj skew 30s). Token `300s`, `aud=step-up`, 1 `scope`, 1 uso (`stepup:jti` DEL atómico). Nunca en negocio general (middleware negocio lo `401` por `aud`).
* **RN-03:** Doble cuando ambos existen (password Y 2º factor); federated-only sin nada → solo re-login (sin token local). Backup usado en challenge SE consume (alerta igual login-backup).
* **RN-04:** 3 fallos challenge NO queman distinto (reusa lock 5/15min cuenta, igual login); `jti` reusado → quemado permanente (denylist 5min).
* **RN-05:** Idempotencia: `challenge` mismo RequestID no re-emite distinto token en 60s (retorna mismo si `scope` igual y no usado; si usado → nuevo exige nuevo desafío).
* **SEC-01:** Secretos solo body POST (nunca URL), solo memoria (nunca logs/spans/eventos: `password/code/token` jamás, audit con `scope, jti, amr_usado`).
* **SEC-02:** `ConstantTime` + dummy Argon2 + jitter en fails password (igual login); TOTP ±1 + replay-cache (igual MFA; el counter usado en challenge también se marca para no reusar en login).
* **SEC-03:** `sub` amarrado (token de A no sirve con Bearer de B); `scope` amarrado (token `change-password` no sirve en `delete-account`); `kid` rotativo multikid (igual Access).
* **SEC-04:** Sin escalación: el token no otorga `roles` ni amplía `scope` API (solo satisface el guard de la op); expira en 5min aunque la op sea larga (la op debe validar al inicio, no al final).

## 6. Requerimientos de Observabilidad
* **Métrica:** `step_up_total{op, result="fast_pass|issued|used|required|invalid|reused|relogin_required|rate_limited|error"}` + `step_up_duration_seconds` + `step_up_reuse_blocked_total`.
* **Trazabilidad:** Raíces `UseCase.StepUpChallenge`, `Guard.StepUpCheck(scope)` (hijos: `auth.freshness`, `crypto.verify (+totp)`, `lock.record|reset`, `crypto.sign`, `cache.jti.save|burn`, `outbox.insert`). Atributos `scope`, nunca secretos.
* **Auditoría:** `auth.audit.v1 {action:"stepup.challenge|check", scope, result, jti?, trace_id}` + eventos `stepup.passed|failed|reused` (key `user_id`). Sin `password/code/token`.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Fast-pass fresco ejecuta sin token**
  * **Dado** sesión `auth_time=1min`, op `DELETE /federated/google` (scope `federated:unlink`).
  * **Cuando** la llama solo con Bearer.
  * **Entonces** ejecuta (`200 unlinked`), audit `step_up=fast_pass`. Con `auth_time=30min` → `401 STEP_UP_REQUIRED {scope}` sin ejecutar.
* **Escenario 2: Challenge doble emite y consume 1 uso 1 scope**
  * **Dado** stale + password+MFA, scope `cred:change-password`.
  * **Cuando** `POST /challenge {scope, password:ok, code:TOTP-ok}` → token + `POST op` con `X-Step-Up-Token`.
  * **Entonces** challenge `200 {token 5min scope}` + op ejecuta 1 vez; replay mismo token → `401 STEP_UP_REUSED`; token en otra op (`change-email`) → `401`; password mala → `401 INVALID_STEP_UP` (misma que TOTP mala).
* **Escenario 3: Federated-stale exige re-login + último-factor intacto**
  * **Dado** federated-only sin password/MFA, `auth_time=1h`.
  * **Cuando** `POST /challenge {scope}`.
  * **Entonces** `401 STEP_UP_REQUIRES_RELOGIN` (sin token); tras re-login federado fresco, fast-pass ejecuta. Unlink último factor (aunque con token) → `400 LAST_AUTH_FACTOR` (Step-Up no bypasea RN CU-REG-06).
* **Escenario 4: Rate/lock + Redis-down**
  * **Dado** 11 challenges/min (mismo user) y 5 fails/15min; Redis down.
  * **Cuando** challenge 11º, challenge con buena tras lock, challenge/op con Redis down.
  * **Entonces** 11º → `429`; tras lock buena → `401` hasta expirar (no token); Redis-down challenge/token → `500 STEP_UP_UNAVAILABLE` (fail-closed) pero fast-pass local sigue `200` en ops (JWT offline). Kafka-down → `200` + outbox pendiente.

## 8. Notas de Implementación (desviaciones documentadas, 2026-10-06)

> El comportamiento observable (contratos §1-§2) **no cambia**.

* **D-01 — Rate-limit en handler/middleware, no en el servicio.**
  Los buckets (`step-up:challenge:<user>` 10/min en handler,
  `step-up:ip` 30/min en `main.go`) viven en la capa HTTP con el
  `RateLimiter` existente, igual que verify (`rl:verify:tok`) y resend.
  El servicio no recibe limiter (coherente con el resto de servicios).
* **D-02 — Verificación de factores en el servicio, sin adapter `StepUpChallenger`.**
  El plan esbozaba un puerto que adaptara Hasher+TOTP/Backup; se orquesta
  directamente en `StepUpService` con los puertos ya existentes
  (`PasswordHasher`, `TOTPProvider`, `SecretBox`, `MFASecretStore`,
  `MFAChallengeStore`, `BackupCodeIssuer/Store`), reutilizando el
  anti-replay TOTP compartido con MFA (el counter usado en challenge
  queda marcado y no sirve en `/mfa/verify`).
* **D-03 — Sin puerto `StepUpVerifier` separado.**
  La lógica `VerifyFor` (firma+`aud`+`scope`+`sub`+quema `jti`) es método
  `Check` del servicio sobre `StepUpTokenIssuer` + `StepUpJTIStore`; el
  middleware la consume vía interfaz mínima `StepUpChecker`.
* **D-04 — `kid` único (sin multikid en verificación).**
  `VerifyToken` exige `kid` igual al activo. Con TTL 5min el impacto de
  rotación (CRYP-02) es una ventana de re-challenge, documentado para
  endurecer a multikid junto a JWKS.
* **D-05 — k6 `stepup_smoke.js` creado, no ejecutado en vivo** (igual que
  `pless_smoke.js`): pendiente de ventana pre-productiva con cuentas semilla.

  **Evidencia de verificación:** `go vet ./...` limpio, `go build ./...` OK,
  `go test ./... -count=1` verde en serie (`-p 1`) y en paralelo, incl.
  E2E de guard con servicio + cripto reales
  (`require_step_up_e2e_test.go`: stale→401→challenge→token→op→replay 401).

  **Security Gate 🟢 PASSED (STRIDE):** scopes cerrados; doble-factor cuando
  ambos existen (password Y 2º, mismo 401 opaco); `aud=step-up` aislado de
  negocio y de Access; 1-uso-1-op-1-`sub` (Lua GET+DEL, reuso → `REUSED`
  distinto solo en auditoría); sin `password/code/token` en logs, métricas,
  spans ni outbox (solo `scope/jti/amr`); fail-closed sin Redis con fast-pass
  offline intacto; `no-store` siempre; locks exponenciales reutilizados.
