# Spec: CU-AUTH-05 - Inicio de Sesión sin Contraseña (Passwordless)

## 1. Contexto y Propósito
Otorgar acceso con un secreto efímero enviado al correo verificado (link 32B + OTP 8d), sin password. TTL ultra-corto 10min, un solo uso, ligado a huella de emisión, opaco a enumeración y respetuoso de MFA (si hay MFA es solo primer factor). Reutiliza el músculo probado de CU-REG-02 (Redis verdad + PG backup + outbox) con tabla y eventos propios.

Decisiones (2026-10-05, todas Recommended):
- Q1 Solo email MVP dual, Q2 TTL 10min 1 activo, Q3 `202` opaco total + throttle, Q4 Context-binding alerta sin bloqueo (`risk=high` si difiere), Q5 Respeta MFA (MFA→`202 mfa_required`, sin MFA→`200`), Q6 Tabla propia mismo patrón + quotas 60s/5-24h, Q7 `start` + `verify` (+GET alias) con `400` genérico + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Usuario (con acceso al correo), Microservicio Auth, Worker SMTP.
* **Precondiciones:**
  * Solo `users.status=ACTIVE` con email verificado reciben correo (clásicas verificadas CU-REG-02 o federadas `verified=true`; federadas `verified=false`/PENDING/LOCKED/borradas → `202` genérico sin correo).
  * Sin sesión requerida (anónimo). `passwordless_tokens` con ≤1 activo por `user_id` (`active` pointer Redis+PG).

## 3. Flujo Principal (Happy Path)
1. Usuario envía `POST /api/v1/auth/passwordless/start {email}` + `X-Request-ID` (≤2KB). El back valida forma (normaliza igual CU-REG-01; malforma → `400 VALIDATION_FAILED` rápido).
2. Rate-limit `pless:start:ip 10/hora` + `pless:start:email_hash 3/hora` (más duro que register: es emisor de correos) → excede `429 + Retry-After` (sin revelar).
3. Lookup `users by email_normalized` (guarda `eligible = ACTIVE && email_verified`); camino homogéneo: dummy CSPRNG + `jitter 60-100ms` ambas ramas (más ligero que Argon2 porque no hay hash que igualar, pero con jitter + trabajo constante para timing).
4. Si `eligible` + quota (`last_sent>60s` y `sends_24h<5`, Redis `pless:sent:<uid>`, `pless:count:<uid:day>`) → genera par `token 32B + otp 8d` (igual CU-REG-02: `SHA-256` hashes, `expires=now+10min`, `attempts=0/3`, `ctx{ip/24_hash, ua_hash}`), dual-write Redis (`pless:t:<hash>`, `pless:o:<hash>`, `pless:active:<uid>` supersede previo EX 600) + PG Tx (`passwordless_tokens` + outbox `passwordless.requested`) y encola SMTP (link `https://front/passwordless?token=` + código legible + `expira 10min` + `si no fuiste tú ignora`). Si no eligible o throttled → nada (solo audit `not_sent`), pero responde igual `202`.
5. Retorna `202 {status:if_exists_sent}` idéntico siempre + `Cache-Control: no-store`.
6. Usuario abre `GET /passwordless?token=` o envía `POST /passwordless/verify {token|code}` (+ `X-Request-ID`). El back valida forma (32B b64url u 8d), rate `pless:verify:ip 20/min` + `pless:verify:tok 5/min`, lookup Redis→fallback PG read-through (igual CU-REG-02), `ConstantTime` + `delay 40-80ms` en `400`.
7. Si vivo (`!consumed && !burned && now<exp && attempts<3`): compara contexto: `risk = (ip/16 difiere || ua_familia difiere) ? high : low` (permite igual, marca). Tx atómica: `UPDATE users SET last_login=now (sin cambiar status)` + `UPDATE passwordless_tokens SET consumed` + supersede resto + outbox (`passwordless.consumed` + `session.*` o `mfa.*` + `audit{ctx_match, risk}` + si `risk=high` outbox `security.context_mismatch` → email alerta). Invalida Redis (DEL t/o/active).
8. Bifurca MFA (igual login): si `mfa_enabled` → `202 {mfa_required, mfa_token 5min}` (sin sesión); si no → `Issue` (CU-AUTH-04, `method=passwordless_email`, `amr=[email-otp]`) → `200 active` + cookies/body híbrida. Reuso mismo token/OTP imposible (quemado; replay → `400` o `already` solo si mismo RequestID idempotente).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida:** email malformado, `token/code` malforma, ambos/ninguno, body >4KB → `400 VALIDATION_FAILED` (sin consumir intento). Sin `X-Request-ID` se genera (sin idempotencia estricta).
* **4.2. Inválido/expirado/consumido/quemado (opaco):** hash miss (Redis+PG), `exp`, `consumed`, `attempts>=3` (3 fallos queman, igual verify), `superseded`, cuenta ya no-ACTIVE al consumir → `400 INVALID_OR_EXPIRED` idéntico (mismo body/tiempo, sin `404/410`, sin `user_id`). Segundo uso del que activó → `400` (no `already_verified` aquí salvo mismo RequestID replay → `200` idempotente del primer resultado).
* **4.3. Infra:** PG down → `500` (`start` sin crear, `verify` sin consumir); Redis down → fallback PG read-through + fail-open rate local (igual verify) + `WARN`; Kafka/SMTP down → `202/200` igual (outbox pendiente, email puede tardar); HIBP no aplica.
* **4.4. Rate/quota:** `429` en start/verify por buckets (con `Retry-After`); quota `60s/5-24h` NO da `429` distinto (sigue `202` genérico + `throttled` interno, para no oracular elegibilidad).
* **4.5. Contexto high-risk:** consumo desde red/UA radicalmente distinta → `200/202` igual + email `Nuevo acceso sin contraseña desde ... (¿fuiste tú?)` + audit `risk=high` (CU-SEC-03/07 endurecen a desafío después; aquí no bloquea).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Email-only, dual `32B link + 8d OTP` mismo registro (cualquiera consume, ambos queman), TTL `600s`, 1 activo (`supersede` anterior al emitir).
* **RN-02:** Elegibilidad `ACTIVE + email_verified=true` (clásica verificada o federada verified). PENDING/LOCKED/borrada/federada-no-verificada → `202` sin correo (ni siquiera throttled-notify al dueño aquí; el notify de intento-registro lo cubre CU-REG-03).
* **RN-03:** Single-use + `attempts≤3` (3º quema, exige `start` nuevo). Idempotencia RequestID 24h (mismo RequestID replay → mismo `202/200` sin re-emitir/re-consumir).
* **RN-04:** MFA nunca saltado (`mfa→202`, igual login). `amr=[email-otp]` en Access cuando directo (distingue de `pwd` en auditoría).
* **RN-05:** Quotas `60s` cooldown + `5/24h` por cuenta (por `user_id` si eligible sino por `email_hash` para no distinguir). Exceso → `202` + `throttled` interno.
* **SEC-01:** Opaco total (misma 202/400/delay que verify; `ConstantTime`, hashes `SHA-256`, sin `sub/email` en errores; `code/token` solo body POST salvo GET-alias link que es idempotente y single-use).
* **SEC-02:** Context-binding `ip/24+ua_familia` en emisión, comparado laxamente (`/16` + familia) con `risk` (sin PII completa en logs: hashes). Prefetch email: GET-alias idempotente (doble apertura → `400` salvo replay RequestID, documentado; el front debe hacer `POST verify` tras landing para evitar quemas por prefetch — el email advierte `si el botón no funciona copia el código`).
* **SEC-03:** Almacenamiento solo hashes (igual verify), token 32B CSPRNG + OTP 8d CSPRNG, SMTP con link+OTP y expiración visible, plano nunca en Kafka (worker lo resuelve interno igual CU-REG-02).
* **SEC-04:** `passwordless_tokens` sin `UPDATE` salvo `consumed/burned` (append + flags, auditoría); ` risk=high` no eleva a `401` (disponibilidad primero, detección después).

## 6. Requerimientos de Observabilidad
* **Métrica:** `passwordless_total{op="start|verify", result="sent|throttled|not_eligible|success|mfa_required|invalid|rate_limited|error"}` + `passwordless_duration_seconds` + `pless_context_mismatch_total{risk=high}` + `pless_redis_fallback_total`.
* **Trazabilidad:** Raíces `UseCase.PasswordlessStart/Verify` (hijos: `ratelimit`, `db.user.lookup`, `crypto.rand`, `cache+db.token.save|lookup|consume`, `ctx.compare`, `session.issue|mfa.issue`, `outbox.insert`). Atributos `risk, ctx_match`, nunca secreto.
* **Auditoría:** `auth.audit.v1 {action:"passwordless.start|verify", email_hash, user_id?, result, risk?, trace_id}` + eventos `passwordless.requested|consumed` + `security.context_mismatch` cuando `high` (key `user_id`/`email_hash`). Sin token/código.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Start+link directo sin MFA**
  * **Dado** ACTIVE sin MFA verificado, quotas libres.
  * **Cuando** `POST /start {email}` → `202` + Mailhog link/OTP + `POST /verify {token}` <10min mismo contexto.
  * **Entonces** `200 active` + cookies (Issue `amr=[email-otp]`), token quemado (reuso → `400`), `pless_total{sent,success}` +1, Redis claves DEL + PG `consumed`.
* **Escenario 2: Opaco no-elegible + MFA branching**
  * **Dado** `inexistente`, `PENDING`, y ACTIVE con MFA.
  * **Cuando** `start` los 3 + `verify` del MFA con OTP válido.
  * **Entonces** 3× `202` idénticos (solo el ACTIVE elegible recibe correo; Mailhog 1), p50 ±40ms; verify MFA → `202 mfa_required` + pre-token (no sesión), `mfa_token` solo en `/mfa/verify`.
* **Escenario 3: Expirado/quemado/replay indistinguibles + quotas**
  * **Dado** token expirado (11min), consumido ayer, aleatorio, y cuenta con 3 fallos (quemado).
  * **Cuando** se verifican + `start` 2× en 30s (2º en cooldown).
  * **Entonces** 4× `400 INVALID_OR_EXPIRED` idénticos; 2º `start` → `202` sin correo (`throttled`); 6º `start` en 24h → `202` sin correo. `attempts=3` exige `start` nuevo.
* **Escenario 4: Contexto high-risk + infra**
  * **Dado** token emitido en `IP-A/UA-X`, consumido en `IP-B/16 distinto/UA-Y`.
  * **Cuando** verify válido + Redis-down / Kafka-down.
  * **Entonces** `200/202` igual + email `context_mismatch` + audit `risk=high`; Redis-down → `200` vía PG + `WARN`; Kafka-down → `200` + outbox pendiente. PG-down → `500` sin consumir.

## 8. Notas de Implementación (desviaciones documentadas, 2026-10-06)

> Estas decisiones se apartan puntualmente del plan original con justificación
> técnica. El comportamiento observable (contratos §1-§2) **no cambia**.

* **D-01 — TTL/quota como consts de dominio, no env (`PLESS_TTL`, `QUOTA`).**
  `PlessTTL=10min`, `PlessCooldown=60s`, `PlessMaxDay=5` viven en
  `internal/domain/auth/passwordless.go` en vez de variables de entorno.
  Motivo: §5 los fija como reglas de negocio inmutables, igual que
  `VerifyTTL=15min` / `ResendCooldown` de CU-REG-02 (tampoco son env).
  Hacerlos configurables por deploy permitiría relajar por error una
  invariante de seguridad (TTL ultra-corto, anti-spam). T-11 se da por
  cumplida sin nuevas vars (se reutiliza `FRONT_BASE_URL` para el link).
* **D-02 — Concurrencia mismo-token sin test de carrera dedicado.**
  La garantía 1×`200`/1×`400` ante doble consumo simultáneo la da el
  `UPDATE … WHERE consumed=FALSE AND superseded=FALSE …` atómico de
  `ConsumeTx` (0 filas = perdedor → `400`; mismo patrón probado en
  `backup_race_test.go` de CU-AUTH-03). Cubierto por test unitario de
  reuso + integración (segundo `ConsumeTx` → `ErrPlessInvalid`).
* **D-03 — `amr` emitido como `otp-email` (no `email-otp`).**
  El plan decía `amr=[email-otp]`, pero CU-AUTH-04 ya definió y validó el
  valor canónico `AMROTPEmail="otp-email"` (y `SessionRequest.ValidateRequest`
  solo acepta ese). Se usa `method=passwordless_email, amr=[otp-email]`
  para no bifurcar el vocabulario de auditoría entre CUs.
* **D-04 — k6 `pless_smoke.js` creado, no ejecutado en vivo.**
  El script existe (`scripts/load/pless_smoke.js`, escenarios start/verify
  con thresholds) pero no se corrió contra entorno vivo con cuentas
  semilla. Los percentiles se infieren de la arquitectura (Issue sin
  Argon2 + jitter acotado) y quedan pendientes de la ventana de carga
  pre-productiva junto a los demás smoke scripts.
* **D-05 — E2E Mailhog cubierto vía `email_queue` + integración, sin SMTP real.**
  En vez de compose+Mailhog en vivo, la evidencia es: test de integración
  PG+Redis real (`passwordless_store_test.go`: fila `email_queue` con
  link+OTP, outbox `requested/consumed/mismatch`, email de alerta
  high-risk) + httptest de handlers. El worker SMTP (`mailer.go`) drena
  `email_queue` de forma genérica y no se modificó.

  **Evidencia de verificación:** `go vet ./...` limpio, `go build ./...` OK,
  `go test ./... -count=1` verde en serie (`-p 1`) y en paralelo.
