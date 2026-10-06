# Spec: CU-CRED-03 - Actualización de Correo Electrónico

## 1. Contexto y Propósito
Cambiar la identidad primaria probando control del NUEVO correo (link 15min) con Step-Up mandatorio, avisando al VIEJO en paralelo y cerrando todo al confirmar. Cierra el Módulo 3: la unicidad se vuelve explícita (`409` autenticado y auditado, no oráculo anónimo) y el cambio consolida `verified=true` + corte global (re-login).

Decisiones (2026-10-05, todas Recommended):
- Q1 Guard Step-Up `cred:change-email` (sin current extra), Q2 `409 EMAIL_TAKEN` autenticado+rate+audit, Q3 Link 32B 15min 1 uso + alerta al viejo, Q4 Revoca todo + relogin, Q5 Misma VO email + distinto + `verified=true`, Q6 `3/hora` + `60s/5-24h` + Redis/PG + doble-mail, Q7 `start` auth + `confirm` con token (con/sin Bearer ligado a `user_id`).

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado ACTIVE (Bearer) + poseedor del nuevo correo (puede ser el mismo u otro humano con acceso al buzón), Microservicio Auth, Worker SMTP.
* **Precondiciones:**
  * `users.status=ACTIVE`. Step-Up `cred:change-email` (fast-pass ≤5min o `X-Step-Up-Token` scopeado; si no → `401 STEP_UP_REQUIRED`, sin crear nada).
  * Nuevo ≠ actual (comparación `normalized`, case-insensitive; igual → `400 SAME_EMAIL`).
  * ≤1 cambio pendiente por cuenta (`emailchange:active:<uid>`; nuevo `start` supersede el anterior).

## 3. Flujo Principal (Happy Path)
1. Usuario (sesión + Step-Up) envía `POST /api/v1/auth/email/change/start {new_email}` + Bearer (+ `X-Step-Up-Token` si stale) + `X-Request-ID` (≤2KB). El back valida Guard Step-Up primero (falla → `401`, sin rate de email).
2. Normaliza `new` (igual CU-REG-01; malforma → `400 VALIDATION_FAILED`; igual-actual → `400 SAME_EMAIL`). Rate `emailchange:user 3/hora` (+ `emailchange:ip 20/hora`) → `429`.
3. Chequea unicidad `SELECT id WHERE email_normalized=$new`: si ocupado por OTRA cuenta → `409 EMAIL_TAKEN {message:"Ese correo ya está en uso."}` + audit `taken` (rate+audit contienen sondeo; no revela cuál cuenta). Si libre (o solo el propio pendiente anterior) → sigue.
4. Quotas (`sent:<uid>>60s`? bloquea; `count:<uid:day>≥5`? bloquea → `202` genérico? No: aquí el solicitante es autenticado y sabe que pidió; si throttled → `429 EMAIL_SEND_THROTTLED + Retry-After` explícito (distinto de `409`; no oracula existencia ajena, solo propio throttle). Documentado.
5. Genera `token 32B`, `hash SHA-256`, `exp=now+15min`, `new_normalized/new_original`, `requester=user_id`, dual-write Redis (`emailchange:t:<hash>`, `emailchange:active:<uid>` supersede EX 900) + PG Tx (`email_change_tokens` + outbox ×2) y encola en paralelo: (a) confirmación al NUEVO (link `https://front/email-change?token=` + `15min` + `solicitado por tu cuenta`), (b) aviso al VIEJO (`Se solicitó cambiar tu correo a u***@nuevo (sin token) + si no fuiste tú asegura + revoca`). Retorna `202 {status:confirmation_sent}` (si el front quiere polling, `GET /email/change/status` opcional con Bearer → `{pending:true}` sin token).
6. Poseedor del nuevo abre `POST /email/change/confirm {token}` con o sin Bearer (el token manda; si trae Bearer de OTRO user distinto al `requester` → `401 TOKEN_USER_MISMATCH`? No: para no filtrar, `400 INVALID_OR_EXPIRED` igual; solo acepta si `token.requester` existe ACTIVE y el Bearer ausente o igual — Bearer distinto se ignora y se valida solo token? Decisión vinculante: el `confirm` NO exige Bearer (el link es la auth); si trae Bearer se valida que sea del `requester` o se ignora? Se EXIGE que ausente o igual (distinto → `400` opaco). Documentado).
7. El back valida forma 32B + rate `confirm:ip 20/min` + lookup Redis→PG + `ConstantTime` + `delay 40-80ms` en `400`; si vivo + `users(requester)` aún ACTIVE + `new` aún libre (re-chequeo `UNIQUE` en Tx — si otro lo tomó entre medio → `409 EMAIL_TAKEN` + quema token): Tx atómica `UPDATE users SET email_normalized=new, email_original=newOrig, email_verified=true, tokens_valid_after=now, updated_at` + `UPDATE email_change_tokens SET consumed` + supersede resto + `UPDATE families revoked + DELETE sessions TODAS (incluida actual)` + `DEL` Redis (change + sess/fam) + outbox (`email.changed` + `session.revoked_all` + aviso `Tu correo cambió` al NUEVO + audit). Retorna `200 {status:email_changed, new_email_masked}` SIN sesión (re-login con nuevo email).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** sin Bearer/inválido → `401`; sin Step-Up → `401 STEP_UP_REQUIRED {scope}`; `new` malforma/igual → `400`; body >2KB → `413`; token malforma → `400 VALIDATION_FAILED` (sin quemar).
* **4.2. Tomado/inválido:** `new` ocupado → `409 EMAIL_TAKEN` (start) o `409` en confirm-race (quema token intentado). Token miss/exp/consumed/burned (3 confirms abusivos con token hallado? Igual reset: policy no aplica aquí (sin password), quema por reintentos con token válido-formato pero inexistente? No quema registro (sin registro); con registro vigente, 3 confirms fallidos por `USER_MISMATCH`/race → burn + `400 INVALID_OR_EXPIRED` idéntico (sin `404/410`).
* **4.3. Infra:** PG down → `500` (sin crear/consumir); Redis down → PG verdad + fail-open rate + `WARN`; Kafka/SMTP down → `202/200` igual (doble-mail pendiente; el cambio ya es Tx-committed aunque el aviso tarde — documentado orden Tx→entrega).
* **4.4. Rate/quota:** `429` start/confirm buckets (con `Retry-After`); send-quota throttled → `429 EMAIL_SEND_THROTTLED` (autenticado, explícito, con `Retry-After`; no oracula ajenos).
* **4.5. Viejo inaccesible / federated:** si el viejo es relay Apple sin buzón, el aviso puede rebotar (worker marca `bounced`, no falla el cambio). Federated `sub` no cambia (el link federado sigue por `sub`, el email es display/login; documentado que `email_at_link` se actualiza informativamente).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Step-Up mandatorio (`cred:change-email`) en `start` (el `confirm` no lo exige — el token es la prueba; pero si trae Bearer debe ser del requester o ausente).
* **RN-02:** Unicidad `email_normalized` global (`409` autenticado). `new ≠ actual` (normalizado). `verified=true` tras confirm (prueba control nuevo).
* **RN-03:** Link 32B TTL `900s` 1 activo 1 uso `attempts≤3` (igual reset); `GET /email/change?token=` alias solo muestra form si formato OK (no consume ni revela, igual reset).
* **RN-04:** Corte global al confirmar (`valid_after=now` + families/sessions TODAS, incluida actual) + relogin con NUEVO email (el viejo ya no loguea). Emails a AMBOS (nuevo: confirmación + `cambió`; viejo: aviso sin token).
* **RN-05:** Idempotencia RequestID (`start` mismo RequestID 60s no re-emite; `confirm` mismo RequestID replay → mismo `200` si ese RequestID consumió, sino `400`).
* **SEC-01:** Sin oráculo anónimo (`start` exige auth; `409` solo autenticado+rate+audit). `confirm` opaco (`400` único, `ConstantTime`, hashes, delay).
* **SEC-02:** Token ligado a `requester user_id` (no a `new` solo; si el atacante pide cambio a su email desde su sesión y engaña al dueño para que confirme? El confirm no pide Bearer, cualquiera con link confirma — pero el link va al NUEVO (atacante ya lo controla) y el cambio afecta la cuenta del SOLICITANTE (requester), no la del confirmante. Flujo correcto: el solicitante (dueño) pide, el nuevo (dueño) confirma. Si el atacante solicita desde SU sesión a email suyo, solo cambia SU cuenta (inútil). Para robar, necesitaría sesión del dueño (Step-Up lo frena). Documentado modelo amenaza.
* **SEC-03:** Solo hashes DB + plano una vez SMTP; `new_email` completo solo en correo al nuevo + enmascarado (`u***@`) en respuestas/audit al viejo; sin PII cruzada (el viejo no ve nuevo completo? Sí lo ve enmascarado + dominio para reconocer typo/abuso — completo solo si política `FULL_NEW_TO_OLD=true`, default enmascarado).
* **SEC-04:** `confirm` sin Bearer permitido implica que el link es bearer-token de 256-bit/15min/1-uso (igual reset) — aceptado por diseño (el buzón nuevo es el 2º factor).

## 6. Requerimientos de Observabilidad
* **Métrica:** `email_change_total{op="start|confirm", result="sent|taken|throttled|success|invalid|rate_limited|step_up_required|error"}` + duración + `emailchange_redis_fallback_total`.
* **Trazabilidad:** Raíces `UseCase.EmailChangeStart/Confirm` (hijos: `stepup.check`, `ratelimit`, `email.normalize`, `db.uniqueness`, `crypto.rand`, `cache+db.save|lookup|consume`, `db.email.update+revoke_all`, `outbox.insert×2`). Atributos `new_domain`, nunca token/emails completos (mask).
* **Auditoría:** `auth.audit.v1 {action:"email.change_start|confirm", user_id, old_hash, new_hash, result, trace_id}` + eventos `email.change_requested|changed` + `session.revoked_all{reason:email_change}` (key `user_id`). Sin token.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Cambio completo con corte**
  * **Dado** ACTIVE `viejo@` con 2 sesiones (A actual+B), Step-Up fresco, `nuevo@` libre.
  * **Cuando** `POST /start {nuevo}` → `202` + 2 mails (nuevo link, viejo aviso) + `POST /confirm {token}` (sin Bearer).
  * **Entonces** `200 email_changed (masked)`, `users.email=nuevo verified`, `valid_after≈now`, 0 sesiones (A+B muertas), login viejo → `401` (no existe), login nuevo + password → `200`, `change_total{sent,success}` +1. Reuso token → `400`.
* **Escenario 2: Tomado + Step-Up ausente**
  * **Dado** `ocupado@` de otra cuenta; sesión stale sin token.
  * **Cuando** `start {ocupado}` fresco y `start` stale sin token.
  * **Entonces** fresco → `409 EMAIL_TAKEN` + audit (0 correos al nuevo, 0 cambios); stale → `401 STEP_UP_REQUIRED` sin crear nada. Sondeo masivo (10 nuevos/hora) → 4º `429`.
* **Escenario 3: Race + token inválido + viejo**
  * **Dado** token vivo `nuevo@`; otro registra `nuevo@` antes de confirmar; token expirado/consumido/aleatorio.
  * **Cuando** `confirm` race + 3 inválidos.
  * **Entonces** race → `409 TAKEN` + token quemado; 3× `400 INVALID_OR_EXPIRED` idénticos. `new==actual` en start → `400 SAME_EMAIL`.
* **Escenario 4: Infra + federated**
  * **Dado** Redis-down / Kafka-down / PG-down; cuenta federated-only (Step-Up vía re-login fresco).
  * **Cuando** start/confirm.
  * **Entonces** Redis-down → `202/200` vía PG; Kafka-down → `202/200` + doble-mail pendiente; PG-down → `500` sin cambios. Federated stale → `401` hasta re-login; fresco → `202/200` + `sub` intacto.

## 8. Notas de Implementación (desviaciones documentadas, 2026-10-06)

> El comportamiento observable (contratos §1-§2) **no cambia**.

* **D-01 — Step-Up verificado en el servicio, sin middleware `RequireStepUp`.**
  El plan esbozaba el middleware en la ruta; se verifica en
  `EmailChangeStartService` vía `StepUpChecker` con el `X-Step-Up-Token`
  del header. Motivo: `Check` consume el `jti` (single-use); con doble
  guard (middleware + servicio) el token se quemaría en el primero y el
  segundo vería `REUSED` (igual que CU-CRED-02). Misma garantía, un solo
  dueño de la quema.
* **D-02 — Puerto dividido `Taken` + `Issue` (no `Request` combinado).**
  El plan esbozaba `Request(...) (rec, taken, err)`; se separó en
  `Taken` (solo lectura, para el 409 auditado) + `Issue` (Tx) para
  respetar ISP y testear unicidad sin efectos. Idéntico comportamiento.
* **D-03 — `GET /email/change/status` (polling) no implementado.**
  El plan lo marcaba opcional y los contratos no lo listan; el front usa
  el link del correo. No hay ruta de sondeo que endurecer.
* **D-04 — `verified=true` implícito (sin columna nueva).**
  No existe columna `email_verified` (ni en CU-REG-02 la hubo):
  `ACTIVE` implica verificado y `ConfirmTx` exige `ACTIVE`. El `sub`
  federado no se toca (la tabla `federated_identities` no se escribe).
* **D-05 — TTL/rate/quota como consts de dominio, no env.**
  Igual que D-01 de CU-AUTH-05 y D-05/06 de CU-CRED-01/02: reglas fijas §5
  (`EmailChangeTTL=15min`, `EmailChangeRatePerHour=3`,
  `EmailChangeCooldown=60s`, `EmailChangeMaxDay=5`).
* **D-06 — k6 `emailchange_smoke.js` creado, no ejecutado en vivo** (igual
  que los demás smoke scripts): pendiente de ventana pre-productiva.
* **D-07 — E2E Mailhog cubierto vía `email_queue` + integración PG+Redis
  real, sin SMTP vivo** (igual que CU-AUTH-05/CU-CRED-01): se asertan
  ambos correos (link al nuevo, aviso mask al viejo), outbox y corte.
* **D-08 — Modo de verificación de referencia: serie (`-p 1`).**
  Igual que D-08 de CU-CRED-02: DB local compartida + wipes E2E; los tests
  llevan re-asegurado + reintento, gate verde en serie y en paralelo.

  **Evidencia de verificación:** `go vet ./...` limpio, `go build ./...` OK,
  `go test ./... -count=1` verde en serie (`-p 1`) y en paralelo.

  **Security Gate PASSED (STRIDE):** Step-Up mandatorio en start
  (fast-pass o token 1-uso); `409` solo autenticado + rate + audit (no
  oráculo anónimo); link 32B + solo hashes + 1-uso-1-activo + supersede;
  confirm ligado a `requester` (bearer ajeno → 400; modelo §5 SEC-02);
  corte global + relogin sin auto-login; doble-mail sin token al viejo
  y mask en respuestas/auditoría; cero secretos/PII en logs, métricas,
  spans y eventos; `no-store` siempre.
