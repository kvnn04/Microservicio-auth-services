# Spec: CU-REG-06 - Vinculación y Desvinculación de Cuentas Federadas

## 1. Contexto y Propósito
Permitir a una cuenta `ACTIVE` sumar o quitar identidades federadas (MVP: Google) sin romper unicidad ni regalar takeovers. Cierra el Módulo 1: resuelve el `409 ACCOUNT_LINK_REQUIRED` de CU-REG-04 por vía autenticada (el usuario prueba posesión de ambas puntas) y blinda el unlink con regla de último-factor + Step-Up. Sin este CU, las colisiones federadas serían callejones sin salida.

Decisiones (2026-10-05, todas Recommended):
- Q1 Solo ACTIVE, 1 sub/provider/cuenta (`UNIQUE(provider,user_id)` además de `PK(provider,sub)`), Q2 `POST /link` initiate (auth, retorna URL) + `GET /link/callback` (auth + match user), Q3 Step-Up `auth_time≤5min` + `current_password` si tiene password, Q4 Colisión ajena `409 FEDERATED_ALREADY_LINKED` + notify ambas (self → `200 already_linked`), Q5 Unlink solo si quedan ≥1 factores (`400 LAST_AUTH_FACTOR`), Q6 Reuso OIDC CU-REG-04 + Redis `fed:link` fail-closed, Q7 `GET /linked` (sub_hash) + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado ACTIVE (Bearer válido + fresco), IdP Google, Microservicio Auth, Worker.
* **Precondiciones:**
  * `users.status=ACTIVE` (PENDING/LOCKED/SOFT_DELETED → `403 ACCOUNT_UNAVAILABLE`, sinlink).
  * Step-Up MVP: `auth_time ≤5min` (claim `auth_time` del Access JWT, ver CU-AUTH-04; si ausente/viejo → `401 STEP_UP_REQUIRED` con `meta.max_age=300`). Si `password_hash` non-null exige además `current_password` válido en initiate (ConstantTime, mismo Argon2id CU-REG-01; erróneo → `401` genérico `INVALID_STEP_UP`, sin distinguir).
  * Provider `google` habilitado; cuenta no excede `MAX_LINKED_PROVIDERS=5` (aunque MVP solo google, deja guarda).

## 3. Flujo Principal (Happy Path — link)
1. Usuario (sesión fresca) llama `POST /api/v1/auth/federated/google/link {current_password?}` + `Authorization: Bearer` + `X-Request-ID`. El back valida Bearer+Step-Up (+password si aplica; si falla → `401` sin crear state).
2. Genera `state=32B hex`, `nonce=32B`, `verifier/pkce` (igual CU-REG-04), guarda `fed:link:<state> {user_id, nonce, verifier, ip_hash} EX 600 NX`, retorna `200 {url:<authorize IdP con state/nonce/pkce>, state, expires_in:600}` (no `302`, SPA abre popup).
3. Usuario consiente en Google → Google redirige a `GET /api/v1/auth/federated/google/link/callback?code=&state=` **con la misma sesión** (Bearer/cookie obligatorio). El back valida: `state` existe y `user_id(state)==user_id(Bearer)` (mismatch → `400 INVALID_LINK_STATE` + DEL, anti-fijación entre cuentas), consume `state` (DEL un solo uso).
4. Canjea y verifica `id_token` idéntico a CU-REG-04 (JWKS cache, `iss/aud/exp/nonce` ConstantTime, timeout 5s+retry; `4xx`→`400 INVALID_FEDERATED_CODE`, `5xx`/timeout→`502 IDP_UNAVAILABLE`, firma mala→`401 INVALID_ID_TOKEN`, sin crear nada).
5. Lookup `federated_identities(provider,sub)`:
   a. Miss total (sub libre) + usuario no tiene ese provider → Tx: `INSERT federated_identities(provider,sub,user_id,email_at_link,iss)` + `UPDATE users SET federated_only=false` + outbox (`federated.linked` + audit). Si viola `UNIQUE(provider,user_id)` (ya tiene otro Google) → `400 PROVIDER_ALREADY_LINKED` (cámbialo vía unlink primero).
   b. Hit mismo `user_id` (self) → idempotente `200 {status:already_linked}` (doble-clic seguro).
   c. Hit OTRO `user_id` → `409 FEDERATED_ALREADY_LINKED` genérico + notify ambas (ver 4.2), 0 cambios.
6. Borra state, retorna `200 {status:linked, provider:google}` + `Cache-Control: no-store`. El nuevo factor funciona de inmediato para login (CU-REG-04 hit-path).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * Sin Bearer / Bearer inválido → `401 UNAUTHORIZED` (estándar). Bearer válido pero `auth_time>5min`/ausente → `401 STEP_UP_REQUIRED {meta:{max_age:300}}` (link y unlink y `GET linked` no; `linked` permite Bearer normal sin frescura — lectura). `current_password` ausente cuando se exige o erróneo → `401 INVALID_STEP_UP` genérico (mismo mensaje ambas, sin oráculo password). `provider` desconocido → `404`. Callback sin `code/state`, state-user mismatch, `code` reusado → `400 INVALID_LINK_STATE`. Body >4KB → `413`.
* **4.2. Conflicto o unicidad:**
  * Sub vinculado a OTRA cuenta → `409 FEDERATED_ALREADY_LINKED {message:"Esta cuenta Google ya está vinculada a otra cuenta."}` (sin `user_id` ajeno), + outbox `security.federated_link_collision` → emails a ambas (throttle 1/h por `sub_hash`, plantilla sin PII cruzada: cada dueño solo ve su email enmascarado). Self → `200 already_linked` (no 409).
  * Usuario ya tiene ese provider con distinto sub → `400 PROVIDER_ALREADY_LINKED` (debe desvincular primero; evita ambigüedad multi-sub).
  * PENDING que intenta linkear → `403 ACCOUNT_UNAVAILABLE` (verifique primero CU-REG-02), sin state creado.
* **4.3. Falla de servicio externo o infraestructura:**
  * Google/JWKS down → `502` (igual CU-REG-04, sin Tx). Postgres down → `500` (sin link parcial; state queda 10min para reintentar callback con nuevo `code`? No: `code` es un solo uso Google, debe reiniciar initiate — documentado `409?` no, `500` + reintentar initiate).
  * Redis down → fail-closed `500 LINK_STATE_UNAVAILABLE` (sin estado no se valida fijación; no degrada a stateless en MVP) + alerta. Kafka down → `200` igual (outbox pendiente).
* **4.4. Rate-limit:** `link:initiate` 10/hora/user + 20/hora/IP, `link:callback` 10/min/IP, `unlink` 10/hora/user, `linked` 60/min/user → `429 + Retry-After`. Sin distinguir existencia de links.
* **4.5. Unlink (flujo simétrico):**
  * `DELETE /api/v1/auth/federated/{provider}` (auth + Step-Up + `current_password` si tiene password; body `{current_password?}` o `POST /unlink` si el cliente no soporta body en DELETE — se aceptan ambos, mismo efecto).
  * Factores actuales = `(password_hash non-null ? 1:0) + COUNT(federated)`; si `factores<=1` → `400 LAST_AUTH_FACTOR {message:"Vincula otro acceso antes de quitar el único."}`, 0 cambios. Si `provider` no vinculado → `404 FEDERATED_NOT_LINKED` (revela solo lo propio, con auth, permitido).
  * Si permitido → Tx: `DELETE federated_identities WHERE provider+user_id` + outbox (`federated.unlinked` + audit + email aviso `Tu Google se desvinculó` con `Si no fuiste tú recupera aquí`, throttle no aplica — siempre avisa al dueño) → `200 {status:unlinked}`. Sesiones existentes NO se revocan globalmente (el Access sigue hasta expirar; el Refresh sigue válido por otros factores — documenta que cambio de factores no rota sesiones salvo CU-SES-02 explícito).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Solo `ACTIVE` linkea/desvincula. `UNIQUE(provider,sub)` (PK) + `UNIQUE(provider,user_id)` (1/provider/cuenta). `MAX_LINKED_PROVIDERS=5`.
* **RN-02:** `state` link ligado a `user_id` (`fed:link:<state>→user_id`, 10min, un solo uso, match estricto con Bearer en callback). Sin match no hay canje (anti-fijación entre sesiones).
* **RN-03:** Step-Up `auth_time≤300s` en link/unlink (no en `GET linked`). `current_password` obligatorio si `password_hash` existe (verifica Argon2id; 3 fallos en 15min → `429` progresivo, reuso CU-SEC-01).
* **RN-04:** Último factor inamovible (password o federado). Desvincular el único → `400` siempre, aunque Step-Up sea perfecto.
* **RN-05:** Idempotencia `X-Request-ID` 24h en initiate/callback/unlink (replay mismo RequestID → misma respuesta sin duplicar INSERT/DELETE; `INSERT ... ON CONFLICT DO NOTHING` + `DELETE ... IF EXISTS`).
* **SEC-01:** Reuso OIDC estricto CU-REG-04 (`state/nonce/PKCE`, JWKS allowlist, `iss/aud/exp`, `redirect_uri` exacta `.../link/callback` distinta de la anónima — evita confusión de callbacks). `client_secret` nunca al front.
* **SEC-02:** Sin auto-desvinculación cruzada: un `sub` nunca se mueve de cuenta (solo `DELETE` propio + `INSERT` nuevo con consentimiento IdP fresco en la otra cuenta).
* **SEC-03 (PII):** `GET linked` expone `provider, email_at_link (enmascarado `u***@dominio`), linked_at, sub_hash(8ch)` — nunca `sub` completo. Logs/audit con hashes. Emails colisión/unlink sin PII cruzada.
* **SEC-04:** `return_to` allowlist relativo (igual CU-REG-04); cookies `fed_link_state` HttpOnly Lax 10min como doble-submit opcional (igual que `fed_state`).

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `federated_link_total{provider="google", op="initiate|link|unlink|list", result="ok|already|link_required|already_linked|last_factor|invalid_state|step_up_required|idp_unavailable|rate_limited|error"}` + `federated_factors_gauge{user_hash?}` no (por cardinalidad: solo `unlink_last_factor_blocked_total`). Alerta `rate(link_collision[10m])>20` (posible abuso).
* **Trazabilidad:** Raíces `UseCase.LinkFederatedInitiate`, `UseCase.LinkFederatedCallback`, `UseCase.UnlinkFederated` (hijos `auth.stepup.check`, `fed.state.save|consume`, `oauth.exchange`, `jwt.verify`, `db.federated.insert|delete`, `outbox.insert`). Atributo `provider`, nunca secretos.
* **Auditoría:** `auth.audit.v1 {action:"federated.link|unlink|list", provider, sub_hash, result, trace_id}` + eventos `federated.linked/unlinked/link_collision` (key `user_id` o `sub_hash`). Sin `code/tokens`.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Link nuevo OK**
  * **Dado** ACTIVE con password (sesión fresca 1min) sin Google, IdP mock válido `sub=G999`.
  * **Cuando** `POST /link {current_password:ok}` → `200 {url,state}` + `GET /link/callback?code=&state=` misma sesión.
  * **Entonces** `200 {status:linked}`, PG fila `(google,G999,user)` + outbox, login con Google posterior → `active` (CU-REG-04 hit), `link_total{ok}` +1. Replay mismo callback → `400` (state consumido).
* **Escenario 2: Self idempotente vs ajeno 409**
  * **Dado** `G999` ya del usuario A.
  * **Cuando** A repite callback (mismo sub) y B (otro ACTIVE fresco) intenta linkear `G999`.
  * **Entonces** A → `200 already_linked`, B → `409 FEDERATED_ALREADY_LINKED` + 0 cambios + emails throttled a A y B + `collisions` +1.
* **Escenario 3: Step-Up viejo y último-factor**
  * **Dado** sesión de 30min (stale) y cuenta con solo Google (sin password).
  * **Cuando** `POST /link` o `DELETE /google` con Bearer stale.
  * **Entonces** `401 STEP_UP_REQUIRED` (sin state creado/borrado); con sesión fresca `DELETE` del único factor → `400 LAST_AUTH_FACTOR` + 0 cambios. Con password+Google, `DELETE google` fresco+password OK → `200 unlinked` + email aviso.
* **Escenario 4: Lista vinculada**
  * **Dado** ACTIVE con password + Google.
  * **Cuando** `GET /linked` con Bearer (no fresco vale).
  * **Entonces** `200 [{provider:google, email_masked, sub_hash, linked_at}]` sin `sub` completo; sin links → `[]`.
