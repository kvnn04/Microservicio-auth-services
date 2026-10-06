# Spec: CU-REG-04 - Registro Federado (OAuth2 / OIDC)

## 1. Contexto y Propósito
Permitir crear/entrar con cuentas externas de confianza (MVP: Google) sin password local, delegando la prueba de identidad al IdP vía OIDC Authorization Code + PKCE. Si el IdP certifica el email (`email_verified=true`) la cuenta nace `ACTIVE` (sin OTP); si no, nace `PENDING_VERIFICATION` y exige CU-REG-02. Es la vía "un clic" del OVERVIEW, con anti-takeover estricto: jamás fusiona emails existentes sin prueba de posesión (anticipa CU-REG-06).

Decisiones acordadas (2026-10-05, todas Recommended):
- Q1 Solo Google MVP extensible (`provider` enum, scopes `openid email profile`), Q2 Code+PKCE back-driven (state/nonce 32B, Redis 10min), Q3 Bifurcada verified, Q4 Sin auto-link (409 LINK_REQUIRED + email seguridad), Q5 Discovery 24h/JWKS 1h/timeout 5s+1 retry →502, Q6 Authorize 302 + callback GET JSON, Q7 Puertos IdentityProviderClient + FederatedIdentity UNIQUE(provider,sub).

## 2. Actores y Precondiciones
* **Actores:** Usuario Anónimo (browser), IdP Google (authorization/token/JWKS), Microservicio Auth, Worker (emails/eventos).
* **Precondiciones:**
  * `provider=google` habilitado en config (`FEDERATED_GOOGLE_CLIENT_ID/SECRET/REDIRECT_URI`, `ALLOWED_PROVIDERS=google`). Otro `provider` → `404 PROVIDER_NOT_SUPPORTED` (único 404 permitido, por config no por existencia de cuenta).
  * Usuario sin sesión (si trae Bearer válido y quiere linkear → `400 USE_LINK_FLOW` que lo deriva a CU-REG-06 futuro, no se linkea aquí).
  * Redis disponible para `fed:state:<state>` 10min; Postgres con tablas `users` + `federated_identities`; JWKS cache válida o refrequeable.

## 3. Flujo Principal (Happy Path)
1. Front redirige a `GET /api/v1/auth/federated/google/authorize?return_to=/app` (sin auth). El back genera `state=32B CSPRNG hex`, `nonce=32B hex`, `code_verifier=64B base64url (43-128ch)`, `code_challenge=S256(verifier)`, guarda en Redis `fed:state:<state> {nonce, verifier, return_to, ip_hash, created_at} EX 600 NX` + cookie `fed_state` HttpOnly Secure SameSite=Lax 10min (defensa CSRF doble), y responde `302` a `https://accounts.google.com/o/oauth2/v2/auth?client_id=&redirect_uri=<callback>&response_type=code&scope=openid+email+profile&state=&nonce=&code_challenge=&code_challenge_method=S256`.
2. Usuario consiente en Google; Google redirige a `GET /api/v1/auth/federated/google/callback?code=<authcode>&state=<state>` (+ `error=` si denegó, ver 4.2).
3. El back valida: `state` existe en Redis y coincide con cookie `fed_state` (si cookie ausente se acepta solo `state` + chequeo IP/UA-hash laxo, sin bloquear legítimo sin cookies third-party); si mismatch/ausente/expirado → `400 INVALID_FEDERATED_STATE` genérico + borra Redis. Consume `state` (DEL, un solo uso, anti-replay).
4. Canjea `POST https://oauth2.googleapis.com/token {code, client_id, client_secret (confidential), redirect_uri, grant_type=authorization_code, code_verifier}` con timeout 5s + 1 reintento (backoff 500ms). Si IdP `4xx` (code inválido/expirado/reusado) → `400 INVALID_FEDERATED_CODE` genérico. Si timeout/5xx/DNS → `502 IDP_UNAVAILABLE` genérico (sin cuerpo IdP) + métrica. Sin guardar nada aún.
5. Valida `id_token` (JWT): obtiene JWKS (`https://www.googleapis.com/oauth2/v3/certs`, cache 1h, 10min en ventana rotación detectada por `kid` miss), verifica firma `RS256/ES256` (`kid` debe existir, `alg` en allowlist, nunca `none`), claims: `iss ∈ {https://accounts.google.com, accounts.google.com}`, `aud == CLIENT_ID`, `exp > now+30s skew`, `iat < now+60s`, `nonce == Redis nonce` (ConstantTime), `sub` non-empty ≤255. Si falla → `401 INVALID_ID_TOKEN` genérico (sin decir qué claim). Extrae `email, email_verified, name, picture` (picture/name solo perfil, no auth).
6. Normaliza `email` igual que CU-REG-01 (si IdP no trae email o trae malformado → `400 IDP_EMAIL_MISSING`, caso Apple-relay futuro → trata como no-verificado con email sintético `relay+sub@privaterelay` + exige OTP; en Google MVP email siempre presente).
7. Lookup: `SELECT federated_identities WHERE provider='google' AND sub=$1`:
   a. Hit → login federado (no es registro): si `users.status=ACTIVE` → emite sesión (delega a CU-AUTH-04, `200 {status:active}` + cookies); si PENDING → `200 {status:pending_verification}` (debe completar OTP); si LOCKED/SOFT_DELETED → `403` genérico `ACCOUNT_UNAVAILABLE` (sin detallar).
   b. Miss + `email_normalized` NO existe → crea: `users(id UUIDv7, email_*, status = verified?ACTIVE:PENDING, password_hash=NULL, password_algo='federated', terms_version=legales vigentes auto-aceptadas con `terms_source=federated`)` + `federated_identities(provider, sub UNIQUE, user_id, email_at_link, id_token_iss, created_at)` + outbox (`federated.registered` + `user.activated` si ACTIVE + audit) en UNA Tx. Si ACTIVE → emite sesión inmediata; si PENDING → encola OTP CU-REG-02 y `200 pending`.
   c. Miss + `email_normalized` SÍ existe (distinto sub) → ANTI-TAKEOVER: no crea ni fusiona; `409 ACCOUNT_LINK_REQUIRED {message:"Esta dirección ya tiene cuenta. Inicia sesión para vincular."}` genérico (sin revelar provider previo ni sub) + outbox `security.federated_collision` → email seguridad al dueño (throttle 1/hora, igual que CU-REG-03) con links login/forgot. El link real se hace autenticado en CU-REG-06.
8. Limpia `fed:state` + cookie (expire inmediato), setea sesión solo si ACTIVE (cookies `HttpOnly Secure SameSite=Lax` delegadas a CU-AUTH-04; este CU nunca pone tokens en URL).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * `provider` desconocido → `404 PROVIDER_NOT_SUPPORTED`. `callback` sin `code/state`, `state` malformado, cookie manipulada → `400 INVALID_FEDERATED_STATE`. `id_token` sin `sub/email` → `400 IDP_EMAIL_MISSING`. Todos sin tocar DB salvo contador rate-limit, sin `user_id` en error.
* **4.2. Conflicto o unicidad (colisión email — núcleo):**
  * Condición 7c (email existe, sub distinto) → `409 ACCOUNT_LINK_REQUIRED` (único `409` del sistema federado; no confundir con CU-REG-01 que nunca da 409). No indica si la existente es password/federada/bloqueada. No consume `state` reutilizable (ya consumido). Email seguridad async (throttle). Atacante que crea Google con email ajeno no-verificado NO obtiene nada (además Google exige verificar email para `email_verified=true`, y aun con `true` no fusionamos sin posesión).
  * Usuario deniega en Google (`callback?error=access_denied`) → `400 FEDERATED_CANCELLED` genérico (sin reintento auto), métrica `cancelled`.
  * Reuso `code`/`state` (doble callback por refresh/prefetch) → `400 INVALID_FEDERATED_STATE` (state ya DEL) o `200 already_verified/active` idempotente solo si el primer callback de ese `state` ya activó y el segundo trae mismo `RequestID` (idempotencia 24h); en otro caso `400` (no oracula).
* **4.3. Falla de servicio externo o infraestructura:**
  * Google token/JWKS/userinfo timeout (>5s) o 5xx o `kid` desconocido tras refresh → `502 IDP_UNAVAILABLE` genérico + `Retry-After: 5`, sin crear usuario/outbox, `federated_idp_errors_total{op=token|jwks}` +1. JWKS stale: 1 refresh forzado ante `kid` miss; si sigue miss → `401` (posible rotación atacante, no acepta).
  * Postgres down → `500 INTERNAL_ERROR` (tras canje válido, sin perder IdP proof: guarda `fed:pending:<state_hash>` 10min para reintentar callback sin re-consentir, + `WARN`). Redis down → no puede validar `state/nonce/PKCE` con rigor → `500` (fail-closed aquí, distinto de register: sin estado no hay seguridad; mensaje pide reintentar) + alerta. Kafka down → `200` igual (outbox pendiente, igual que CU-REG-01/02).
* **4.4. Rate-limit:**
  * `authorize` 20/min/IP + `callback` 10/min/IP + `callback:state` 5/min (Redis, fail-open 2x salvo `state` que es fail-closed). Excedido → `429 + Retry-After`. Sin distinguir existencia.
* **4.5. Claims borde:**
  * `email_verified` ausente/null → trata `false` (PENDING + OTP). `email` con mayúsculas/espacios → normaliza igual. `sub` >255 o con control → `401`. `nonce` mismatch → `401` (no `400`, para no confundir con state). `aud` con varios clientes → debe contener el nuestro. `exp` con skew >30s → `401`. `picture/name` >2KB → trunca, nunca bloquea.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** MVP `provider=google` único. Añadir provider exige nueva spec delta (JWKS, mapeo claims, relay) sin tocar este flujo base.
* **RN-02:** `email_verified=true` (bool estricto, no `"true"` string) → `ACTIVE` directo + sesión; `false/null/ausente` → `PENDING + OTP`. Nunca emite sesión a PENDING.
* **RN-03:** Unicidad doble: `UNIQUE(provider, sub)` + `UNIQUE(email_normalized)`. Colisión email+sub-distinto → `409` + notify, nunca merge silencioso ni cuenta duplicada.
* **RN-04:** `state/nonce/code_verifier` un solo uso, TTL 10min, `state` ligado a `ip_hash+UA-familia` (laxo, no bloquea CGNAT). `code` canjeado una vez (Google lo invalida; reuso → `400`).
* **RN-05:** Consentimiento legal: al crear por federado se registra `terms_version` vigente + `terms_source=federated_google` + `ip_hash`; si el front exige checkbox previo, `authorize` debe traer `terms_accepted=true` o se rechaza `400 TERMS_REQUIRED` (configurable `FEDERATED_REQUIRE_TERMS=true` por defecto).
* **SEC-01 (CSRF/inyección):** `state` 32B + cookie `fed_state` doble-submit + `nonce` OIDC + PKCE S256 obligatorios. Valida los tres; `ConstantTimeCompare` en `state/nonce`. `redirect_uri` exacta registrada (sin wildcards, sin `return_to` abierto — allowlist `/app|/login` relativos).
* **SEC-02 (Tokens IdP):** `id_token` solo vía JWKS + allowlist `alg`, `kid` verificado, `iss/aud/exp/nonce` estrictos. `access_token` Google nunca se persiste ni loguea (solo memoria del canje, TTL request). `client_secret` solo en back (env/HSM, nunca al front).
* **SEC-03 (Takeover):** Sin auto-link aunque `verified=true`. El `409` no revela `provider` previo ni `sub`. Email colisión throttled 1/hora. Vinculación real solo autenticada (CU-REG-06 + Step-Up).
* **SEC-04 (PII):** Logs/audit con `provider, sub_hash (sha256), email_hash, email_domain`, nunca `code/state/verifier/nonce/access_token/id_token` ni email plano (salvo evento mailer interno). `sub` completo solo en DB (`federated_identities.sub` cifrado en reposo si hay KMS).
* **SEC-05 (Sesión):** Este CU no inventa formato sesión; delega emisión a CU-AUTH-04 (Access 5-15min + Refresh rotado HttpOnly). Si ACTIVE federado tiene MFA obligatorio (futura política), retorna `mfa_required` con pre-token (CU-AUTH-02) en vez de sesión final.

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `federated_registration_total{provider="google", result="active|pending|linked_login|link_required|cancelled|invalid_state|invalid_token|idp_unavailable|rate_limited|error"}` + `federated_idp_latency_seconds{op="token|jwks"}` Histogram + `federated_collisions_total{provider}`.
* **Trazabilidad:** Span raíz `UseCase.RegisterFederated` (hijos: `oauth.build_authorize`, `oauth.exchange_code`, `jwks.fetch|cache`, `jwt.verify`, `db.federated.lookup`, `db.user.insert+link (Tx)`, `outbox.insert`, `kafka.produce` worker). Atributos `provider`, `email_verified`, `email.domain`; nunca secretos.
* **Auditoría:** `auth.audit.v1 {action:"federated.register|login|collision|cancelled|failed", provider, sub_hash, email_hash, result, trace_id}` + si creado `auth.user.activated.v1` (cuando ACTIVE) o `verification_requested` (cuando PENDING). Sin tokens IdP.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Google verified nuevo → ACTIVE + sesión**
  * **Dado** IdP mock devuelve `id_token` válido (`sub=google123`, `email=Nuevo@Example.com`, `verified=true`, firma JWKS OK) y email no existe.
  * **Cuando** `GET authorize → 302` + `GET callback?code=&state=` válido.
  * **Entonces** `200 {status:active}` + cookies sesión (formato CU-AUTH-04), PG `users(ACTIVE, password_algo=federated)` + `federated_identities(google,google123)` + outbox `federated.registered + user.activated`, `federated_registration_total{active}` +1, segundo `callback` mismo state → `400` (replay).
* **Escenario 2: Google no-verified → PENDING + OTP**
  * **Dado** `verified=false` (o sin email) y email no existe.
  * **Cuando** callback válido.
  * **Entonces** `200 {status:pending_verification}`, `users=PENDING`, outbox `verification_requested` (OTP/link CU-REG-02), sin cookies sesión, login con password imposible (`CanAuthenticate=false`).
* **Escenario 3: Colisión email existente → 409 sin fusión + notify**
  * **Dado** `existe@example.com` ACTIVE con password (o con `sub=otro`), atacante consigue `id_token` Google mismo email distinto `sub` (aunque sea `verified=true`).
  * **Cuando** callback válido.
  * **Entonces** `409 ACCOUNT_LINK_REQUIRED` genérico (sin revelar tipo previo), 0 filas nuevas, 0 cambios, email seguridad al dueño (throttle 1/h) + `collisions_total` +1. Con `sub` ya vinculado → `200 active` (login, no registro).
* **Escenario 4: IdP caído / state inválido**
  * **Dado** Google token endpoint timeout (mock 6s) o `state` reusado/ausente.
  * **Cuando** callback.
  * **Entonces** timeout → `502 IDP_UNAVAILABLE` sin crear nada (reintentable con nuevo authorize); state malo → `400 INVALID_FEDERATED_STATE`; ambos sin `user_id/email` en error y `result` metricado.
