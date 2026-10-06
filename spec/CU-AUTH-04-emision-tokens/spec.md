# Spec: CU-AUTH-04 - Emisión y Gestión de Tokens Enterprise

## 1. Contexto y Propósito
Emitir el par de sesión tras autenticación completa (login clásico CU-AUTH-01, MFA CU-AUTH-02/03, federado CU-REG-04, y futuros passwordless/CRED): `Access JWT Ed25519 15min` (verificable descentralizadamente vía JWKS) + `Refresh opaco 32B` (family rotativa, HttpOnly). Es el único punto que firma Access y crea families; todo lo demás (`login`, `mfa/verify`, `federated/callback`, `refresh` en CU-SES-04) lo invoca como puerto `SessionIssuer`. Sin este CU no hay sesión interoperable ni revocación.

Decisiones (2026-10-05, todas Recommended):
- Q1 Ed25519 15min `kid` + claims mínimos, Q2 Refresh opaco 32B + family UUIDv7 + chain + 30d sliding/90d absoluto single-use (rota en SES-04), Q3 Híbrida Access-body + Refresh-cookie web / doble-body nativo, Q4 Redis verdad + PG backup + device + `tokens_valid_after`/denylist preparados, Q5 Snapshot `roles/scopes` versionado sin PII, Q6 Issue crea family (Rotate en SES-04, multikid en CRYP-02), Q7 3 puertos + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Microservicio Auth (emisor), Cliente (browser SPA / nativo), Stores Redis/PG, KMS (clave Ed25519), Gateway/consumidores (verifican vía JWKS, CU-CRYP-01).
* **Precondiciones:**
  * `users.status=ACTIVE` + autenticación completa probada por el llamador (password+MFA si aplica, federado verified, Step-Up no exige aquí).
  * Clave Ed25519 activa (`kid` actual en `signing_keys`, privada solo KMS/env `SESSION_SIGNING_KEY`, nunca en repo/logs).
  * `device{ip_hash(/24), ua_hash}` calculado por el llamador (login/MFA/federado lo pasan).

## 3. Flujo Principal (Happy Path — Issue)
1. El caso llamador (`LoginService`, `MFAVerify`, `RegisterFederated`) invoca `SessionIssuer.Issue(user, device, method, amr)` con `method∈{password, federated_google, ...}` y `amr` (ej. `[pwd]` o `[pwd,totp]` o `[federated]`), `auth_time` (=now del login completo, no del inicio).
2. El emisor genera `sid UUIDv7` (sesión) + `jti UUIDv7` (este Access) + `family UUIDv7` (nueva, siempre en Issue; Rotate crea hijos en SES-04) + `refresh_plain=32B CSPRNG base64url` + `refresh_hash=hex(SHA-256(plain))` + `parent_hash=""` (génesis).
3. Construye Access JWT: `header{alg:EdDSA, kid:<actual>, typ:JWT}` + `payload{iss:"https://auth.example.com", aud:"api", sub:<user_id>, sid, jti, iat:now, exp:now+15min, auth_time, amr[], scope:"openid profile api", roles:[snapshot], roles_ver:<int>, token_ver:1}`. Firma Ed25519 (detached, `crypto/ed25519`, sin `none`, `kid` obligatorio). `roles` = snapshot `user_roles` + `roles_ver` (si cambia en CU-SEC-06 se fuerza re-issue/revoke por versión).
4. Persiste en UNA Tx PG + write-through Redis: `sessions(sid PK, user_id, family, jti_actual, device_hash, ip_hash, created_at, last_seen, expires_at=now+90d)` + `refresh_families(family PK, user_id, current_hash, parent_hash, counter=0, absolute_exp=now+90d, revoked=false)` + `refresh_hashes(hash PK, family, counter, expires_at=now+30d)` + outbox `session.issued` + audit. Redis: `sess:<sid> EX  faction?` (`SET sess:<sid> {user,family,jti,device} EX 7776000` 90d + `fam:<family> {current_hash} EX 7776000` + `jti:<jti> EX 900` para denylist corta SES-01).
5. Entrega híbrida (sin URL jamás):
   * Web (defecto, sin `X-Client-Type:native`): body `{access_token, token_type:Bearer, expires_in:900, sid}` + `Set-Cookie: refresh_token=<plain>; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/refresh; Max-Age=2592000` (+ `__Host-` prefix si HTTPS estricto, documentado). Access NO en cookie (memoria JS, evita CSRF en APIs).
   * Nativo (`X-Client-Type: native`): body `{access_token, refresh_token, expires_in, sid}` sin `Set-Cookie` (el cliente guarda en keystore).
6. El Access es verificable offline por gateways con JWKS (`kid` → CU-CRYP-01) + checks `iss/aud/exp` + `tokens_valid_after` (si `iat < users.tokens_valid_after` → rechazado, anticipa SES-02) + denylist `jti` (SES-01). El Refresh solo sirve en `POST /refresh` (CU-SES-04).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * `user` no-ACTIVE, `device` vacío, `method/amr` desconocido, `X-Client-Type` inválido → `ErrValidation` interno (el llamador lo convierte a su `400/401`; Issue nunca responde HTTP directo — es puerto interno). Sin crear family/sesión.
* **4.2. Conflicto o unicidad:**
  * Colisión `sid/family/jti/hash` (CSPRNG, probabilidad ~0) → `UNIQUE` PG la rechaza → reintenta 1 vez con nuevos IDs ( Máx 2 intentos, luego `ErrInfra`). `refresh_hash` duplicado entre users imposible pero garantizado por PK global (igual backups).
  * Límite sesiones: `MAX_SESSIONS_PER_USER=20` (LRU: al crear la 21ª revoca la más vieja `last_seen` + outbox `session.evicted` + métrica; configurable, documentado para SES-03).
* **4.3. Falla de servicio externo o infraestructura:**
  * KMS/clave ausente o `kid` sin privada → fail-fast al arrancar + `500 ISSUE_UNAVAILABLE` si rota en caliente sin clave (sin emitir sin firmar, nunca `none`/HMAC fallback).
  * Postgres down → `500` (sin JWT firmado huérfano: firma en memoria pero sin persistir NO se entrega — orden vinculante firma→Tx→entrega; si Tx falla se descarta el JWT).
  * Redis down → degrada a PG verdad (`WARN` + `issue_redis_fallback_total`; entrega igual si PG OK, rehidrata al recuperar).
  * Kafka down → entrega igual (outbox pendiente, SES-04/CRYP lo drenan).
* **4.4. Rate-limit:** Issue no tiene bucket propio (hereda del llamador: login/MFA/federado ya limitaron). Llamadas directas internas sin llamador → `500` (no expuesto HTTP). Abuso creación masiva sesiones mismo user → `MAX_SESSIONS` LRU lo contiene + alerta `sessions_per_user>15`.
* **4.5. Claves/claims borde:**
  * Rotación (CU-CRYP-02): durante coexistencia firma con `kid_nuevo`, verifica con ambos (gateway tolera 2 `kids`); `kid` ausente en JWKS → gateway `401` (no aquí). `roles` >4KB → trunca a `roles_ver` + `scope` mínimo (nunca Access >8KB; si excede, emite `roles_hash` + obliga introspección — documentado, no bloquea MVP).
  * Nativo que pierde Refresh (sin cookie) → debe re-loguear (sin recovery por email aquí; CRED-01 es para password, no Refresh).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Access `Ed25519`, `exp-iat=900s`, `aud=api` exacto, `iss` configurable único, `jti/sid` UUIDv7 únicos, `auth_time` = instante auth completa (no Issue), `amr` refleja factores reales (`pwd`, `totp|backup`, `federated_google`, `otp-email` futuro).
* **RN-02:** Refresh `32B→43ch b64url`, `hash SHA-256 hex` único global, `family UUIDv7` nueva por Issue, `counter=0` génesis, `expires_at=now+30d`, `absolute_exp=now+90d` (Rotate en SES-04 exige `now<absolute` y renueva `expires` sin mover `absolute`).
* **RN-03:** Single-use lógico desde el nacimiento (aunque Rotate lo implemente, el `current_hash` ya es único; reuso del génesis en `/refresh` lo detecta SES-04 como robo → revoca family).
* **RN-04:** Transporte: nunca en URL/query/logs; Refresh web solo cookie flags máximas (`HttpOnly+Secure+SameSite=Lax`, `Path` acotado, `Max-Age` = restante real); Access web solo body (documenta `Authorization: Bearer` en llamadas, nunca cookie).
* **RN-05:** Sesión `sid` estable por login (Rotate mantiene `sid`, cambia `jti`; logout individual revoca por `sid` en SES-01). `MAX_SESSIONS_PER_USER=20` LRU.
* **SEC-01:** Privada Ed25519 en KMS/env con `mlock` si disponible, rotación sin downtime (CRYP-02), `kid` en header siempre, rechazo `alg!=EdDSA` en verificación (gateway), `aud/iss/exp` estrictos + skew 30s.
* **SEC-02:** Refresh plano solo memoria request + `Set-Cookie`/body TLS (nunca DB/logs: solo hash). `parent_hash` chain permite detectar bifurcación (robo) en SES-04.
* **SEC-03:** Sin PII en Access (`sub` UUID, sin email/nombre; `roles` son códigos, no datos). Device solo hashes. `sid/jti/family` aleatorios no correlacionables sin DB.
* **SEC-04:** `tokens_valid_after` (columna `users`, tocada en SES-02/CRED) + denylist `jti:<jti> EX 900` (SES-01) permiten revocación inmediata pese a stateless (gateway chequea denylist corta + `valid_after` cacheado 60s).
* **SEC-05:** Cookies `__Host-` + `Secure` exigen HTTPS (en local `Secure` se relaja solo con `ENV=dev` + `WARN`, documentado).

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `tokens_issued_total{method="password|federated_google|mfa", amr="pwd|pwd+totp|pwd+backup|federated"}` + `token_issue_duration_seconds` + `sessions_active_gauge` + `sessions_evicted_total{reason=lru}` + `issue_redis_fallback_total`.
* **Trazabilidad:** Span `Session.Issue` (hijos: `crypto.ed25519.sign`, `db.session.insert (Tx)`, `cache.session.save`, `outbox.insert`) llamado dentro de `UseCase.Login/MFAVerify/RegisterFederated`. Atributos `kid, sid, family, amr`, nunca tokens.
* **Auditoría:** `auth.audit.v1 {action:"session.issue", user_id, sid, family, jti, amr, device_hash, trace_id}` + evento `session.issued.v1 {user_id, sid, family, amr, expires_at}` (key `user_id`). Sin Access/Refresh (solo `jti/family_hash_prefix`).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Issue password sin MFA (web)**
  * **Dado** ACTIVE verificado password, `device` dado, clave `kid=A` activa.
  * **Cuando** `Issue(password, amr=[pwd])` web.
  * **Entonces** Access verificable (`ed25519.Verify` con JWKS `kid=A`, `exp-iat=900`, `aud=api`, `amr=[pwd]`) + Refresh 43ch cuyo `SHA-256` está en `refresh_hashes` (plano no) + `sessions+families` PG + Redis `sess/fam` + body Access + cookie Refresh flags + `issued_total{password}` +1. Refresh en `POST /refresh` (SES-04) funciona; Access en gateway mock pasa.
* **Escenario 2: Issue MFA/federado + nativo**
  * **Dado** MFA `amr=[pwd,totp]` y federado `amr=[federated_google]`, cliente nativo.
  * **Cuando** `Issue` nativo.
  * **Entonces** `amr` exacto en JWT, body trae ambos tokens sin cookies, `auth_time` = instante MFA/federado (no Issue), `sid` distinto por login (2 logins → 2 `sid/family`).
* **Escenario 3: Límites y revocación preparada**
  * **Dado** user con 20 sesiones, crea la 21ª; luego SES-02 setea `tokens_valid_after=now`.
  * **Cuando** Issue 21ª + gateway valida Access viejo (`iat<valid_after`) y denylist `jti` tras SES-01.
  * **Entonces** 21ª evicta la más vieja (`evicted_total` +1, vieja Refresh `revoked`) y Access viejo es rechazado por `valid_after`/`denylist` aunque firma OK.
* **Escenario 4: Infra degradada**
  * **Dado** Redis down / PG down / KMS sin clave.
  * **Cuando** Issue.
  * **Entonces** Redis-down → `200` vía PG + `WARN` + rehidrata; PG-down → `500` sin entregar JWT huérfano (0 filas); sin clave → `500` arranque fallido (fail-fast, 0 tokens `none`).
