# Spec: CU-SEC-07 - Detección de Dispositivo Desconocido (Device Fingerprint + Desafío)

## 1. Contexto y Propósito
Reconocer el aparato tras la credencial: huella gruesa server-side + HMAC, lista trusted (10 LRU), y ante desconocido desafío fuera de banda (MFA users: su TOTP; resto: OTP/link 10min) + alerta con kill-link 1-clic 24h. Cierra el Módulo 5. Supuesto Q1 (sin respuesta, a confirmar): huella gruesa `UA-familia+OS+clase+IP/24+lang` + HMAC, sin JS-cliente.

Decisiones (Q2-Q7 Recommended + Q1 supuesto Recommended):
- Q2 Dual (MFA→TOTP basta; no-MFA→email OTP/link), Q3 Kill-link 24h 1 uso anónimo, Q4 3 logins pre-Issue + 1º auto-trusted (refresh no), Q5 Exact-match o desafío (sin scoring), Q6 10 LRU + quotas (solo trusted tras pasar), Q7 Tablas + puertos + métricas.

## 2. Actores y Precondiciones
* **Actores:** Usuario (conocido o atacante con credencial), Microservicio Auth, Worker SMTP.
* **Precondiciones:**
  * Secreto primario OK + cuenta `ACTIVE` (si falla antes, no hay device-check).
  * `DEVICE_HMAC_KEY` cargada (si ausente → `WARN` + todo `skipped_no_hmac`, fail-open documentado).

## 3. Flujo Principal (Happy Path)
1. Tras secreto OK (pre-Issue en login/pless/federado), calcula `fp = hex(SHA-256(ua_family|os_family|device_class|ip/24|lang))` + `hmac = HMAC_SHA256(fp, DEVICE_HMAC_KEY)` (UA parseada server-side `mileusna/useragent` o similar liviano; sin UA → `fp=unknown-ua` + sigue como desconocido, no `400`).
2. Lookup `trusted_devices WHERE user_id AND fp_hash=$fp` (PG verdad; Redis `dev:<uid>:<fp>` fast-path EX 86400 + fallback PG): hit + `hmac` verifica (`ConstantTime`; mismatch → trata como desconocido + `WARN tamper` + métrica) → `trusted` directo: sigue a Issue/pre-token normal + `last_seen=now` (LRU touch) + sin email.
3. Miss (o 0 trusted = primer dispositivo → auto-trusted sin desafío: registra + sigue normal + email `Primer dispositivo registrado` informativo, sin kill-link urgente):
   a. Clasifica `risk=medium-high` + emite desafío según MFA: con `mfa_enabled` → convierte a `202 mfa_required` (el TOTP vale como desafío; flujo idéntico MFA normal + email `Nuevo dispositivo: confirma con tu segundo factor` con detalles + kill-link por si el password era robado y el atacante no tiene TOTP — muere en el TOTP).
   b. Sin MFA → genera `device_challenge` (OTP 8d + link 32B, `SHA-256`, TTL 10min, 1 uso, scope `device_approval`, ligado a `fp` pendiente, 1 activo) + email `Nuevo inicio: código/link` (con detalles + kill-link futuro? El kill-link mata la SESIÓN, que aún no existe — en este punto el email lleva el challenge, no el kill; el kill llega tras Issue en el email de confirmación `Se inició sesión en X [cerrarla]`).
4. Usuario resuelve: MFA→TOTP OK en `/mfa/verify` (reuso CU-AUTH-02, sin endpoint nuevo; el `challenge_id` MFA lleva `device_fp` para atarlo) o no-MFA→`POST /device/verify {device_token, code|token}` (endpoint mínimo de este CU, sin Bearer, el challenge es la auth, igual `/mfa/verify` pattern).
5. Al pasar: Tx `INSERT trusted_devices(fp, hmac, label, first_seen, last_seen)` (+ evicta oldest si 10) + sigue a `Issue` (o a `mfa_required` si además travel-forzó? No: si travel ya forzó MFA y device también, un solo `202` basta — se fusionan: el pre-token MFA lleva `device_fp` y al verificar TOTP se registran AMBOS (travel-ok + device-trusted) de una vez; documentado anti-triple-factor) + email `Se inició sesión en <label> (<ip_masked>) [Cerrar esta sesión]` con kill-link de la `sid` recién creada (24h 1 uso).
6. Kill-link: `GET /device/kill?token=` (o POST, ambos aceptan; GET por 1-clic mail, idempotente, sin Bearer, token manda) → valida `session_kill` (firma/hash + exp 24h + no usado + `sid` existe del user) → revoca ESA `sid` (triple-capa SES-01/03, sin tocar otras) + `200 killed` (página `Sesión cerrada` si GET browser) + email confirmación `Cerraste <label>` + audit. Reuso → `400` opaco (o `200 already_killed` idempotente si mismo token? Decisión: `200 already_killed` — el dueño re-clicando no ve error).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** challenge malforma → `400` (sin consumir intento); kill-token malforma → `400`; sin `DEVICE_HMAC_KEY` → skips (Q-fail-open) + `WARN`.
* **4.2. Desconocido sin resolver:** challenge expirado (10min)/quemado (3 fails)/nunca resuelto → `400 INVALID_DEVICE_CHALLENGE` opaco (sin sesión, sin trusted, sin kill-link). 3 fails queman + exigen nuevo login (nuevo challenge).
* **4.3. Kill inválido:** miss/exp/usado/`sid` de otro user o ya muerta → `400` opaco (o `200 already_killed` si ese token ya mató — idempotente mismo token). Sin oráculo entre cuentas (mismo `400`).
* **4.4. Infra:** PG down → `500` (sin Issue sin device-check? El check es pre-Issue: sin PG no hay trusted-lookup → fail-closed? No: fail-open `skipped_db` + `WARN` + sigue a Issue (disponibilidad primero; el riesgo se audita). Documentado: device-check nunca bloquea por infra (solo por desafío no resuelto). Redis down → PG verdad + `WARN`. Kafka down → `200/202` + emails pendientes. HMAC-key rotada: `hmac` viejos mismatch → todos desconocidos una vez (re-desafío masivo + `WARN` + métrica `hmac_mismatch_total`; ventana aceptada, documentada migración dual-key).
* **4.5. Rate:** `device:send 5/hora/user` + `device:verify:tok 5/min` + `kill:ip 30/min` → `429` (sin revelar trusted). Trusted-llenado por atacante imposible (solo tras pasar desafío con secreto+MFA/mailbox).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Huella gruesa (supuesto Q1): `ua_family|os|clase|ip/24|lang` + `SHA-256` + `HMAC(key)`. Sin JS, sin canvas, sin IP completa almacenada (solo `/24` en hash + masked en labels).
* **RN-02:** 10 trusted LRU por user (`last_seen` touch en hit; evicta oldest al 11º). Primero auto-trusted (confianza inicial) + email informativo.
* **RN-03:** Exact-match o desafío (sin scoring). `hmac` mismatch = desconocido + `WARN`.
* **RN-04:** Dual: MFA→TOTP (sin email-OTP extra) / no-MFA→email OTP+link 10min 1 uso scope `device_approval` (no sesión). Fusión con travel-forced-MFA (un solo `202`).
* **RN-05:** Kill-link 24h 1 uso anónimo por `sid` (`session_kill` tabla: `token_hash PK, user_id, sid, exp, used`), idempotente `already_killed`.
* **RN-06:** Quotas `5/hora send` + `5/min verify` + 3 fails queman challenge (nuevo login para otro).
* **SEC-01:** `fp` + `hmac` en DB (nunca UA crudo/IP completa; labels `Chrome · Windows` + `ip_masked` + ciudad si GeoIP disponible — reuso travel sin duplicar).
* **SEC-02:** Challenge no es sesión (scope aislado, `aud=device-challenge`, 10min, 1 uso; rechazado en negocio). Kill-token no lista nada (solo mata su `sid`).
* **SEC-03:** Emails con detalles + kill-link solo al buzón verificado (el atacante con password pero sin mailbox no se auto-aprueba; con mailbox comprometido totalmente ya es takeover completo — fuera de alcance, documentado).
* **SEC-04:** `ConstantTime` en `hmac`/hash compares + delay 20-50ms en `400` challenge (igual MFA).

## 6. Requerimientos de Observabilidad
* **Métrica:** `device_unknown_total{action="trusted|first|mfa_challenge|email_challenge|kill|invalid|rate|skipped_nohmac"}` + `device_trusted_gauge_bucket` (0|1|2-5|6-10 por user? No: cardinalidad — solo `trusted_count` histogram) + `device_kill_total{result}`.
* **Trazabilidad:** Hijo `Defense.DeviceCheck` pre-Issue (hijos: `device.fingerprint`, `db.trusted.lookup`, `challenge.issue|verify`, `db.trusted.add`, `kill.issue|redeem`). Atributos `label` (no huella cruda).
* **Auditoría:** `auth.audit.v1 {action:"device.check|challenge|trusted|kill", fp_hash_prefix(8), label, result, trace_id}` + eventos `device.unknown|trusted|killed` (key `user_id`). Sin `fp/hmac/token` completos (prefix).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Conocido directo + primero auto**
  * **Dado** trusted PC-A; cuenta nueva 0 trusted.
  * **Cuando** login PC-A (conocido) y primer login cuenta nueva (cualquier aparato).
  * **Entonces** PC-A → `200/202` normal sin email extra + `last_seen` tocado; nueva → `200/202` + trusted creado + email informativo (sin desafío). UA sin header → `unknown-ua` tratado como desconocido (desafío), no `400`.
* **Escenario 2: Desconocido dual (MFA vs no-MFA) + kill**
  * **Dado** MFA-user y no-MFA-user, ambos con 1 trusted viejo, login aparato nuevo.
  * **Cuando** passwords OK.
  * **Entonces** MFA → `202 mfa_required` (TOTP) + email nuevo-dispositivo (sin OTP extra); TOTP OK → `200` + trusted nuevo + email sesión-con-kill. No-MFA → `202 device_challenge` (email OTP/link, sin sesión); OTP OK → `200` + trusted + email-con-kill. Kill-link del email → `200 killed` (esa `sid` muere, otras viven) + confirmación; re-clic → `200 already_killed`.
* **Escenario 3: Rate/quema + HMAC-key rotada**
  * **Dado** 6 sends/hora; 3 verifies malos; rotación `DEVICE_HMAC_KEY`.
  * **Cuando** 6º send, 3er verify, login tras rotación con aparato antes-trusted.
  * **Entonces** 6º → `429`; 3er malo → challenge quemado (`400` posterior aunque código correcto tardío); post-rotación → desconocido 1 vez (re-desafío) + `hmac_mismatch_total` +1 (sin `500`).
* **Escenario 4: Infra + exactitud**
  * **Dado** PG-down / Redis-down / Kafka-down / sin HMAC-key.
  * **Cuando** login aparato nuevo.
  * **Entonces** PG-down → `500` base (sin check); Redis-down → PG verdad + `200/202` + `WARN`; Kafka-down → `200/202` + emails pendientes; sin key → `skipped_nohmac` + `200/202` + `WARN` (0 desafíos). Exact-match con red distinta (`/24` cambió, resto igual) → desafío igual (red no exime).
