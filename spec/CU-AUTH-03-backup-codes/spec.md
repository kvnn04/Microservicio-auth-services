# Spec: CU-AUTH-03 - Códigos de Respaldo para MFA (Backup Codes)

## 1. Contexto y Propósito
Dar un paracaídas de un solo uso cuando el TOTP es inaccesible (pérdida de teléfono). Se generan en el `enable` de CU-AUTH-02 (y en cada `regenerate`), se guardan solo como `SHA-256 + pepper`, se exhiben una vez y cada consumo quema el código, emite sesión (vía CU-AUTH-04) y dispara alerta de alta prioridad. Sin este CU, perder el autenticador = lockout.

Decisiones (2026-10-05, todas Recommended):
- Q1 10×10 Crockford (~50 bits, `XXXX-XXXXXX`), Q2 `SHA-256 hex + pepper` + ConstantTime, Q3 Una exhibición (enable/regenerate con Step-Up que quema previos) + `count` en status + warning ≤2 + sin auto-regen, Q4 Mismo `POST /mfa/verify` autodetectado (backup solo login, no disable/Step-Up), Q5 Comparte tracker/quemado CU-AUTH-02 + `401` único, Q6 Tabla `mfa_backup_codes(code_hash PK global)` + Tx `FOR UPDATE → used`, Q7 Alerta siempre sin throttle + métricas + puertos.

## 2. Actores y Precondiciones
* **Actores:** Usuario (sin TOTP, con papel/impresión), Microservicio Auth, Worker SMTP.
* **Precondiciones:**
  * `users ACTIVE` + `mfa_enabled=true` + existe ≥1 backup `used=false` (si 0 → `401` igual que malo; debe usar TOTP o regenerar autenticado).
  * Verify: posee `mfa_token` vigente no quemado (igual CU-AUTH-02, `aud=mfa-challenge` 5min).
  * Regenerate: Bearer ACTIVE + Step-Up ≤5min (igual CU-REG-06).

## 3. Flujo Principal (Happy Path)
### A. Generación (enable/regenerate, con sesión fresca)
1. En `POST /totp/enable` exitoso (CU-AUTH-02) o `POST /api/v1/auth/mfa/backup-codes/regenerate` (auth+Step-Up), el back genera `10×10ch` CSPRNG (alfabeto `23456789ABCDEFGHJKMNPQRSTVWXYZ`, formato display `XXXX-XXXXXX` pero canónico `10ch upper sin guion`), calcula `hash=hex(SHA-256(canónico + pepper))` (pepper `PASSWORD_PEPPER` reuso, 32B env; si ausente usa solo SHA-256 + `WARN` arranque, nunca falla cerrado aquí).
2. En UNA Tx PG: si regenerate → `UPDATE mfa_backup_codes SET used=true, superseded=true WHERE user_id=$1 AND used=false` (quema previos sin borrar, auditoría) + `INSERT 10 nuevos (code_hash PK, used=false)` + outbox `backup.regenerated`; si enable → solo `INSERT 10` + outbox `backup.generated` (misma Tx que `PromoteTx` TOTP CU-AUTH-02).
3. Retorna `200 {backup_codes:[10 planos], warning:"Guárdalos. Solo se muestran una vez."}` (única exhibición; el back nunca los re-emite). `GET /mfa/status` desde entonces incluye `{backup_remaining:N, backup_warning:N<=2}` (sin valores).
### B. Consumo (login sin TOTP)
4. Usuario envía `POST /api/v1/auth/mfa/verify {mfa_token, backup_code:"K7Q2-M9XD4P"}` (acepta con/sin guion, lower/upper, trim; campo `code` con 10ch también autodetecta como backup — ver contracts). Sin Bearer.
5. El back valida pre-token + rate (idéntico CU-AUTH-02: challenge single-use, buckets, `401` opaco si challenge malo). Normaliza `canónico=upper(sin-guion-no-espacios)`; exige `^[2-9A-HJ-NP-TV-Z]{10}$` (malforma → `400 VALIDATION_FAILED`, sin consumir intento challenge — igual que TOTP malformado).
6. Calcula `hash` + `SELECT ... WHERE code_hash=$1 FOR UPDATE` en Tx: si miss o `used=true` → `RecordFail` challenge (igual TOTP, a 5 quema) + `401 INVALID_MFA` idéntico al TOTP-malo (sin distinguir backup vs TOTP, ver 4.2). Si hit `used=false` → `UPDATE SET used=true, used_at=now, used_challenge_id=$cid` (si 0 filas por carrera → `401` replay) + quema challenge (`DEL`, single-use) + `SessionIssuer.Issue` → `200 active` + cookies.
7. Post-commit async (outbox misma Tx): `backup.consumed` + `auth.login.mfa_challenged{method:backup}` + email alta prioridad `Usaste un código de respaldo (quedan N)` con IP/device-hora, links `Regenerar códigos` + `Si no fuiste tú asegura tu cuenta`, + audit. Quedan `N-1` (si `N-1<=2` el email y el `status` incluyen `warning:low`; si `0` incluyen `exhausted:true` + exigen regenerar autenticado o TOTP).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * `backup_code` malformato (longitud/alfabeto), ambos `code+backup_code` o ninguno, body >4KB → `400 VALIDATION_FAILED` (sin `RecordFail` challenge). Regenerate sin Step-Up → `401 STEP_UP_REQUIRED`.
* **4.2. Código inválido/consumido/agotado (opaco):**
  * Hash miss, `used=true` (ya consumido o superseded por regenerate), 0 restantes, challenge quemado/expirado, `aud` erróneo → SIEMPRE `401 INVALID_MFA` idéntico al TOTP (mismo body/tiempo ±jitter 20-50ms; el atacante no sabe si probó TOTP o backup ni si quedan). 5º fallo quema challenge con mismo `401`. Carrera: 2 consumes simultáneos mismo código → uno `200`, otro `401` (`UPDATE ... WHERE used=false` 0 filas).
* **4.3. Falla de servicio externo o infraestructura:**
  * Postgres down → `500` (sin sesión, sin quemar; fails no cuentan). Redis down → reuso CU-AUTH-02 (challenge DB-fallback, rate fail-open; consumo backup es PG-Tx así que sigue correcto sin Redis). Kafka/SMTP down → `200` igual (outbox + email pendientes; el email de alerta puede tardar, documentado).
  * Pepper ausente/rotado: verificación prueba `pepper_actual` y (solo durante ventana rotación `PEPPER_PREV`) `pepper_previo` (ConstantTime ambas); generación usa actual. Sin pepper → SHA puro + `WARN` (no `500`).
* **4.4. Rate-limit:** Comparte buckets `mfa:verify:*` CU-AUTH-02 (backup erróneo = 1 fail). Regenerate `10/hora/user` → `429`. Sin bucket propio que distinga tipo.
* **4.5. Bordes:** Regenerate con backups sin usar → quema los 10 aunque estén intactos (avisa `previos invalidados`). Disable MFA (CU-AUTH-02) → quema todos (`used=true, superseded`) + no se pueden usar ni regenerar hasta re-enable. Backup NO sirve en `DELETE /totp`, Step-Up, ni APIs negocio (solo `/mfa/verify`; elsewhere → `401`).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** 10 activos máx (generate/regenerate siempre dejan 10 `used=false`, resto `used/superseded`). Alfabeto/canónico exactos Q1; display con guion `4-6` solo UX.
* **RN-02:** Single-use irreversible (`used=true` + `used_at` + `used_challenge_id`, nunca `false` de nuevo, nunca `DELETE` físico — auditoría). Superseded por regenerate también `used=true` (no reutilizables aunque intactos).
* **RN-03:** Exhibición única (enable/regenerate response TLS). Prohibido `GET` valores, reenvío email con valores (el email de consumo NO incluye códigos restantes planos, solo count), o log de planos.
* **RN-04:** Consumo exige pre-token vigente + challenge no quemado (igual TOTP). Sin pre-token no hay consumo aunque el código sea correcto (evita bypass login).
* **RN-05:** Agotados (`remaining=0`) → verify-backup siempre `401`; el usuario usa TOTP o regenerate autenticado (con TOTP/Step-Up). Sin auto-regeneración silenciosa.
* **SEC-01:** Hash `SHA-256(canónico+pepper)` hex, `UNIQUE(code_hash)` global (colisión CSPRNG entre users imposible pero garantizada por constraint; colisión en generate → regenera ese código en memoria hasta 10 únicos + `INSERT ... ON CONFLICT DO NOTHING` + rellena).
* **SEC-02:** `ConstantTimeCompare` en hash compare (aunque el lookup por índice ya filtra, defensa en profundidad) + normalización previa estricta (evita bypass `lower/guion/espacios`).
* **SEC-03:** Alerta siempre (sin throttle): cada consumo → email alta prioridad + audit `backup.consumed` (si SMTP cae, outbox reintenta; si se consumen 3 seguidos en 10min → 3 emails, documentado como señal takeover que el usuario debe ver).
* **SEC-04:** Códigos solo memoria request + response TLS (nunca URL, nunca QR, nunca logs/spans/eventos con plano; eventos llevan `code_hash_prefix(8)` como correlación sin reversible).

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `backup_total{op="generate|consume|regenerate", result="ok|invalid|replay|rate_limited|exhausted|error"}` + `backup_remaining_gauge{bucket="0|1-2|3-10"}` (privada, por cardinalidad solo buckets) + `backup_consumed_total` + reuso `mfa_total{verify}` (consume-ok cuenta también como `mfa verify ok{method:backup}`).
* **Trazabilidad:** Hijos `Backup.GenerateHashes`, `Backup.ConsumeTx`, `Notify.BackupEmail` dentro de `UseCase.MFAEnable/Verify/Regenerate`. Atributos `remaining, code_hash_prefix`, nunca plano/token.
* **Auditoría:** `auth.audit.v1 {action:"backup.generate|consume|regenerate", result, remaining?, challenge_id?, trace_id}` + eventos `backup.generated|consumed|regenerated|failed` (key `user_id`). Sin plano.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Enable genera 10 y consume 1 con alerta**
  * **Dado** ACTIVE sin MFA, sesión fresca, enable TOTP válido.
  * **Cuando** `POST /enable` y luego `POST /login` → `202` + `POST /verify {mfa_token, backup_code:B1}`.
  * **Entonces** enable `200` con 10 planos únicos + DB 10 hashes (`SELECT` no contiene planos) + `GET /status {remaining:10}`; verify B1 → `200 active` + cookies + DB `B1.used=true` + `remaining:9` + email alta prioridad (Mailhog) + `backup_total{consume ok}` +1. Reuso B1 → `401` aunque cripto OK.
* **Escenario 2: Indistinguible TOTP vs backup + agotados**
  * **Dado** challenges frescos, casos: TOTP malo, backup inexistente, backup ya usado, 0 restantes.
  * **Cuando** se verifican los 4.
  * **Entonces** 4× `401 INVALID_MFA` byte-idénticos (p50 ±25ms n=50), 0 sesiones, fails cuentan igual (5º quema). Con `remaining:2` el próximo consumo trae `warning:low`; con `0` el consumo trae `401` + `status` sugiere regenerar.
* **Escenario 3: Regenerate quema y re-exhibe**
  * **Dado** 10 con 3 usados (`remaining:7`), sesión fresca.
  * **Cuando** `POST /backup-codes/regenerate` (Step-Up) → nuevos 10 + `POST /verify` con viejo intacto B_old.
  * **Entonces** regenerate `200` con 10 nuevos + viejos 7 marcados `superseded/used` + `remaining:10` nuevos; `B_old` → `401` (quemado) + email no (solo audit `superseded_use`). Stale (30min) → `401 STEP_UP_REQUIRED` sin quemar.
* **Escenario 4: Concurrencia y PG-down**
  * **Dado** backup B válido, 2 verifies simultáneos mismo B + mismo challenge? (mismo challenge solo 1 gana por single-use) y con challenges distintos mismo B.
  * **Cuando** compiten.
  * **Entonces** uno `200`, otro `401` (`used` + challenge quemado deterministas por Tx); PG-down → `500` sin quemar ni sesionar. Redis-down → consumo sigue `200` correcto (PG verdad) + rate fail-open.
