# Spec: CU-CRED-02 - Cambio de Contraseña desde Sesión Activa

## 1. Contexto y Propósito
Rotar la clave con sesión abierta exigiendo la actual (que equivale a Step-Up, sin header extra) o token Step-Up si no hay password (federated-set). Impide reciclaje con historial N=5, mantiene solo el `sid` actual y revoca pares, y alimenta locks de cuenta. Sin este CU, una sesión desatendida podría perpetuarse tras el cambio.

Decisiones (2026-10-05, todas Recommended):
- Q1 Basta `current_password` (=Step-Up; federated-set exige token), Q2 Historial N=5 (Verify×5, append-only), Q3 Mantiene actual + revoca pares (sin `valid_after` global), Q4 Federated-set permitido con token (sin current), Q5 Policy CU-REG-01 + ≠actual + ∉historial + HIBP + rate 5/hora, Q6 Current mala cuenta a lock + `401` (policy `400` interno ok), Q7 `POST /password/change` + tabla history + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado ACTIVE (Bearer válido, cualquier `auth_time` — la `current_password` suple frescura; federated-set exige `X-Step-Up-Token` scope `cred:change-password` o fast-pass ≤5min).
* **Precondiciones:**
  * `users.status=ACTIVE`. Con `password_hash` non-null exige `current_password`; sin hash (federated-only) exige Step-Up token/fast-pass y omite `current`.
  * Rate `pwdchange:user 5/hora` libre (si excede → `429`).

## 3. Flujo Principal (Happy Path)
1. Usuario envía `POST /api/v1/auth/password/change {current_password?, new_password}` + Bearer (+ `X-Step-Up-Token` solo si federated-set) + `X-Request-ID` (≤8KB).
2. El back valida Bearer ACTIVE + rate (5/hora/user → `429`). Valida policy `new_password` (igual CU-REG-01: 12ch/clases/HIBP/NFKC; malforma → `400 POLICY_*` con details, sin tocar hash ni fails de cuenta? Sí toca `pwdchange` rate pero no `login fails`).
3. Si tiene password: `Argon2id.Verify(current, stored)` + `ConstantTime` + dummy si hash corrupto (imposible) + sin jitter extra (ya autenticado, timing no oracula a anónimos; pero mantiene `Verify` real para no filtrar por tiempo a quien posee sesión secuestrada? Igual se hace homogéneo con `Verify` siempre real). Si falla → `RecordFail` login-tracker (5/15min lock, reuso CU-AUTH-01) + `401 INVALID_CURRENT` (sin revelar policy). Si federated-set: verifica Step-Up (`Guard` CU-AUTH-06: fast-pass o token scopeado; si no → `401 STEP_UP_REQUIRED/INVALID`).
4. Chequea `Verify(new, current_hash)==false` (si `true` → `400 PASSWORD_REUSED`, sin quemar nada, sin contar fail). Chequea historial: `SELECT hash FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT 5` + `Verify(new, h_i)` c/u (si alguno `true` → `400 PASSWORD_IN_HISTORY {meta:{n:5}}`). HIBP ya validado en policy (si timeout → fallback local + `WARN`, igual registro).
5. Genera `newHash=Argon2id(new)` (mismos `m/t/p`/pepper) y en UNA Tx PG: `INSERT password_history(user_id, hash=oldHash)` (guarda la saliente) + `UPDATE users SET password_hash=newHash, password_ver=ver+1, updated_at` + `UPDATE refresh_families SET revoked WHERE user_id AND family<>currentFamily` + `DELETE sessions WHERE user_id AND sid<>currentSID` + `DEL` Redis pares (`sess:<uid>:*` menos actual, `fam:*` menos actual) + outbox (`password.changed{via:change}` + `session.revoked_peers{kept_sid}` + audit). Si federated-set además `federated_only=false`.
6. Retorna `200 {status:password_changed, sessions_revoked:N}` + `Cache-Control: no-store`, mantiene cookies/sesión actual (no re-emite `Issue`; el Access actual sigue válido — su `password_ver`? Si el Access llevara `pwd_ver`, el actual quedaría viejo; decisión vinculante: el Access NO lleva `pwd_ver` (solo `roles_ver`), así el actual sobrevive y los pares mueren por `family revoked` + `sess DEL`. Documentado).
7. Email siempre `Cambiaste tu clave (mantuvimos este dispositivo, cerramos otros N)` con hora/IP + `si no fuiste tú recupera` (sin throttle, es acto propio verificado).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** sin Bearer/inválido → `401`; `new_password` policy-fail → `400 POLICY_*` (sin fail cuenta, sin hash nuevo); `current` ausente cuando se exige → `400 MISSING_CURRENT` (distinto de `401` mala — el front distingue programáticamente, sin riesgo externo pues ya autenticado); body >8KB → `413`. El back no acepta campo `confirm` (desconocido → `400 INVALID_JSON`).
* **4.2. Current/history:** `current` errónea → `401 INVALID_CURRENT` + `RecordFail` (a 5 → lock 15/30/60 igual login; durante lock incluso la buena da `401` hasta expirar). `new==actual` → `400 PASSWORD_REUSED`; `new∈historial5` → `400 PASSWORD_IN_HISTORY`; hist-dirty (hash corrupto en history que falla Verify con error, no `false`) → se ignora ese registro + `WARN` (no bloquea cambio legítimo).
* **4.3. Infra:** PG down → `500` (sin cambiar nada; history no se inserta sin Tx); Redis down → PG verdad + `WARN` (pares se revocan en PG y se borran sus claves si Redis responde; las huérfanas expiran por TTL — PG es la verdad); Kafka down → `200` igual (outbox pendiente); HIBP timeout → fallback + `WARN`.
* **4.4. Rate:** `pwdchange:user 5/hora` → `429 + Retry-After` (sin distinguir causa). `step-up:challenge` buckets aplican solo en federated-set (reuso CU-AUTH-06).
* **4.5. Federated-set borde:** federated-only con Step-Up válido pero `current_password` enviado (ignorado? No: si no hay hash, cualquier `current` → `400 UNEXPECTED_CURRENT` para no confundir). Tras set, `password_history` base = 0 previas (la federated no aporta hash) + login password ya funciona (más `mfa` si tenía).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** `current_password` obligatorio si hash existe (equivale a Step-Up scope `cred:change-password`; no se exige header adicional). Federated-set exige Step-Up (fast-pass o token) y prohíbe `current`.
* **RN-02:** Historial `password_history(user_id, hash, created_at)` append-only (`UNIQUE(user_id,hash)` para no duplicar si reutiliza tras >5? No: si reutiliza tras 6 cambios está permitido y se inserta de nuevo? No — `UNIQUE` lo impediría; decisión: SIN unique global, solo `INDEX(user)`, se permite re-insertar hash viejo que salió de ventana (documentado). Retención indefinida (auditoría), N=5 ventana móvil.
* **RN-03:** `new ≠ actual` (Verify) y `new ∉ últimos 5` (Verify×5). Coste peor caso 6×Argon2 (`current` + `new-vs-actual` + 5) ≈ 900ms, aceptable con rate 5/hora (documentado SLO `p95<1200ms` este endpoint).
* **RN-04:** Revocación pares: mata `families/sessions` salvo `currentFamily/sid` (actual sobrevive sin re-login). `tokens_valid_after` NO se toca (mataría actual). Email siempre (acto propio).
* **RN-05:** Idempotencia RequestID 24h (mismo RequestID replay → mismo `200` sin re-hashear si ese RequestID ya cambió; distinto RequestID con misma `new` tras cambio → `400 REUSED` (ya es la actual)).
* **SEC-01:** `current/new` solo memoria+TLS (nunca logs/spans/eventos/URL; `new` se hashea y se olvida; `current` se verifica y se olvida). `ConstantTime` + `Verify` real siempre que hay hash.
* **SEC-02:** Fails cuentan a lock cuenta (reuso tracker login; `pwdchange` fails alimentan `login:fails` para no duplicar contadores — documentado).
* **SEC-03:** Sin `valid_after` global aquí (CRED-01 sí); pares mueren por `family revoked + sess DEL` (gateway los rechaza por `fam`/`sess` miss aunque Access firme OK y no expirado — requiere gateway que chequea denylist/sesión en refresh, y Access corto 15min limita ventana residual sin check por-request; documentado trade-off vs stateless puro).

## 6. Requerimientos de Observabilidad
* **Métrica:** `password_change_total{result="success|invalid_current|policy_failed|reused|in_history|step_up_required|validation_failed|replayed|error", via="change|set"}` + duración (incluye Verify×N) + `pwdchange_history_hits_total` + `sessions_revoked_peers_total` + `pwdchange_hibp_fallback_total` (+ `login_locks_total` reutilizado). Los `429` del bucket se cuentan en la capa HTTP, no aquí.
* **Trazabilidad:** Raíz `UseCase.ChangePassword` (hijos: `auth.check`, `ratelimit`, `crypto.verify_current`, `crypto.policy+hibp`, `crypto.history_check×N`, `crypto.argon2.hash`, `db.password.update+history+revoke_peers`, `outbox.insert`). Atributos `history_checked`, nunca claves.
* **Auditoría:** `auth.audit.v1 {action:"password.change", result, peers_revoked, trace_id}` + eventos `password.changed{via:change|set}` + `session.revoked_peers{kept_sid}` (key `user_id`). Sin hashes/claves (solo `password_ver` nuevo).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Cambio con pares revocados, actual vive**
  * **Dado** ACTIVE con 3 sesiones (A actual, B, C), password conocida, quotas libres.
  * **Cuando** `POST /change {current:ok, new:Válida-2026!}` con Bearer A.
  * **Entonces** `200 {peers_revoked:2}`, `Verify(new)` true (vieja false), `history` +1 (vieja), B/C Refresh fallan (`revoked`) y Access viejos expiran sin renovar, A sigue (`200` en API con mismo Access), email `Cambiaste` + audit. `POST /login` vieja → `401`, nueva → `200`.
* **Escenario 2: Current mala + historial + federated-set**
  * **Dado** historial con 2 previas (H1,H2).
  * **Cuando** `current:mala` / `new:H1` / `new:actual` / federated-only `set` sin token.
  * **Entonces** mala → `401 INVALID_CURRENT` + fail (5ª → lock, buena también `401` hasta expirar); `new:H1` → `400 IN_HISTORY`; `new:actual` → `400 REUSED`; federated sin token → `401 STEP_UP_REQUIRED`; con token + `new` válida → `200` set + history base.
* **Escenario 3: Rate + PG/Redis down**
  * **Dado** 6 cambios/hora mismo user; PG down; Redis down.
  * **Cuando** 6º cambio, cambio con PG down, cambio con Redis down.
  * **Entonces** 6º → `429`; PG-down → `500` sin cambiar hash/history/sesiones; Redis-down → `200` vía PG + `WARN` + pares Redis purgados al recuperar.

## 8. Notas de Implementación (desviaciones documentadas, 2026-10-06)

> El comportamiento observable (contratos §1-§2) **no cambia**.

* **D-01 — TOCTOU por `password_ver` optimista, sin re-`Verify` en Tx.**
  El plan pedía re-verificar `≠old` dentro de la Tx; en su lugar la Tx
  fija la base con `SELECT … FOR UPDATE` y exige `password_ver` esperado:
  una rotación concurrente intermedia deja 0 filas → `400 REUSED` opaco.
  Garantía equivalente (1×200 + 1×REUSED probado en carrera real) sin
  llevar el plano a la Tx.
* **D-02 — Rate y Step-Up fuera del middleware de la ruta.**
  El bucket `pwdchange:user 5/h` vive en el handler (necesita el `uid`
  autenticado) y el token Step-Up se verifica en el servicio solo en la
  rama federated-set (`current_password` equivale a Step-Up y no exige
  header). No se usa `RequireStepUp` en esta ruta porque bloquearía con
  `401` a sesiones stale que presentan `current` válida.
* **D-03 — `sid` actual vía contexto ("" con Bearer legacy → corte total).**
  `RequireAuth` expone `AuthSIDFromContext` (poblado desde `sid` del JWT
  Ed25519; vacío en legacy). Sin `sid` no hay forma de preservar la
  sesión: se revocan todas (fail-closed, igual que CRED-01). En prod
  (Ed25519) la actual siempre sobrevive.
* **D-04 — Sin índice `sess:by_user` ni `SADD` en Issue.**
  El plan pedía mapear `sid` por usuario en Redis para borrar sin SCAN;
  en su lugar la Tx lista las sesiones en PG (`SELECT … WHERE user_id`)
  y borra esas claves exactas post-commit. Cero SCAN/`KEYS`, sin cambios
  en CU-AUTH-04 ni migración de Redis.
* **D-05 — Emails sin IP cruda (solo hora).**
  La capa de persistencia solo maneja hashes: el aviso lleva hora UTC +
  conteo de pares + consejo (igual que D-03 de CU-CRED-01).
* **D-06 — N/rate como consts de dominio, no env (`PWD_HISTORY_N`, …).**
  Igual que D-01 de CU-AUTH-05 y D-05 de CU-CRED-01: reglas fijas §5
  (`PasswordHistoryN=5`, `PwdChangeRatePerHour=5`).
* **D-07 — k6 `pwdchange_smoke.js` creado, no ejecutado en vivo** (igual que
  `pless/stepup_smoke.js`): pendiente de ventana pre-productiva.
* **D-08 — Modo de verificación de referencia: serie (`-p 1`).**
  Los paquetes de integración comparten la DB local y los setups E2E
  hacen wipes globales (`DELETE FROM users/outbox`); en paralelo pueden
  darse flakes (FK/deadlock/filas barridas) ajenos al producto. Los tests
  llevan re-asegurado + reintento una vez, y el gate se verifica en serie
  (100% verde) además de en paralelo.
* **D-09 — Sin campo `confirm` (aunque §3/§4 lo mencionaban).**
  El back solo acepta `{current_password?, new_password}`; un `confirm`
  enviado cae en `400 INVALID_JSON` (desconocido). La doble escritura la
  valida el front localmente.

  **Evidencia de verificación:** `go vet ./...` limpio, `go build ./...` OK,
  `go test ./... -count=1` verde en serie (`-p 1`) y en paralelo.

  **Security Gate 🟢 PASSED (STRIDE):** `current`=Step-Up (federated con
  token scopeado); Verify×N con pepper + `ConstantTime`; sin claves/hashes
  en logs, métricas, spans ni eventos (solo `ver`, conteos); pares muertos
  + actual viva sin `valid_after` global (Access 15min acota ventana
  residual); rate 5/h + locks exponenciales reutilizados; `no-store`.
