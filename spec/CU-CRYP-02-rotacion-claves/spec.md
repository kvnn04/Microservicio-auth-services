# Spec: CU-CRYP-02 - Rotación Programada de Claves Asimétricas Maestras

## 1. Contexto y Propósito
Rotar Ed25519 cada 90d sin downtime: genera `kid_nuevo`, coexiste 1h (emite nuevo, valida ambas), retira el previo (archiva pub, fuera de JWKS), con cache defensiva 60s en overlap y trigger dual cron+manual. Sin este CU, la clave eterna amplía blast-radius de fuga.

Decisiones (2026-10-05, todas Recommended):
- Q1 90d + overlap 1h + retiro+archivo, Q2 Cron diario + manual `POST /admin/keys/rotate` (admin + Step-Up `crypto:rotate` 12º scope), Q3 KMS-or-file0600 (nunca privada en PG), Q4 `kid YYYY-MM-<seq>`, Q5 60s en overlap (600s resto) + refetch-client, Q6 Archiva siempre (jamás DELETE pub), Q7 Puertos + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Cron worker (diario), Admin Ciberseguridad (manual), Microservicio Auth (signer+directory).
* **Precondiciones:**
  * ≥1 activa con `next_rotation_at` (nueva columna; default `created+90d`).
  * KMS/file escribible para la privada + PG para la pública (si KMS down → manual falla `500`, cron reintenta mañana; nunca genera sin custodiar).

## 3. Flujo Principal (Happy Path)
1. Disparo: cron diario `key-rotation-check` (worker 02:00) ve `now ≥ next_rotation_at - 7d` (ventana aviso: emite `keys.rotation_due` + email técnico a los 7d previos) o admin llama `POST /admin/keys/rotate` (auth admin + Step-Up `crypto:rotate`; rate `5/hora`; body `{reason?}`).
2. Genera en memoria `ed25519.GenerateKey(rand)` + `kid=YYYY-MM-<seq>` (seq = siguiente letra disponible del mes; colisión `UNIQUE` → reintenta letra; si agota a-z → `YYYY-MM-a2`... documentado) + custodia privada (KMS `CreateKey` o file `keys/ed25519-<kid>.key` 0600 + `priv_ref`) + Tx PG: `INSERT signing_keys(kid, pub_b64, alg, priv_ref, created)` + `UPDATE` la anterior `overlap_until=now+1h` (sigue activa) + `next_rotation_at=nueva+90d` + outbox (`keys.rotated{old,new}` + audit) + pub/sub `keys.rotated` (<1s a todas las instancias: `Signer.UseKid(nuevo)` + `Directory.Reload()` + JWKS `max-age=60s` modo overlap).
3. Overlap 1h: Issue firma SOLO `kid_nuevo`; JWKS sirve `[nuevo, viejo]`; gateways verifican ambas (los tokens pre-rotación con `kid_viejo` siguen `200`; los nuevos con `kid_nuevo` exigen refetch si cache vieja — norma CRYP-01).
4. Tras 1h (cron `key-retire-check` horario o el mismo worker): Tx `UPDATE signing_keys SET retired_at=now WHERE kid=viejo` + archiva pub (`key_archive` tabla offline o export `keys/archive-<kid>.pub` + audit `keys.retired`) + pub/sub `keys.retired` (Directory reload → JWKS `[nuevo]`, `max-age` vuelve 600s) + outbox + email `Rotación completada`.
5. La privada vieja se destruye en KMS/file (`DeleteKey`/`shred -u`, con confirmación `retired_at+7d` para forense de firmas en disputa — la PUB queda para verificar historia; la PRIVADA se destruye a los 7d post-retiro, documentado).

## 4. Flujos Alternativos y Excepciones
* **4.1. Sin custodia:** KMS/file no escribible → `500 KEY_CUSTODY_UNAVAILABLE` (sin INSERT huérfano sin privada; reintenta mañana/manual). Arranque sin activa → fail-fast (CRYP-01).
* **4.2. Concurrencia:** 2 rotates simultáneos (cron + manual) → `UNIQUE(kid)`/lock `rotate:mutex EX 300` (Redis; perdedor → `409 ROTATION_IN_PROGRESS`, sin doble-generar).
* **4.3. Rollback:** si la nueva firma falla en smoke-test post-generación (firma/verifica 1 JWT test en Tx? No en Tx: antes del INSERT público) → aborta (sin INSERT, sin pub/sub) + `500` + P1. Si el overlap detecta errores de verificación en gateways (tasa `401 kid-unknown` >1%/5min) → auto-extiende overlap +2h (una vez) + P1 (documentado).
* **4.4. Rate:** manual `5/hora/admin` → `429` (cron exento).
* **4.5. Multialg futuro:** si se introduce `ES256`, rota por familia independiente (cada `alg` su cadena `kid`; JWKS multialg; este CU versiona por `kid`, no por `alg` — documentado).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Cadencia 90d (`next_rotation_at`), aviso 7d previos, overlap 1h exactas (`overlap_until`), retiro tras overlap (no antes del TTL máximo 15min + cache 10min + margen — 1h lo cubre 4×).
* **RN-02:** Emite-nuevo/valida-ambas en overlap; emite-nuevo/valida-nuevo tras retiro (la vieja solo verifica historia offline, no online).
* **RN-03:** `kid` fecha+seq único; `next_rotation_at` siempre futuro (tras rotate = nueva+90d).
* **RN-04:** Cache 60s en overlap (JWKS header dinámico por estado overlap; `ETag` cambia con el set) + 600s resto.
* **RN-05:** Archivo pubs eternas (`key_archive`, auditoría legal); privadas destruidas +7d post-retiro (forense disputa).
* **SEC-01:** Privada jamás en PG/logs/outbox/audit (solo `kid` + `pub_b64` + `priv_ref` opaco). Generación con `crypto/rand` (nunca `math/rand`).
* **SEC-02:** Manual exige admin + Step-Up `crypto:rotate` (12º scope, añadido a matriz SEC-06 como extensión) + rate + audit `granted_by`.
* **SEC-03:** Mutex `rotate:mutex` (anti-doble) + smoke-test firma-antes-de-publicar + auto-extensión ante `401 kid-unknown` gateways.

## 6. Requerimientos de Observabilidad
* **Métrica:** `key_rotation_total{result="ok|in_progress|extended|error", trigger="cron|manual"}` + `keys_count{state="active|overlap|retired"}` + `overlap_gauge` (1 en overlap) + `jwks_max_age` (gauge 600|60) + `kid_unknown_401_total` (gateways reportan para auto-extensión).
* **Trazabilidad:** Raíces `UseCase.RotateKeys/RetireKeys` (hijos: `crypto.generate`, `kms.store`, `db.keys.insert`, `directory.reload`, `pubsub.broadcast`, `jwks.cache_mode`). Atributos `old_kid,new_kid`.
* **Auditoría:** `auth.audit.v1 {action:"keys.rotate|retire|extend", old_kid, new_kid, trigger, trace_id}` + eventos `keys.rotated|retired.v1` (key `new_kid`). Sin material privado (solo `kid`s).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Rotate programado sin downtime**
  * **Dado** activa `A` con tokens vivos (emitidos hace 5min, TTL 15min) + gateways con cache.
  * **Cuando** cron/manual genera `B` + overlap 1h + retiro.
  * **Entonces** durante overlap: nuevos JWT `kid=B` verifican (tras refetch) + viejos `kid=A` verifican (sin refetch) + JWKS `[B,A]` + `max-age=60`; tras 1h: JWKS `[B]` + `max-age=600` + viejos Access expirados naturalmente (≤15min) sin `401` prematuro en ningún momento + `rotation_total{ok}` +1. p95 Issue durante rotate <300ms (sin contención `rotate:mutex` fuera del camino Issue salvo `UseKid` atómico).
* **Escenario 2: Manual + concurrencia + custodia**
  * **Dado** admin sin Step-Up / con Step-Up; cron+manual simultáneos; KMS down.
  * **Cuando** `POST /rotate` ambos casos + doble disparo + KMS-caído.
  * **Entonces** sin Step-Up → `401`; con Step-Up → `202 accepted` (rotate async <30s) + 2º simultáneo → `409 IN_PROGRESS`; KMS-down → `500` sin INSERT + reintento mañana (cron) + P1 si manual.
* **Escenario 3: Auto-extensión + archivo**
  * **Dado** gateways con `401 kid-unknown` >1%/5min en overlap (cache rebelde).
  * **Cuando** monitor lo detecta.
  * **Entonces** overlap +2h una vez + P1 + `extended` +1; tras retiro, `key_archive` contiene pub `A` (verifica un JWT viejo offline OK) y la privada `A` se destruye a +7d (intento usarla → `500` no hay).
