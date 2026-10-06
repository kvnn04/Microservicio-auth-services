# Spec: CU-CRYP-03 - Mitigación de Desastres por Fuga o Compromiso de Secretos

## 1. Contexto y Propósito
Botón rojo ante privada comprometida: revoca el `kid` sin overlap (JWKS purga + `no-store`), corta TODO con epoch global + batches (Access/pre/MFA/step-up/pless mueren; families/sessions caen por lotes), genera sucesora ya, destruye la privada YA (archiva pub forense) y avisa en broadcast + bulk-mail + banner. Difiere de CRYP-02 (programado, con overlap y sin corte): aquí la continuidad cede ante la contención.

Decisiones (2026-10-05, todas Recommended):
- Q1 Epoch global + batches 1000 (sin Tx gigante), Q2 Triple rojo (admin + Step-Up `crypto:emergency` 13º + `REVOKE <kid>`, 1/hora, P1), Q3 Purge inmediata (`no-store` 1h + pub/sub), Q4 Todo muere (toda JWT local + sessions batched), Q5 Broadcast + bulk 10k/min + `401 EMERGENCY_RELOGIN` banner, Q6 Nueva ya + destroy priv YA + archiva pub, Q7 Puertos + drill-mode trimestral + P1.

## 2. Actores y Precondiciones
* **Actores:** Admin Ciberseguridad (botón), Microservicio Auth (ejecutor), Gateways/Satélites (purgan), Usuarios (re-autentican), Worker (batches/mails).
* **Precondiciones:**
  * `kid` objetivo activo (si ya retirado → `409 ALREADY_RETIRED`, sin drama).
  * `EMERGENCY_ENABLED=true` (kill-switch config; en `false` el endpoint responde `503 DISABLED` — evita drills accidentales en prod congelado).
  * Custodia escribible para la sucesora (si falla → igual se revoca (contención primero) y la firma queda con... ninguna activa → Issue `500` hasta resolver. Decisión: contención SIEMPRE precede a continuidad (primero mata, luego genera; si generar falla, P1 + reintento 1min hasta lograr sucesora).

## 3. Flujo Principal (Happy Path — fuego real)
1. Admin envía `POST /api/v1/auth/admin/keys/emergency-revoke {kid, confirm:"REVOKE <kid>", reason}` + Bearer admin + Step-Up `crypto:emergency` + `X-Request-ID`. Valida triple (sin Step-Up → `401`; frase inexacta → `400 CONFIRM_MISMATCH`; rate `1/hora` global (no por admin — el botón es global; 2º fuego/hora → `429` + P1 `double-fire`) → `409` si `kid` no activo).
2. Fase 1 — purga (segundos, Tx pequeña): `UPDATE signing_keys SET retired_at=now(emergency) WHERE kid` + `Directory.Reload()` + `PUBLISH keys.emergency{kid, epoch}` + JWKS modo `no-store 1h` (header dinámico por `emergency_active` flag Redis EX 3600) + outbox (`keys.emergency_revoked`) + audit P1. Desde aquí el `kid` NO verifica en ningún lado (gateways que purgaron) y la privada vieja se destruye YA (`Custody.Destroy`, sin +7d).
3. Fase 2 — epoch (misma Tx o inmediata siguiente): `UPDATE system_flags SET crypto_epoch=now()` + `PUBLISH crypto.epoch` + memo gateways (`epoch` cache 10s + pub/sub ~1s). Toda JWT local con `iat<epoch` muere en verificación (cualquier `aud`: api, mfa-challenge, step-up, device-challenge — los verificadores comparan `iat` contra `epoch` ADEMÁS de `exp`; documentado como chequeo obligatorio post-emergencia).
4. Fase 3 — batches (minutos, reanudable): worker `emergency-sweep` por lotes `1000 FOR UPDATE SKIP LOCKED`: `UPDATE families revoked + DELETE sessions` + progreso (`emergency_revoke_progress{done,total}` + `revoke_rate` 5k/s objetivo) hasta 0 vivas. Pre/step/mfa challenges en Redis se `DEL` por patrón (`mfa:challenge:*` no es por user... no indexado por user: se `FLUSHDB` selectivo? No: se dejan expirar (≤5min) + `epoch` ya los mata en verificación (iat<epoch) — documentado: el epoch cubre lo que el sweep no alcanza).
5. Fase 4 — sucesora (paralela a 3, no bloquea contención): genera `kid_nuevo` (igual CRYP-02 generate+custody+smoke) + `INSERT` activa + `UseKid` + `Directory.Reload` + outbox (`keys.rotated{emergency:true}`) → Issue vuelve a `200` para re-logins (los tokens pre-fuego siguen muertos por epoch aunque firmen con kid sano? No: los pre-fuego firmaban con kid MUERTO (firma inválida ya) O con kid sano pero `iat<epoch` (epoch los mata). Correcto en ambos casos).
6. Broadcast + bulk: Kafka `keys.emergency` (todos purgan JWKS/sesiones-cache YA) + bulk-mail `Re-autentícate (incidente de seguridad)` encolado 10k/min (sin bloquear; `emergency_mail_lag` métrica) + front muestra banner ante `401 EMERGENCY_RELOGIN` (código nuevo solo post-emergencia: los verificadores responden `EMERGENCY_RELOGIN` en vez de genérico cuando `iat<epoch`, para banner; documentado como única excepción al opaco, justificada por respuesta masiva).
7. Cierre: `emergency_active` expira (1h) → JWKS vuelve `600s`; `crypto_epoch` QUEDA (no se revierte — los pre-fuego mueren para siempre); post-mortem obligatorio (plantilla en tasks T-14).

## 4. Flujos Alternativos y Excepciones
* **4.1. Drill (simulacro):** `POST .../emergency-revoke?dry_run=true` (mismo triple) recorre TODO sin commitear (Tx rollback + `drill=true` en audit + métrica `emergency_drill_total`): genera kid efímero (sin custodiar), calcula batches (COUNT, sin DELETE), emite broadcast `drill` (gateways lo ignoran salvo log). Trimestral obligatorio (Q7).
* **4.2. Doble-fuego / kid sano:** 2º fuego <1h → `429` + P1 (evita pánico-loop); `kid` inexistente/retirado → `404/409` (sin epoch, sin batches — no se corta todo por un typo; la frase `REVOKE <kid>` + Step-Up ya filtran).
* **4.3. Infra en fuego:** PG down → `500` (reintenta; la purga-JWKS en memoria de la instancia que recibió el POST SÍ se aplica local + pub/sub a hermanas aunque PG falle? No: sin Tx no hay verdad; se responde `500` sin cambiar nada + P1. Documentado fail-closed en fuego (mejor no-cortar-a-medias que cortar la mitad). Redis down → PG verdad + pub/sub degradado a poll 10s (gateways) + `WARN`. Kafka down → fases 1-4 igual (outbox pendiente; el pub/sub Redis compensa lo inmediato).
* **4.4. Sin sucesora (custodia caída):** contención hecha, Issue `500` (`no active key`) hasta lograr sucesora (reintento 1min ×60 + P1). Ventana sin firma = apagón auth (aceptado ante fuga; documentado RTO).
* **4.5. Multialg:** revoca por `kid` (una familia `alg`); si la fuga es del proveedor KMS (no de un kid) → revoca TODOS los kids de ese `priv_ref` + rota familia completa (loop por `kid`, documentado).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Sin overlap (retiro inmediato + `no-store` 1h). Sin `valid_after` por user (epoch global lo sustituye en fuego; los `valid_after` individuales se conservan intactos).
* **RN-02:** Epoch única para TODA JWT local (cualquier `aud`): verificadores la chequean (`iat<epoch → 401 EMERGENCY_RELOGIN`) con cache 10s + pub/sub.
* **RN-03:** Batches 1000 `SKIP LOCKED`, reanudables (checkpoint `emergency_sweep_cursor`), progreso público (`/admin/keys/emergency/status` con Bearer admin: `{done,total,epoch}`).
* **RN-04:** Triple rojo + rate global 1/hora + P1 por fuego (y por doble-fuego intentado).
* **RN-05:** Privada vieja destruida YA; pub archivada (`key_archive` + `forensics` flag); sucesora inmediata (contención primero, continuidad después, ambas P1).
* **RN-06:** Drill trimestral con mismo código path (`dry_run=true`) + post-mortem tras fuego real (plantilla).
* **SEC-01:** `crypto:emergency` 13º scope (solo `break-glass` admins; ni siquiera `admin` genérico sin ese scope dispara fuego — documentado separación `rotate` vs `emergency`).
* **SEC-02:** `EMERGENCY_ENABLED` kill-switch + `confirm` frase exacta (anti-CSRF de consola: el front admin la pide tipada, no checkbox).
* **SEC-03:** `user.erased`-style: el broadcast NO lleva material (solo `kid, epoch`); el bulk-mail NO lleva links de sesión (solo `login` genérico + `qué pasó`).

## 6. Requerimientos de Observabilidad
* **Métrica:** `emergency_total{result="ok|drill|disabled|rate|error", trigger}` + `emergency_revoke_progress{done,total}` + `crypto_epoch` (gauge unix) + `jwks_emergency_mode` (0|1) + `emergency_mail_lag_seconds` + `kid_unknown_401_total` (pico post-fuego esperado).
* **Trazabilidad:** Raíz `UseCase.EmergencyRevoke` (hijos: `stepup.check`, `db.keys.retire`, `epoch.bump`, `directory.reload`, `pubsub.broadcast`, `batches.sweep`, `successor.issue`, `outbox.insert`). Atributos `kid, epoch`.
* **Auditoría:** `auth.audit.v1 {action:"keys.emergency_revoke|drill", kid, epoch, admin, trace_id}` P1 + eventos `keys.emergency.v1` (key `kid`) + `crypto.epoch_bumped`. Sin material (solo `kid`s).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Fuego corta todo y vuelve con nueva**
  * **Dado** 3 sesiones + Access/MFA/step-up tokens vivos `kid=A`, gateways cacheados.
  * **Cuando** `POST /emergency-revoke {A, REVOKE A}` triple-OK.
  * **Entonces** <5s: JWKS sin `A` (`no-store`) + gateways `401 EMERGENCY_RELOGIN` (Access viejos, aunque `exp` futura) + batches → 0 sesiones/families + pre/MFA/step-up viejos `401` por epoch + sucesora `B` activa + re-login `200` con `kid=B` + bulk-mail encolado + P1. Priv `A` destruida (intento usarla → error custodia) + pub `A` archivada (verifica un forjado offline OK para forense).
* **Escenario 2: Triple-fail + drill + doble-fuego**
  * **Dado** sin Step-Up / frase `REVOKE B` con `kid=A` / `dry_run=true` / 2º fuego a los 20min.
  * **Cuando** cada uno.
  * **Entonces** sin Step-Up → `401`; frase mal → `400` (0 cambios); drill → `200 drill` (0 cambios, audit `drill`, métrica); 2º fuego → `429` + P1 (sin re-epoch). `kid` inexistente → `404` (sin corte).
* **Escenario 3: Custodia caída + PG-down + bulk**
  * **Dado** KMS down; PG down; 100k users.
  * **Cuando** fuego.
  * **Entonces** KMS-down → contención OK (purga+epoch+batches) + Issue `500` hasta sucesora (reintento 1min, P1, RTO medido); PG-down → `500` sin cambios (fail-closed, reintenta); bulk 100k → encolado 10k/min (`mail_lag` visible, 0 bloqueo request). Batches reanudables tras caída worker (cursor).
