# Spec: CU-SEC-05 - Eliminación de Cuenta y Derecho al Olvido (Data Privacy)

## 1. Contexto y Propósito
Ejecutar el olvido en dos tiempos: corte instantáneo + gracia reversible 30d (`DELETION_REQUESTED`, sin login) y, vencida, destrucción PII + anonimización de trazas + evento downstream, con retención fiscal mínima aislada. Sin este CU, GDPR art. 17/20 queda en promesa.

Decisiones (2026-10-05, todas Recommended):
- Q1 Gracia 30d + `POST /cancel` con Step-Up restaura, Q2 Triple (Step-Up `account:delete` + email tipado + accepted), Q3 Corte ya (`valid_after` + revoke-all + MFA/secrets off + `403 ACCOUNT_DELETED`), Q4 Destroy PII + anon ledger/audit + consent-proof + `user.erased`, Q5 Fire-and-forget + DLQ (sin 2PC), Q6 `retention_ledger` mínima cifrada 7a auditor-only, Q7 Gracia shadow-bloquea email, hard lo libera.

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado ACTIVE (Bearer + Step-Up `account:delete`), Microservicio Auth, Worker (purga/emails/eventos), Satélites (consumen `user.erased`).
* **Precondiciones:**
  * `users.status=ACTIVE` (PENDING/LOCKED → resolver primero; `DELETION_REQUESTED` → solo `cancel`/espera; `ANONYMIZED` → `404` base).
  * Sin pagos/subscripciones abiertas? Fuera de Auth (el front advierte; Auth no bloquea por facturación — documentado; la retención fiscal cubre lo legal).

## 3. Flujo Principal (Happy Path)
### A. Solicitud (corte + gracia)
1. Usuario envía `POST /api/v1/auth/account/deletion/request {confirm_email, accepted:true}` + Bearer + `X-Step-Up-Token` (scope `account:delete`) o fast-pass ≤5min + `X-Request-ID`. El back valida Guard Step-Up (falla → `401 STEP_UP_REQUIRED/INVALID`), `confirm_email` normalizado == actual + `accepted==true` (si no → `400 DELETION_CONFIRM_REQUIRED`, sin tocar nada).
2. Rate `deletion:user 3/día` (anti-clic-loop; excede → `429`).
3. En UNA Tx PG: `UPDATE users SET status='DELETION_REQUESTED', deletion_requested_at=now, deletion_effective_at=now+30d, tokens_valid_after=now` + `UPDATE families revoked` + `DELETE sessions` + `UPDATE mfa_totp_secrets SET enabled=false (soft, conserva cifrado por si cancela)` + `UPDATE mfa_backup_codes SET used=true WHERE !used` (quema sin borrar) + outbox (`deletion.requested` + `revoked_all{reason:deletion}` + audit) + Redis sweep (sess/fam/challenges DEL). Email `Recibimos tu solicitud (tienes 30 días, cancela aquí)` + `si no fuiste tú asegura`.
4. Retorna `202 {status:deletion_requested, effective_at:+30d}` + Clear-Cookie actual + `no-store`. Desde aquí: login → `403 ACCOUNT_DELETED {effective_at}` (cualquier método, incluso buena + MFA; federado igual); `cancel` sí permitido (ver 5); registro mismo email → shadow-bloqueado (CU-REG-03: `DELETION_REQUESTED` cuenta como existente).
### B. Cancelación (gracia)
5. Dentro de 30d: `POST /account/deletion/cancel` + Bearer? No hay Bearer vivo (revocamos todo). ¿Cómo se autentica para cancelar? Con password + MFA de nuevo (re-login está bloqueado por `403`)... Contradicción. Resolución vinculante: el cancel usa link mágico al correo (prueba posesión buzón, igual que reset): `POST /deletion/cancel/start` (anónimo, `{email}` → `202` opaco + link 15min si `DELETION_REQUESTED`) + `POST /deletion/cancel/confirm {token}` → restaura `ACTIVE` + `deletion_*=null` + `tokens_valid_after` se MANTIENE (las sesiones viejas no resucitan; debe loguear de nuevo) + MFA re-habilitado (un-quema? Los backups quemados NO resucitan — debe regenerar; TOTP secreto conservado se re-activa) + outbox `deletion.cancelled` + email. (Alternativa re-login directo vetada: el `403` lo impide por diseño.)
### C. Ejecución hard (worker, tras 30d sin cancel)
6. Cron diario `deletion-executor` (worker 04:00): `SELECT ... WHERE status=DELETION_REQUESTED AND effective_at<=now() FOR UPDATE SKIP LOCKED` (lotes 100): por cuenta, en Tx: destruye PII (`email_original='deleted.invalid'`, `email_normalized='deleted+'||id||'@invalid'`, `password_hash=NULL`, `federated sub/email_at_link → NULL/'deleted'`, `DELETE secrets/tokens/sessions/families/challenges/backup/geo/device`, `mfa_enabled=false`), inserta `retention_ledger` mínima si aplica (facturación ref, Q6), marca `status='ANONYMIZED'`, `anon_id=anon:<sha256(user_id+salt)>`, anonimiza vistas audit/consent (SEC-04: `audit_log_public` mapea `user_id→anon_id`; filas crudas restringen a `auditor_role`), outbox (`user.erased{user_id, anon_id}` + audit `deletion.executed`) + email al (ex-)correo? Ya no existe buzón propio (el email se destruyó); el aviso de ejecución va... a ningún lado (documentado: el último email es el de solicitud + recordatorio día 25; la ejecución no envía (sin destino)).
7. Email recordatorio día 25 (worker): `Tu cuenta se elimina en 5 días (cancela aquí)` (si canceló, no se envía). Tras hard: el email queda LIBRE para re-registro limpio (sin vínculo al `anon_id`).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** sin Bearer/Step-Up → `401`; `confirm_email` mismatch/`accepted!=true` → `400` (sin Tx); ya `DELETION_REQUESTED` → `409 DELETION_ALREADY_REQUESTED` (con `effective_at`); `ANONYMIZED` → `404` base (ya no existe). Rate `429`.
* **4.2. Cancel fuera de ventana:** `effective_at` pasado + job ya corrió → `410 DELETION_EXECUTED` (irreversible; debe registrar de nuevo). Token cancel expirado/consumido → `400` opaco (igual reset).
* **4.3. Infra:** PG down → `500` (sin corte parcial); Redis down → PG verdad + `WARN` (sweep pendiente); Kafka down → `202` + outbox pendiente (el `user.erased` puede tardar; satélites reconcilian por poll `GET /internal/erased-since`? No MVP: solo bus + DLQ + reintento 24h, documentado); SMTP down → `202` + emails pendientes (el corte no espera al correo).
* **4.4. Federated/MFA atados:** `sub` Google de la cuenta borrada se libera (otro user podría linkearlo después — correcto: el `sub` es del humano, no de la cuenta). TOTP secreto se DESTRUYE en hard (no se conserva; si vuelve debe re-enrollar).
* **4.5. Retención fiscal:** si `retention_ledger` tiene fila (facturación), el hard la conserva (cifrada `AES-GCM`, `auditor_role` only, TTL 7a default `RETENTION_YEARS`, purga anual con `audit_purged`). Sin fila fiscal → nada se conserva salvo audit/consent anonimizados.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Estados `ACTIVE → DELETION_REQUESTED (30d) → ANONYMIZED` (solo adelante; atrás solo vía `cancel` en gracia; `ANONYMIZED` terminal).
* **RN-02:** Triple confirmación (Step-Up + email tipado + accepted). `confirm_email` compara normalizado (no original con espacios).
* **RN-03:** Corte instantáneo (revoke-all + `valid_after` + MFA off + backups quemados + `403` logins). Sin auto-borrado parcial.
* **RN-04:** Email en gracia shadow (CU-REG-03 lo trata como existente); tras hard libre (`deleted+id@invalid` no colisiona con reales).
* **RN-05:** Cancel solo vía link al correo (no re-login, que está `403`; no Bearer, que murió). Link 15min 1 uso (igual reset, tabla propia o reuso `password_reset`-like con `purpose=cancel_deletion` — decisión: tabla propia `deletion_cancel_tokens`, no mezclar).
* **RN-06:** Downstream fire-and-forget (`user.erased` + DLQ 24h; sin ACK satélite; cada satélite es responsable GDPR de su purga).
* **SEC-01:** Sin PII en eventos post-hard (solo `anon_id` + `user_id` histórico para correlación satélite — el `user_id` en `user.erased` es necesario para que purguen; se envía UNA vez y no se re-emite; documentado base legal).
* **SEC-02:** `retention_ledger` cifrada + `GRANT auditor_role` only (app no lee; solo inserta vía `SECURITY DEFINER` + purga anual).
* **SEC-03:** `403 ACCOUNT_DELETED` solo en contexto propio/autenticado o con email exacto en cancel-start? El `POST /login` con email borrado-en-gracia da `403` (revela que existe-pero-borrada a quien prueba ese email). Aceptado (igual que `409` autenticado CU-CRED-03: el atacante anónimo que prueba emails recibe `403` vs `401` distinto... ¡oráculo!). Corrección vinculante: `POST /login` con cuenta `DELETION_REQUESTED` responde `401 INVALID_CREDENTIALS` OPACO (igual que mala), NO `403` (el `403 ACCOUNT_DELETED` solo aparece en endpoints autenticados/cancel donde el solicitante ya probó posesión, y en `cancel/start` opaco `202`). Documentado anti-oráculo.

## 6. Requerimientos de Observabilidad
* **Métrica:** `deletion_total{op="request|cancel_start|cancel_confirm|execute", result="ok|throttled|invalid|taken|error"}` + `deletion_pending_gauge` + `deletion_executed_total` + `retention_purged_total`.
* **Trazabilidad:** Raíces `UseCase.DeletionRequest/Cancel/Execute` (hijos: `stepup.check`, `db.deletion.*`, `cache.sweep`, `outbox.insert`). Atributos `effective_at`, nunca email (hash).
* **Auditoría:** `auth.audit.v1 {action:"deletion.request|cancel|execute", result, effective_at?, anon_id?, trace_id}` + eventos `deletion.requested|cancelled`, `user.erased` (key `user_id`). Sin PII post-hard (solo `anon_id`).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Request + corte + cancel vía link**
  * **Dado** ACTIVE con 2 sesiones + MFA, Step-Up fresco.
  * **Cuando** `POST /request {confirm_email:ok, accepted:true}` → `202` + `POST /login` (buena) + `cancel/start` + `cancel/confirm`.
  * **Entonces** request `202` + 0 sesiones + login `401` opaco (no `403`) + mail solicitud; cancel-link `confirm` → `ACTIVE` restaurado (MFA TOTP re-activo, backups quemados exigen regenerate) + login nueva? (misma password, sí `200`) + `cancelled` 1. Sin cancel en 30d → hard (esc. 3).
* **Escenario 2: Triple-fail + re-request + recordatorio**
  * **Dado** stale sin token / email tipado mal / ya solicitada / día 25.
  * **Cuando** request sin Step-Up, con email distinto, re-request, cron día 25.
  * **Entonces** sin Step-Up → `401`; email mal → `400` (0 cambios); re-request → `409` con `effective_at`; día 25 → 1 email recordatorio (si cancela después, no hard).
* **Escenario 3: Hard + downstream + re-registro**
  * **Dado** `DELETION_REQUESTED` con `effective_at` pasado, satélite mock suscrito, fiscal con 1 factura.
  * **Cuando** cron executor + re-registro mismo email + login viejo.
  * **Entonces** hard: PII destruida (email `deleted+id@invalid`, hash NULL), `ANONYMIZED` + `anon_id`, audit/consent anonimizados (chain intacta), `retention_ledger` 1 fila cifrada, `user.erased` 1 + satélite purga mock OK; re-registro mismo email → `201` nueva cuenta limpia (sin vínculo); login con credenciales viejas → `401`.
* **Escenario 4: Infra + federated-sub**
  * **Dado** PG-down / Redis-down / Kafka-down; cuenta federated-only.
  * **Cuando** request/cancel/executor.
  * **Entonces** PG-down → `500` 0 cambios; Redis-down → `202/200` vía PG + `WARN`; Kafka-down → `202/200` + outbox pendiente (erased reintentado 24h + DLQ); federated `sub` liberado tras hard (tercero puede linkearlo).
