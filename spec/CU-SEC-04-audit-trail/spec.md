# Spec: CU-SEC-04 - Trazabilidad y Logs de Auditoría Inmutables (Audit Trail)

## 1. Contexto y Propósito
Unificar lo que todos los CUs ya emiten (`auth.audit.v1` + outbox) en un ledger consultable, encadenado y sanitizado: envelope único con hash-chain mensual, dual bus (Kafka 1 año) + PG append-only particionado (verdad, 2 años), default-deny PII con scanner CI, y lectura propia paginada (`GET /audit/me`) para transparencia OVERVIEW. Sin este CU, la auditoría es un archipiélago de eventos dispares.

Decisiones (2026-10-05, todas Recommended):
- Q1 Envelope + hash-chain por mes, Q2 Dual Kafka-1año + PG-2años (REVOKE U/D), Q3 Default-deny + scanner CI, Q4 `GET /audit/me` paginado masked (sin bulk admin), Q5 Retención 2a + particiones + nightly chain-verify + no-borrable (salvo anonimización SEC-05), Q6 Triple tiempo+ids (occurred/received + trace/request + UUIDv7, NTP), Q7 Append-en-Tx + QueryMe + Sanitizer + métricas (drop siempre 0).

## 2. Actores y Precondiciones
* **Actores:** Microservicio Auth (emisor en cada Tx negocio), Worker/Kafka (bus), Subsistema Auditoría (PG + nightly verify), Usuario (lector propio), NTP.
* **Precondiciones:**
  * Relojes NTP (skew >1s → `WARN` + métrica, no bloqueo).
  * `audit_log` particionado vigente (worker crea partición mes+1 el día 25) + `prev_hash` del último evento del mes anterior sellado.

## 3. Flujo Principal (Happy Path)
1. Cada caso de uso, DENTRO de su Tx negocio, construye `AuditEvent{event_id UUIDv7, occurred_at=clock_timestamp() UTC, actor{user_id?, device_hash}, action (p. ej. `user.register`, `login.attempt`, `session.rotate`), result, trace_id, request_id, data (tipado, ya sanitizado por el llamador)}` y lo valida con `Sanitizer` (denylist §5; si viola → el servicio NO commitea con PII: falla cerrado `ErrAuditUnsafe` → `500` + `audit_unsafe_total` + P1 en dev; en prod bloquea el deploy vía scanner CI, no runtime).
2. Calcula `prev_hash` (último `hash` del mes: `SELECT hash ORDER BY occurred_at DESC, event_id DESC LIMIT 1 FOR UPDATE` en la Tx si el llamador pide chain estricto, o `last_hash` cache Redis `audit:chain:<yyyy-mm>` + reconcilia; decisión: PG `FOR UPDATE` en la Tx del llamador solo para acciones críticas (register/login/password/session); para alta-frecuencia (rate/limited, travel-normal) chain eventual por worker (rellena `prev/hash` async en 60s). Documentado dual estricto/eventual).
3. `hash = hex(sha256(prev_hash + canonical_json(event_sin_hash)))` + `INSERT audit_log (...)` en la MISMA Tx negocio (si la Tx revierte, el audit revierte — atomicidad) + `INSERT outbox(auth.audit.v1)` mismo Tx (el worker lo publica a Kafka con `received_at` broker).
4. Worker drena outbox → Kafka `auth.audit.v1` (retención 1a, `cleanup.policy=delete`, sin compactar) + marca `sent`. Consumidores satélites archivan a su data-lake (fuera de alcance).
5. Lectura propia: `GET /api/v1/auth/audit/me?cursor=<occurred_at,id>&limit=20` (Bearer, sin Step-Up — lectura propia no sensible más allá de auth; rate 60/min) → `200 {events:[masked...], next_cursor}` (masked = mismo envelope menos `device_hash` completo? No: `device_hash` parcial 8ch + `ip` nunca + `data` ya sanitizada en origen; el endpoint NO re-sanitiza salvo truncar `data` a allowlist de lectura propia).
6. Nightly `audit-verify` job (cron worker 03:00 UTC): recorre mes en curso + anterior verificando `hash[i]==sha256(prev+body)` y huecos `event_id` (UUIDv7 desorden tolerado ±5min por outbox; hueco real = `audit_chain_break_total` + P1 + `audit_gap` evento). Purga particiones >2a (worker mensual día 1, `DROP PARTITION` + `audit_purged_total`, con excepción legal-hold flag).

## 4. Flujos Alternativos y Excepciones
* **4.1. Sanitizer viola:** `ErrAuditUnsafe` → `500` + no-Tx (fail-closed; en CI el scanner ya lo habría parado — runtime es red de seguridad). Contador `audit_unsafe_total` (siempre 0 en prod sano; >0 = P1 deploy).
* **4.2. Kafka down:** outbox pendiente (nunca drop: `audit_dropped_total` existe pero su SLO es `==0` siempre; si >0 → P1). Lectura `me` sigue (PG verdad). Orden bus puede diferir (UUIDv7 + `occurred_at` permiten reordenar; `prev_hash` eventual del worker lo cose en orden de inserción PG, no de llegada Kafka — documentado).
* **4.3. PG audit down:** la Tx negocio que lo incluye falla → `500` del flujo (fail-closed: sin audit no hay mutación — decisión fuerte documentada; alternativa fire-forget vetada en Q7). Lecturas `me` → `500` (no `200 []` falso).
* **4.4. Partición ausente / chain roto:** partición mes no creada → worker la crea bajo demanda (`CREATE TABLE IF NOT EXISTS` + `WARN`); chain-break → P1 + congela purga (no se purga nada hasta resolver) + audit `chain_break`.
* **4.5. SEC-05 (olvido):** el audit NO se borra con la cuenta (interés legítimo); se anonimiza (`user_id → anon:<hash>` + `device_hash → null`, conserva `action/result/timestamps/hash` para que la chain no rompa — la anonimización RE-hashea el evento? No: rompería chain. Decisión: se añade evento `privacy.anonymized` que apunta, sin reescribir historia (los viejos quedan con `user_id` seudonimizado vía vista `audit_log_public` que enmascara, no UPDATE físico — documentado en SEC-05, aquí se deja gancho `anonymize_view`)).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Envelope único (Q1) para TODO audit (los CUs previos migran sus `auth.audit.v1` a este envelope sin cambiar `action/result` — compat BACKWARD con campo `v:2`).
* **RN-02:** Append-only (`REVOKE UPDATE,DELETE ON audit_log* FROM app_role`; solo `INSERT+SELECT`; particiones mensuales `audit_log_yyyy_mm` con `CHECK` + `DEFAULT`).
* **RN-03:** Denylist PII (Q3): `password, password_hash, access_token, refresh_token, id_token, mfa_token, step_up_token, totp_code, backup_code, otp, verification_token, client_secret, secret_enc, email (plano), ip (completa), lat, lon` — scanner CI (`scripts/audit_pii_scan.sh`) falla si algún ejemplo de contracts o test contiene patrón (`password.{0,20}:\s*"[^"]{3,}"` etc., allowlist explícita por `action` en `audit_allowlist.yaml`).
* **RN-04:** Lectura propia paginada (`cursor=(occurred_at,event_id)`, `limit 1..100 default 20`, solo `user_id==sub`, masked). Sin bulk/admin/export MVP.
* **RN-05:** Retención 2a (731d) + chain-verify nightly + purga mensual con legal-hold (si `legal_hold=true` en partición, no se purga).
* **SEC-01:** `prev/hash` SHA-256 hex (no HMAC — integridad, no autenticidad; la autenticidad la da append-only + GRANTs + firma del job verify con clave auditoría en el reporte, documentado).
* **SEC-02:** `trace_id/request_id` obligatorios (si el llamador no trae, se generan; nunca vacíos).
* **SEC-03:** Sin `UPDATE` ni siquiera para anonimizar (vista de lectura enmascara; la fila cruda queda con acceso `auditor_role` únicamente).

## 6. Requerimientos de Observabilidad
* **Métrica:** `audit_appended_total{action}` + `audit_lag_seconds` (occurred→Kafka-sent, p95<30s) + `audit_dropped_total` (SLO 0) + `audit_chain_break_total` + `audit_unsafe_total` (SLO 0) + `audit_verify_duration_seconds`.
* **Trazabilidad:** Cada evento lleva `trace_id` del request que lo causó (hijo lógico, no span nuevo) + el job verify crea span `Audit.VerifyChain` nightly.
* **Auditoría (meta):** El propio job emite `audit.chain_verified{month, events, ok}` (audit del audit).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Tx atómica + chain + lectura**
  * **Dado** login OK con audit en Tx.
  * **Cuando** `POST /login` → `200` + `GET /audit/me`.
  * **Entonces** PG tiene `audit_log(login.attempt)` con `prev/hash` válidos (`verify(hash)==true`), outbox→Kafka <30s p95 (`audit_lag`), `me` lo lista masked (sin PII denylisted) con cursor. Kill Kafka antes → `200` igual + pendiente (drop 0).
* **Escenario 2: Scanner bloquea PII + unsafe runtime**
  * **Dado** contracts-ejemplo con `"password":"x"` en evento (inyectado en CI) y servicio que intenta `Append{data:{token:...}}`.
  * **Cuando** CI scanner + request runtime.
  * **Entonces** CI falla (no merge) y runtime da `500` + `audit_unsafe_total` +1 (sin commitear negocio con PII).
* **Escenario 3: Chain-break + purga con hold**
  * **Dado** fila manipulada (`UPDATE` como superuser en test, simulando atacante DB) + partición de hace 3a con `legal_hold=true`.
  * **Cuando** nightly verify + purga mensual.
  * **Entonces** verify → `chain_break` P1 + purga congelada (nada se purga con break abierto); hold → partición vieja conservada, resto >2a purgado (`audit_purged_total`).
* **Escenario 4: PG-audit down + paginación**
  * **Dado** PG audit down; 50 eventos propios.
  * **Cuando** mutación + `GET /me?limit=20` ×3 páginas.
  * **Entonces** mutación → `500` (fail-closed, 0 negocio sin audit); con PG OK, 3 páginas `20/20/10` con `next_cursor` estable (sin duplicados aunque haya inserts concurrentes — cursor `(occurred_at,id)`).
