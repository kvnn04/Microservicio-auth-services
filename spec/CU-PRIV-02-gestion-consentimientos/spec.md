# Spec: CU-PRIV-02 - Gestión Granular de Consentimientos y Revocación de Finalidades

## 1. Contexto y Propósito
Dar el panel de privacidad: 6 finalidades (3 esenciales + 3 toggles) con historia inmutable (reuso ledger CU-REG-05), versión sellada por servidor y propagación a satélites. Cierra el Módulo 8 y el sistema completo (33/33): revocar lo opcional jamás rompe login; lo esencial solo sale vía borrado (SEC-05).

Decisiones (2026-10-05, todas Recommended):
- Q1 6 propósitos versionados (extiende `legal_versions`), Q2 Opcional libre / esencial `400 ESSENTIAL_CONSENT` → borrado, Q3 Append-only + historial, Q4 `consent.changed.v1` fire-and-forget, Q5 Auth simple (sin Step-Up) + rate, Q6 Server-stamped, Q7 Ledger extendido + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado ACTIVE (Bearer válido, cualquier edad — toggle reversible de bajo riesgo, sin Step-Up), Satélites (suspenden al recibir evento).
* **Precondiciones:**
  * Cuenta con consentimientos base (registro los creó para terms/privacy; operational se otorga implícito al registrar con `granted` + audit `implied`; los 3 opcionales nacen `revoked` por defecto (opt-in, no opt-out) salvo que el registro los haya pedido explícitos (checkboxes no pre-marcados → si marcó, nacen `granted`).
  * Catálogo `purposes` con 1 texto activo por propósito.

## 3. Flujo Principal (Happy Path)
1. Usuario abre panel: `GET /api/v1/auth/privacy/consents` + Bearer → `200 {consents:[{purpose, essential, status:granted|revoked, version, updated_at, text_url}], history_url}` (estado = última fila por propósito; esenciales con `revocable:false`).
2. Toglea: `PUT /api/v1/auth/privacy/consents/:purpose {status:granted|revoked}` + Bearer (mismo estado actual → `200` idempotente `already`, sin fila nueva? No: idempotente sin duplicar — si ya está así, no inserta (evita spam historia); documentado).
3. El back valida: `purpose` conocido (si no → `404 UNKNOWN_PURPOSE`), `status` válido, rate `consents:user 30/min` (excede → `429`).
4. Si esencial y `status=revoked` → `400 ESSENTIAL_CONSENT {message:"Para retirar esto elimina tu cuenta.", deletion_url:"/account/deletion/request"}` (0 filas, 0 eventos). Si opcional (o esencial→`granted` re-confirmando) → en Tx: `INSERT consent_records(user, purpose, version=activa-vigente, status, at=now, ip_hash, source=panel)` + outbox (`consent.changed` + audit) → `200 {purpose, status, version}`.
5. Worker publica `consent.changed.v1 {user_id, purpose, status, version}` (satélites suspenden/reanudan YA; sin ACK) + email? No (toggle propio no avisa; solo audit + métrica. Si revoca `security_profiling`, email informativo `Perderás detección de viajes/dispositivos` — único aviso, documentado).
6. Efecto: revocar `marketing`/`analytics` no toca sesiones/login/core (verificado: ningún guard los consulta salvo el procesador correspondiente vía evento); revocar `security_profiling` desactiva travel/device para ese user (los guards hacen skip `profiling_off` + audit — documentado gancho).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación/autorización:** sin Bearer → `401`; `purpose` desconocido → `404`; `status` inválido → `400`; body >2KB → `413`.
* **4.2. Esencial:** `400 ESSENTIAL_CONSENT` (nunca `200` parcial). No genera fila ni evento.
* **4.3. Infra:** PG down → `500` (sin cambio); Redis (sin estado aquí salvo rate) down → fail-open rate + `WARN`; Kafka down → `200` + outbox pendiente (satélites aplican al recuperar; ventana documentada ≤ lag).
* **4.4. Versión nueva publicada:** togglear tras publicar `marketing v2026.11` sella `v2026.11` (el panel la muestra antes de pedir toggle — el front re-fetchea `GET` si el `PUT`... no hay mismatch posible (server-stamped); el historial muestra versiones mixtas (trazable qué texto aceptó cada vez).
* **4.5. Borrado:** `DELETION_REQUESTED/ANONYMIZED` → `409/404` base (consentimientos mueren con la cuenta; el ledger anonimizado queda como prueba).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Catálogo: `terms, privacy, operational_email` (esenciales, `revocable:false`) + `analytics, marketing, security_profiling` (opcionales, default `revoked` salvo opt-in explícito en registro).
* **RN-02:** Opcional revocado jamás bloquea login/sesiones/core (ningún guard de auth/registro/sesión lee opcionales; solo sus procesadores).
* **RN-03:** Append-only (reuso `consent_records` + `UNIQUE(user,purpose,version,status,at)`? No unique que bloquee re-toggle rápido: sin constraint temporal, solo `INDEX(user,purpose,at)`; idempotencia mismo-estado no inserta (lógica, no constraint)).
* **RN-04:** Server-stamped (versión = activa al momento; el front no la envía).
* **RN-05:** Mismo-estado → `200 already` sin fila/evento (no spam).
* **SEC-01:** Sin Step-Up justificado (reversible, propio, auditado; un secuestrador de sesión podría revocar marketing — impacto nulo en seguridad; esencial protegido por `400`).
* **SEC-02:** Sin PII en eventos (solo `purpose/status/version`; el `user_id` es la key necesaria para que el satélite ubique a quién suspender — base legítima, documentado).

## 6. Requerimientos de Observabilidad
* **Métrica:** `consent_changes_total{purpose, status}` + `consent_essential_blocked_total` + `consent_sat_lag_seconds` (cambio→aplicado satélite, muestreado).
* **Trazabilidad:** Raíces `UseCase.ConsentGet/Set` (hijos: `db.consent.*`, `outbox.insert`). Atributos `purpose, status`.
* **Auditoría:** `auth.audit.v1 {action:"consent.set", purpose, status, version, trace_id}` + eventos `consent.changed.v1` (key `user_id`). Sin texto legal (solo `version+url`).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Toggle opcional + historial + satélite**
  * **Dado** `marketing=revoked`, satélite mock suscrito.
  * **Cuando** `PUT /marketing {granted}` → `GET /consents` + `PUT {revoked}`.
  * **Entonces** `200` ×2 con versiones selladas + historial 3 filas (`revoked→granted→revoked`) + satélite recibe 2 eventos (`granted` reanuda, `revoked` suspende) + login/sesiones intactos en todo momento + `changes_total` +2.
* **Escenario 2: Esencial bloqueado + idempotente**
  * **Dado** `terms=granted`.
  * **Cuando** `PUT /terms {revoked}` + `PUT /marketing {revoked}` (ya revoked) + `PUT /noexiste {granted}`.
  * **Entonces** terms → `400 ESSENTIAL_CONSENT` + link borrado (0 filas); marketing-igual → `200 already` (0 filas); noexiste → `404`. Ninguno toca login.
* **Escenario 3: security_profiling off + Kafka-down**
  * **Dado** travel/device activos, `profiling=granted`.
  * **Cuando** `PUT /security_profiling {revoked}` + login salto-imposible + Kafka-down toggle.
  * **Entonces** travel/device hacen skip (`profiling_off` audit) sin forzar MFA (solo alerta leve? No: sin profiling no hay geo que evaluar → `skipped_optout`, sin email travel) + email informativo 1 vez; Kafka-down → `200` + evento pendiente (satélite aplica al recuperar).
