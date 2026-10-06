# Spec: CU-REG-05 - Aceptación de Términos y Políticas

## 1. Contexto y Propósito
Hacer auditable y bloqueante el consentimiento legal del registro. Sin `terms_accepted=true` con versiones vigentes no existe cuenta, token ni evento de negocio. Formaliza lo que CU-REG-01/04 ya pedían como campos sueltos: catálogo versionado (`legal_versions`), ledger inmutable (`consent_records`) y endpoint público de lectura para que el front muestre textos correctos. Base GDPR para CU-PRIV-02 (granular) y CU-SEC-04 (auditoría).

Decisiones (2026-10-05, todas Recommended):
- Q1 Transversal + `GET /legal/active` (sin POST standalone), Q2 `terms+privacy` `vYYYY.MM` 1 activa/tipo + match exacto, Q3 Append-only estricto `UNIQUE(user,doc,version)`, Q4 Bloqueo `400 TERMS_REQUIRED/OUTDATED` sin side-effects, Q5 Fail-closed registro + cache Redis 1h, Q6 `shared/legal` VOs+puertos antes de Probe, Q7 Métricas + evento + alerta front desactualizado.

## 2. Actores y Precondiciones
* **Actores:** Usuario Anónimo (registro clásico/federado), Front (consulta versiones), Microservicio Auth, Worker (eventos).
* **Precondiciones:**
  * `legal_versions` con exactamente 1 fila `is_active=true` por `doc_type ∈ {terms, privacy}` (seed `v2026.10` con `content_hash`, `url`, `effective_from` UTC).
  * Front obtiene vigentes vía `GET /api/v1/legal/active` (cacheable 1h) y los muestra íntegros + checkbox afirmativo no pre-marcado (prohibido opt-out implícito).
  * Redis con `legal:active` (1h) para lectura; registro clásico/federado exige validación contra DB (no solo cache).

## 3. Flujo Principal (Happy Path)
1. Front llama `GET /api/v1/legal/active` → `{terms:{version, url, content_hash, effective_from}, privacy:{...}}` (`Cache-Control: public, max-age=3600`). Usuario lee y marca `terms_accepted=true` explícito.
2. Usuario envía `POST /register {email, password, terms_accepted:true, terms_version:<vigente>, privacy_version:<vigente>}` o `GET /federated/google/authorize?terms_accepted=true&terms_version=&privacy_version=` (federado: el front pasa los 3 como query validados por back antes del 302; si faltan → `400 TERMS_REQUIRED` sin crear `state`).
3. El back (antes de unicidad/hash/outbox — falla rápido) ejecuta `Legal.CheckConsent`:
   a. Exige `terms_accepted==true` (bool estricto; `"true"`, `1`, ausente → `400 TERMS_REQUIRED`).
   b. Exige `terms_version` y `privacy_version` con formato `^v\d{4}\.\d{2}$` y match EXACTO con activas DB (`GetActive` con cache Redis + fallback DB; mismatch → `400 TERMS_OUTDATED` con `details` + `meta.active:{terms,privacy}` para que el front se auto-actualice).
   c. Calcula `ip_hash=sha256(ip/24)`, `ua_hash=sha256(UA-familia)`, `request_id`.
4. Continúa registro normal (unicidad → hash → Tx `users + federated? + outbox negocio`). Dentro de la MISMA Tx inserta 2 filas `consent_records` (una por `doc_type`, `id UUIDv7`, `accepted_at=now UTC`, `source=classic|federated_google`, `request_id`) con `ON CONFLICT(user_id,doc_type,version) DO NOTHING` (idempotencia replay mismo RequestID no duplica).
5. Retorna `201/302` normal del CU origen. Outbox añade `legal.consent_recorded.v1` (1 evento por doc_type o 1 agregado con ambos — decisión vinculante: 1 evento `legal.consent_recorded` con array `consents:[{doc,version}]`) + audit. Sin consentimiento no hay `user.registered` ni sesión.
6. Lecturas posteriores (perfil/auditoría, futuros CUs) consultan `consent_records` como verdad; `users.terms_version` queda como denormalización de conveniencia (no autoridad).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * `terms_accepted=false/ausente/no-bool`, `terms_version/privacy_version` ausentes/malformato (no `vYYYY.MM`), `Content-Type` inválido → `400 TERMS_REQUIRED` o `VALIDATION_FAILED` con `details[].field=terms_accepted|terms_version|privacy_version`. Sin SELECT unicidad, sin hash dummy, sin outbox, p95 <30ms. Federado sin query terms → `400 TERMS_REQUIRED` antes del 302 (sin `state` en Redis).
* **4.2. Conflicto o unicidad (versión desactualizada):**
  * `terms_version=v2026.09` cuando activa es `v2026.10` (front cacheado, race publicación) → `400 TERMS_OUTDATED {details:[{field:terms_version,reason:OUTDATED}], meta:{active:{terms:v2026.10, privacy:v2026.10}}}`. No revela existencia cuenta (falla antes de Probe, idéntico exista o no). Front debe re-fetchear `GET /legal/active` y re-pedir checkbox (el usuario debe re-confirmar explícitamente la nueva versión, prohibido auto-reenviar mismo `accepted=true` sin mostrar diff). Métrica `consent_outdated_total` + alerta si `>10%/h` (front/CDN desactualizado).
* **4.3. Falla de servicio externo o infraestructura:**
  * Postgres `legal_versions/consent_records` down/timeout → `500 INTERNAL_ERROR` fail-closed (sin crear cuenta, sin outbox parcial; la Tx completa revierte). `GET /legal/active` tolera: Redis cache 1h → si hit sirve stale con `Warning: stale-legal-cache` + métrica; si miss sirve `LEGAL_FALLBACK_VERSIONS` env (solo lectura, con `stale:true`); register NUNCA usa fallback (exige DB).
  * Redis down → `GET` va a DB directo; register valida contra DB directo (sin cache) + `WARN`; throttle notify (CU-REG-03) en fail-open pero consentimiento sigue fail-closed (distinción documentada).
  * Kafka down → no afecta `201` (outbox `consent_recorded` pendiente igual que negocio, mismo backoff/DLQ).
* **4.4. Rate-limit:** `GET /legal/active` 60/min/IP (lectura barata, cacheada) → `429` genérico. `POST /register` con consentimiento inválido repetido cuenta para `register:ip` normal (no bucket aparte; evita oráculo de versiones por timing ya que falla pre-Probe siempre igual).
* **4.5. Publicación de nueva versión (edge operativo):**
  * Publicar `v2026.11` = `INSERT legal_versions + UPDATE activa` en Tx admin (fuera de este CU, vía migración/endpoint admin futuro). Cuentas existentes NO se invalidan (siguen ACTIVE; el re-consentimiento de nuevas versiones es CU-PRIV-02, no este). Solo registros NUEVOS exigen la nueva. `GET` refleja el cambio en <1h (purga `legal:active` en la Tx de publicación).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Documentos MVP: `terms`, `privacy` (exactos, lowercase). `cookies/marketing` vetados aquí (CU-PRIV-02). 1 activa por tipo (`UNIQUE(doc_type) WHERE is_active`).
* **RN-02:** Formato `^v\d{4}\.\d{2}$`. `effective_from` UTC pasado para ser activa. `content_hash=sha256(canónico)` + `url` inmutable por versión (si cambia el texto → nueva versión, nunca UPDATE del texto).
* **RN-03:** Ledger `consent_records`: `PK id`, `UNIQUE(user_id,doc_type,version)`, columnas `user_id FK, doc_type, version, accepted_at, ip_hash, ua_hash, source, request_id`. Sin `UPDATE/DELETE` (revoke por app: la API rechaza `UPDATE/DELETE` a nivel GRANT DB `REVOKE UPDATE,DELETE`; solo `INSERT+SELECT`). Retención indefinida (base legal GDPR art. 7).
* **RN-04:** `terms_accepted` debe ser afirmativo explícito por registro (checkbox no pre-marcado, sin inferencia por uso). Cada `user_id` necesita sus 2 filas (aunque mismo `request_id` federado las cree juntas).
* **RN-05:** Federado: `terms_source=federated_google` + mismas versiones exactas; el `authorize` sin terms → `400` antes de `state` (no regala `302` sin consentimiento).
* **SEC-01:** Sin PII en errores más allá de lo enviado (el `400 OUTDATED` incluye solo versiones públicas vigentes, nunca email/estado). `ip` solo `/24` + hash en ledger/logs.
* **SEC-02:** Anti-tampering: `content_hash` permite al auditor verificar que el usuario aceptó el texto exacto servido (front puede mostrar `hash` junto al texto). Publicación de versión exige `content_hash` del artefacto (mismatch → rechaza seed).
* **SEC-03:** Idempotencia: replay mismo `X-Request-ID` no duplica ledger (`ON CONFLICT DO NOTHING` + `IdempotencyStore`), versiones distintas con mismo RequestID → `400` (no mezcla).

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** `consent_recorded_total{doc_type="terms|privacy", source="classic|federated_google"}` + `consent_rejected_total{reason="missing|outdated|invalid_format"}` + `consent_outdated_total{doc_type}` + gauge `legal_active_version_info{doc_type, version}` (=1). Alerta `rate(outdated[1h])/rate(total[1h])>0.10` (front desactualizado) + dashboard versiones activas.
* **Trazabilidad:** Span hijo `Legal.CheckConsent` de `UseCase.RegisterUser/RegisterFederated` (hijos `legal.versions.fetch (cache_hit|db|fallback)`, `legal.validate`, `db.consent.insert` en Tx negocio). Atributos `terms.version, privacy.version` (públicos, no PII).
* **Auditoría:** Evento `legal.consent_recorded.v1 {user_id, consents:[{doc,version}], source, ip_hash, request_id, trace_id}` a `auth.legal.v1` + `auth.audit.v1 {action:legal.consent, result:recorded|rejected, reason?}`. Sin texto legal en evento (solo `version+hash+url`).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Registro con vigentes → ledger + negocio**
  * **Dado** activas `terms=v2026.10, privacy=v2026.10`.
  * **Cuando** `POST /register {terms_accepted:true, terms_version:v2026.10, privacy_version:v2026.10}` válido.
  * **Entonces** `201` + `users` PENDING + 2 filas `consent_records` (misma Tx) + outbox `consent_recorded` + `consent_recorded_total` +2 (por doc). Sin checkbox no hay nada.
* **Escenario 2: Versión vieja → 400 con activas + alerta**
  * **Dado** activas `v2026.10` y payload con `terms_version=v2026.09`.
  * **Cuando** `POST /register`.
  * **Entonces** `400 TERMS_OUTDATED` con `meta.active` correctas, 0 filas `users/consent/outbox`, `consent_rejected_total{outdated}` +1. Repetido >10%/h dispara alerta.
* **Escenario 3: Federado sin terms → 400 antes de 302**
  * **Dado** `GET /federated/google/authorize` sin `terms_accepted/versions`.
  * **Cuando** se invoca.
  * **Entonces** `400 TERMS_REQUIRED`, 0 `state` en Redis, 0 `302`. Con terms vigentes → `302` + ledger al callback (source=federated_google).
* **Escenario 4: DB legal caída → fail-closed registro, GET degradado**
  * **Dado** Postgres legal down (mock), Redis con `legal:active` vigente.
  * **Cuando** `GET /legal/active` y `POST /register` vigente.
  * **Entonces** `GET` → `200` stale (cache/env + `stale:true`, métrica) y `POST` → `500 INTERNAL_ERROR` sin crear nada (fail-closed), sin `201` huérfano sin ledger.
