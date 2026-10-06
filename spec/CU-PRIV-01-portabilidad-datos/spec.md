# Spec: CU-PRIV-01 - Descarga y Portabilidad de Datos Personales (Right of Access / Portability)

## 1. Contexto y Propósito
Entregar al dueño el paquete interoperable de su identidad (JSON + CSV sesiones) con Step-Up `privacy:export`, job async cifrado (AES-GCM efímera, clave server-side), descarga autenticada 24h multi-uso y autodestrucción, con frecuencia 1/30d. Sin secretos en el bundle (hashes/TOTP/tokens fuera).

Decisiones (2026-10-05, todas Recommended):
- Q1 Step-Up `privacy:export` (14º scope), Q2 Allowlist sin secretos, Q3 Auth-download 24h (clave nunca sale), Q4 1/30d (`429` + `next_available`), Q5 AES-GCM + purga 24h, Q6 3 rutas + tabla `exports`.

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado ACTIVE (Bearer + Step-Up `privacy:export`), Worker exportador, SMTP (aviso listo).
* **Precondiciones:**
  * Sin export `ready/processing` vigente <30d (si hay → `429 EXPORT_TOO_SOON {next_available}`; el anterior sigue descargable si no expiró).
  * Fuentes legibles (PG tablas + audit propio; si `DELETION_REQUESTED/ANONYMIZED` → `409/404` base, sin export).

## 3. Flujo Principal (Happy Path)
1. Usuario envía `POST /api/v1/auth/privacy/export` + Bearer + Step-Up (`privacy:export`) + `X-Request-ID`. Valida Guard (falla → `401`), rate-export (`1/30d` por user: `SELECT MAX(created) FROM exports` + `429` si reciente) + rate IP genérico.
2. Crea `exports(id UUIDv7, owner, status=processing, key_enc=AES-GCM-efímera(KEK env, AAD=user), exp=now+24h? No: exp se fija al TERMINAR (24h desde listo, no desde pedido — el job puede tardar; documentado))` + outbox (`export.requested` + audit) + encola job (no bloquea: `202 {export_id, status:processing}`).
3. Worker recolecta (read-only, `REPEATABLE READ` snapshot): `users(perfil+emails+roles+ver)`, `federated_identities(sub→masked? No: sub completo ES suyo — se incluye (es su dato); documentado)`, `sessions históricas (incluidas muertas 90d)`, `trusted_devices(labels)`, `consent_records`, `audit propio (masked igual `me`)`, `login_locations`, `mfa{enabled, backup_remaining}` (sin secreto/hash), `api_keys/m2m?` (prefijos, sin secretos), `password_history?` NO (hashes fuera). Serializa `export.json` (UTF-8, schema `privacy/v1` versionado) + `sessions.csv` (sid, device, ip_masked, created, last_seen).
4. Cifra `AES-256-GCM(key_efímera, AAD=user_id, bundle)` → guarda blob (`exports.blob_enc` BYTEA o volumen `exports/<id>.enc` + `key_enc` KEK-wrapped en PG; decisión: PG BYTEA si <10MB sino volumen — ambas con `key_enc` en PG; documentado) + `status=ready, ready_at, exp=ready+24h` + email `Tu descarga está lista (24h, descárgala aquí con sesión)` (link al front, NO al blob; sin adjunto).
5. Usuario descarga `GET /privacy/export/:id/download` + Bearer owner (otro user → `404` idéntico a inexistente, sin oráculo; expirado → `410 EXPORT_EXPIRED`) → descifra server-side (streaming, `Content-Type: application/zip`, `Content-Disposition: attachment`, `no-store`) + audit `export.downloaded` (cada descarga). Multi-descarga permitida en 24h.
6. A las 24h (o tras `DELETE /export/:id` voluntario): worker purga blob+key (`status=destroyed`, `audit export.destroyed`); pasada la ventana, `GET` → `410`.

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación/autorización:** sin Bearer/Step-Up → `401`; 2º pedido <30d → `429 EXPORT_TOO_SOON {next_available}` (aunque el anterior expiró ayer — la ventana es desde `created`, no desde `exp`); `:id` ajeno/inexistente → `404` idéntico; expirado → `410`.
* **4.2. Job falla:** fuente caída a mitad → `status=failed` + `GET /status → failed` + reintento manual (nuevo `POST`, pero respeta 30d? No: si falló por infra, no consume cuota — se permite reintento inmediato marcando el fallido `superseded`; documentado).
* **4.3. Infra:** PG down → `500`; KMS/KEK ausente → `500` fail-fast (sin export plano); storage lleno → `500` + `failed`; Kafka down → `202` + outbox pendiente (email puede tardar); SMTP down → `ready` igual (el `status` lo dice; email pendiente).
* **4.4. Tamaño:** bundle >100MB (audit enorme 2a) → pagina audit a últimos 10k eventos + nota `truncated:true` + link `audit/me` para resto (documentado; no OOM worker con `LIMIT` + streaming JSON).
* **4.5. Borrado en curso:** `DELETION_REQUESTED` → `409` (primero decide si se queda: cancela o espera hard — tras hard no hay nada que exportar); `ANONYMIZED` → `404`.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Step-Up mandatorio (`privacy:export`, 14º scope) en `POST`; descarga exige owner-Bearer (sin Step-Up de nuevo — la ventana 24h ya lo cubre; si la sesión muere, re-loguea normal, no Step-Up de nuevo).
* **RN-02:** Allowlist bundle (Q2) + schema `privacy/v1` (`version` en JSON; validador `privacy_schema.json` en CI). Denylist: hashes, secretos TOTP, backup hashes, tokens, `password_hash`, `secret_enc`, IPs completas (masked), `lat/lon` (ciudad si acaso).
* **RN-03:** 1/30d desde `created` (fallidos-infra no consumen). `next_available` en `429`.
* **RN-04:** Clave efímera 32B por export, `key_enc=KEK-wrap(AAD=user)` (`EXPORT_KEK` env/KMS; rotación KEK no re-cifra viejos — expiran en 24h de todos modos).
* **RN-05:** 24h desde `ready` (multi-descarga), purga total (blob+key) + `destroyed`; `DELETE` voluntario adelanta purga.
* **SEC-01:** Descarga autenticada (nunca URL pública firmada sin auth — el email solo notifica, no autoriza). `sub` federado incluido (es su dato) pero NUNCA `password_hash`/secretos.
* **SEC-02:** `exports.blob` solo descifrable con `key_enc` + KEK (ni siquiera DBA sin KEK lee; documentado).
* **SEC-03:** Rate `export:user 1/30d` + `export:ip 10/hora` (anti-cosecha masiva con sesiones robadas en bulk) + audit cada fase.

## 6. Requerimientos de Observabilidad
* **Métrica:** `export_total{op="request|ready|download|destroy", result}` + `export_build_duration_seconds` + `export_size_bytes` Histogram + `export_expired_total`.
* **Trazabilidad:** Raíces `UseCase.ExportRequest/Build/Download` (hijos: `stepup.check`, `db.collect (por fuente)`, `crypto.encrypt`, `storage.save`, `mail.notify`). Atributos `export_id, bytes`, nunca contenido.
* **Auditoría:** `auth.audit.v1 {action:"privacy.export_*", export_id, result, trace_id}` + eventos `export.requested|ready|downloaded|destroyed` (key `user_id`). Sin contenido (solo `bytes`).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Request → build → download → destroy**
  * **Dado** ACTIVE con sesiones/devices/consents/audit, Step-Up fresco, KEK ok.
  * **Cuando** `POST /export` → worker (mock rápido) → `GET /status` → `GET /download` (Bearer) → 24h después.
  * **Entonces** `202` + `status processing→ready` + email listo + `download` ZIP con `export.json` (schema válido, sin `password_hash/TOTP/tokens`, con `sub` propio) + `sessions.csv` + 2ª descarga OK + a las 24h `410` + blob/key purgados + `destroyed` 1. p95 build <60s (dataset medio).
* **Escenario 2: Frecuencia + ajeno + expirado**
  * **Dado** export hace 10d; otro user; export expirado ayer.
  * **Cuando** re-`POST`, `GET :id` ajeno, `GET` expirado.
  * **Entonces** re-`POST` → `429` con `next_available` (+20d); ajeno → `404` (idéntico inexistente); expirado → `410`. Fallido-infra → reintento inmediato permitido (no consume cuota).
* **Escenario 3: Step-Up + tamaño + KEK**
  * **Dado** stale sin token; audit 50k eventos; KEK ausente.
  * **Cuando** `POST` stale, build grande, request sin KEK.
  * **Entonces** stale → `401`; grande → `ready` con `audit_truncated:true` (10k) + resto vía `audit/me`; sin KEK → `500` fail-fast (0 plano). SMTP-down → `ready` + email pendiente (status lo dice).
