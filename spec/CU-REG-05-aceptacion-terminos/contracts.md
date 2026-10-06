# Contratos de Integración: CU-REG-05

## 1. Contrato HTTP (API REST)

* **Ruta nueva (lectura):** `GET /api/v1/legal/active`
* **Autenticación requerida:** Ninguna. `X-Request-ID` opcional. Rate-limit `legal:ip` 60/min → `429 + Retry-After`.
* **Rutas endurecidas (sin cambio de path):** `POST /api/v1/auth/register`, `GET /api/v1/auth/federated/{provider}/authorize` (exigen terms).

### GET /legal/active — éxito
```json
{
  "success": true,
  "data": {
    "terms": { "version": "v2026.10", "url": "https://legal.example.com/terms/v2026.10", "content_hash": "sha256:<64hex>", "effective_from": "2026-10-01T00:00:00Z" },
    "privacy": { "version": "v2026.10", "url": "https://legal.example.com/privacy/v2026.10", "content_hash": "sha256:<64hex>", "effective_from": "2026-10-01T00:00:00Z" },
    "stale": false
  }
}
```
Headers: `Cache-Control: public, max-age=3600`. `stale:true` + `Warning: 110 stale-legal-cache` solo degradado (Redis/DB caídos con fallback env).

### POST /register — endurecido (mismos paths CU-REG-01)
```json
// request exige:
{ "email": "...", "password": "...", "terms_accepted": true, "terms_version": "v2026.10", "privacy_version": "v2026.10" }
```
Errores nuevos (además de los CU-REG-01):
```json
{ "success": false, "error": { "code": "TERMS_REQUIRED", "message": "Debes aceptar los términos y la política vigentes.", "details": [{"field": "terms_accepted", "reason": "REQUIRED"}] } } // 400
{
  "success": false, "error": {
    "code": "TERMS_OUTDATED", "message": "Aceptaste una versión desactualizada. Revisa la vigente.",
    "details": [{"field": "terms_version", "reason": "OUTDATED"}],
    "meta": { "active": { "terms": "v2026.10", "privacy": "v2026.10" } }
  }
} // 400
```
Federado: `GET /authorize?terms_accepted=true&terms_version=&privacy_version=` sin ellos → `400 TERMS_REQUIRED` (sin `302`, sin `state`).

## 2. Eventos Asíncronos (Kafka)

Vía outbox en la Tx de registro. Sin texto legal ni IP completa.

* **Tópico:** `auth.legal.v1` — **Key:** `user_id`
```json
{
  "event_id": "uuid", "event_type": "legal.consent_recorded",
  "occurred_at": "2026-10-05T12:00:00Z", "trace_id": "4bf92f...",
  "payload": {
    "user_id": "uuid",
    "consents": [
      {"doc_type": "terms", "version": "v2026.10"},
      {"doc_type": "privacy", "version": "v2026.10"}
    ],
    "source": "classic",
    "ip_hash": "sha256:.../24",
    "request_id": "550e8400-..."
  }
}
```
`source`: `classic|federated_google`.
* **Tópico:** `auth.audit.v1`
```json
{
  "event_id": "uuid", "event_type": "audit.legal_consent",
  "occurred_at": "2026-10-05T12:00:00Z",
  "payload": { "action": "legal.consent", "user_id": "uuid", "result": "recorded|rejected", "reason": "missing|outdated|null", "versions": {"terms": "v2026.10", "privacy": "v2026.10"}, "trace_id": "4bf92f..." }
}
```
Schemas BACKWARD, DLQ `auth.dlq.v1`.
