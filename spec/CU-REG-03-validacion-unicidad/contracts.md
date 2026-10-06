# Contratos de Integración: CU-REG-03

## 1. Contrato HTTP (API REST)

> **Sin endpoint nuevo (decisión Q1).** Este CU es transversal: endurece `POST /api/v1/auth/register` (CU-REG-01) y `POST /api/v1/auth/resend-verification` (CU-REG-02). Se prohíbe expresamente `GET /check-email`, `POST /check-email`, `HEAD`, o campos `available/exists/taken`.

* **Rutas afectadas (reuso, sin cambios de path):** `POST /api/v1/auth/register`, `POST /api/v1/auth/resend-verification`.
* **Autenticación requerida:** Ninguna. `X-Request-ID` obligatorio (idempotencia).
* **Garantía contractual:** para un `email` con formato válido, la respuesta es byte-idéntica (salvo `X-Request-ID` echo) exista o no la cuenta:
  * register → siempre `201 {success:true, data:{status:"pending_verification", message:"Si el email es válido recibirás instrucciones..."}}` (nunca `user_id/email`, nunca `409`).
  * resend → siempre `202 {success:true, data:{status:"if_exists_verification_sent"}}` (nunca distingue).
* **Diferencias permitidas únicamente:** `400 VALIDATION_FAILED` (formato inválido, sin SELECT), `429 RATE_LIMITED + Retry-After` (cuota), `413`, `500 INTERNAL_ERROR` (infra). Ninguno revela existencia (mismo body para unique/shadow en esos casos también).

### Ejemplo indistinguible
```bash
# nuevo -> 201 genérico + crea PENDING (interno)
curl -X POST http://localhost:8080/api/v1/auth/register -H "Content-Type: application/json" -H "X-Request-ID: <uuid1>" -d '{"email":"nuevo@example.com","password":"Str0ng!Passw0rd-2026","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}'
# existente -> 201 genérico idéntico + 0 filas + notify async (interno)
curl -X POST http://localhost:8080/api/v1/auth/register -H "Content-Type: application/json" -H "X-Request-ID: <uuid2>" -d '{"email":"Existe@Example.com","password":"Otra!Valida-2026","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}'
```
Test contrato: `diff <(jq -S . unique.json) <(jq -S . shadow.json)` vacío (tras normalizar `requestId` si se echa en body; por defecto no va en body).

## 2. Eventos Asíncronos (Kafka)

Vía outbox/worker, nunca en request. Sin `password/hash/token` plano. Email plano solo hacia mailer.

* **Tópico:** `auth.security.registration_attempted.v1` — **Key:** `email_hash` (sha256hex)
```json
{
  "event_id": "uuid",
  "event_type": "security.registration_attempted",
  "occurred_at": "2026-10-05T12:00:00Z",
  "trace_id": "4bf92f...",
  "payload": {
    "email_hash": "sha256:...",
    "email_domain": "example.com",
    "user_id": "uuid-existente",
    "user_status": "ACTIVE",
    "ip_hash": "sha256:.../24",
    "is_existing": true,
    "action": "notify_owner",
    "request_id": "550e8400-..."
  }
}
```
Throttling (1/hora + 3/día por `email_hash` en Redis) se aplica ANTES de publicar al tópico SMTP; el evento audit se publica siempre (incluso throttled, con `notified:false`).

* **Tópico:** `auth.audit.v1` — **Key:** `email_hash`
```json
{
  "event_id": "uuid",
  "event_type": "audit.uniqueness_probe",
  "occurred_at": "2026-10-05T12:00:00Z",
  "payload": {
    "action": "uniqueness.probe",
    "email_hash": "sha256:...",
    "user_id": "uuid-or-null",
    "found": true,
    "result": "shadow_duplicate",
    "notified": true,
    "throttled": false,
    "ip_hash": "sha256:...",
    "trace_id": "4bf92f...",
    "request_id": "550e8400-..."
  }
}
```
`result`: `unique|shadow_duplicate|throttled_notify|error`. Schemas BACKWARD, DLQ `auth.dlq.v1`.
