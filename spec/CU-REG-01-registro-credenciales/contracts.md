# Contratos de Integración: CU-REG-01

## 1. Contrato HTTP (API REST)

* **Ruta:** `POST /api/v1/auth/register`
* **Autenticación requerida:** Ninguna (endpoint público, rate-limitado). Rechaza `Authorization` presente con `400` (`AUTH_NOT_ALLOWED_ANONYMOUS_ONLY` si trae Bearer válido — opcional, por defecto se ignora).
* **Headers:**
  * `Content-Type: application/json` (obligatorio, único valor aceptado)
  * `X-Request-ID: string (UUIDv4)` (obligatorio; si ausente el servidor genera uno y lo devuelve en respuesta, pero para idempotencia estricta el cliente DEBE enviarlo)
  * `User-Agent: string` (opcional, se hashea)
* **Rate-limit:** 10 req/min/IP, 3 req/hora/email_hash. Excedido → `429` + `Retry-After` + `X-RateLimit-Remaining: 0`.
* **Límites:** Body máx 32KB → `413`. `Cache-Control: no-store` en todas las respuestas de este endpoint.

### Request Payload
```json
{
  "email": "Test@Example.com",
  "password": "Str0ng!Passw0rd-2026",
  "terms_accepted": true,
  "terms_version": "v2026.10",
  "privacy_version": "v2026.10"
}
```
Validaciones (resumen vinculante):
- `email`: string 5..254, trim + lowercase, regex `^[^\s@]+@[^\s@]+\.[^\s@]{2,}$`, IDN→punycode, sin control/null. Error → `details[].field="email"`.
- `password`: string 12..128 runas (bytes ≤512, NFKC), 1 mayús + 1 minús + 1 dígito + 1 símbolo, no 4+ repetidos, != local-part email, no en top-10k local ni HIBP (k-anonymity). Error → `field="password"`, `reason="TOO_SHORT|MISSING_CLASS|COMPROMISED|EQUALS_EMAIL"`.
- `terms_accepted`: debe ser `true`. `terms_version/privacy_version`: deben igualar versiones activas (`v2026.10`). Error → `field="terms_accepted"`.

### Respuestas

#### `201 Created` — Aceptado (éxito Y duplicado-shadow idénticos)
```json
{
  "success": true,
  "data": {
    "status": "pending_verification",
    "message": "Si el email es válido recibirás instrucciones para verificar tu cuenta."
  }
}
```
Headers: `Content-Type: application/json`, `X-Request-ID: <echo>`, `Cache-Control: no-store`. NOTA: nunca incluye `user_id`, `email`, `token`. El cliente no puede distinguir éxito de duplicado (por diseño anti-enumeración).

#### `400 Bad Request`
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "La solicitud contiene datos inválidos.",
    "details": [
      {"field": "email", "reason": "INVALID_FORMAT"},
      {"field": "password", "reason": "TOO_SHORT"}
    ]
  }
}
```
Otros `code`: `INVALID_JSON`, `UNSUPPORTED_MEDIA_TYPE`, `MISSING_REQUEST_ID` (si se configura estricto), `TERMS_NOT_ACCEPTED`.

#### `429 Too Many Requests`
```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMITED",
    "message": "Demasiadas solicitudes. Intenta de nuevo en unos segundos.",
    "details": []
  }
}
```
Header obligatorio `Retry-After: 37`.

#### `413 Payload Too Large` / `500 Internal Server Error`
```json
{
  "success": false,
  "error": {
    "code": "PAYLOAD_TOO_LARGE",
    "message": "Cuerpo demasiado grande.",
    "details": []
  }
}
```
```json
{
  "success": false,
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "No pudimos procesar tu solicitud.",
    "details": []
  }
}
```
`500` nunca incluye traza, SQL, ni `request_id` interno salvo `X-Request-ID` echo para soporte.

### Ejemplo cURL
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{"email":"Test@Example.com","password":"Str0ng!Passw0rd-2026","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}'
```

## 2. Eventos Asíncronos (Kafka)

Todos producidos vía outbox por `cmd/worker`, no en el request. `event_id` UUIDv7 único (idempotencia consumer por `event_id`). `occurred_at` RFC3339 UTC. Ningún evento contiene `password`, `password_hash`, token plano.

* **Tópico:** `auth.user.registered.v1`
* **Key:** `user_id` (UUID)
* **Payload:**
```json
{
  "event_id": "0193a2f0-...-7",
  "event_type": "user.registered",
  "occurred_at": "2026-10-05T12:00:00Z",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "payload": {
    "user_id": "0193a2ef-...",
    "email_hash": "sha256:9f2c...",
    "email_domain": "example.com",
    "status": "pending_verification",
    "terms_version": "v2026.10",
    "request_id": "550e8400-..."
  }
}
```

* **Tópico:** `auth.email.verification_requested.v1`
* **Key:** `user_id`
* **Payload:**
```json
{
  "event_id": "uuid",
  "event_type": "email.verification_requested",
  "occurred_at": "2026-10-05T12:00:00Z",
  "trace_id": "4bf92f...",
  "payload": {
    "user_id": "uuid",
    "email": "user@example.com",
    "verification_token_hash": "sha256:...",
    "expires_at": "2026-10-05T12:15:00Z",
    "attempts_allowed": 3
  }
}
```
NOTA: el `email` plano solo viaja aquí (canal interno hacia mailer). El token PLANO nunca viaja en Kafka; el mailer lo compone desde `verification_tokens` vía job interno o el worker incluye `magic_link_hash` firmado. Implementación elegida: worker resuelve token plano desde Postgres (acceso interno) y envía SMTP directamente, Kafka solo lleva el hash para trazabilidad.

* **Tópico (shadow-duplicado):** `auth.security.registration_attempted.v1`
* **Key:** `email_hash`
* **Payload:**
```json
{
  "event_id": "uuid",
  "event_type": "security.registration_attempted",
  "occurred_at": "2026-10-05T12:00:00Z",
  "payload": {
    "email_hash": "sha256:...",
    "email_domain": "example.com",
    "is_existing": true,
    "ip_hash": "sha256:.../24",
    "action": "notify_owner"
  }
}
```

* **Tópico (auditoría):** `auth.audit.v1`
* **Key:** `user_id` o `email_hash` si shadow
* **Payload:**
```json
{
  "event_id": "uuid",
  "event_type": "audit.user_register",
  "occurred_at": "2026-10-05T12:00:00Z",
  "payload": {
    "action": "user.register",
    "user_id": "uuid-or-null-if-shadow",
    "email_hash": "sha256:...",
    "result": "success|duplicate_shadow|validation_failed|rate_limited",
    "ip_hash": "sha256:...",
    "user_agent_hash": "sha256:...",
    "terms_version": "v2026.10",
    "trace_id": "4bf92f...",
    "request_id": "550e8400-..."
  }
}
```
Schemas registrados (Apicurio/Confluent) con compatibilidad BACKWARD. DLQ: `auth.dlq.v1` con headers `original-topic, retry-count, error`.
