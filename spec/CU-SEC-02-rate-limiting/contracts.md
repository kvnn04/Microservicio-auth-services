# Contratos de Integración: CU-SEC-02

## 1. Contrato HTTP (API REST)

> **Transversal (sin rutas nuevas).** Aplica a todo salvo `GET /healthz`, `GET /metrics`. Headers en TODAS (200 y 429); `429` uniforme.

* **Headers éxito:** `RateLimit-Limit: 10`, `RateLimit-Remaining: 7`, `RateLimit-Reset: 42` (segundos al reset de ventana).
* **429:**
```json
{ "success": false, "error": { "code": "RATE_LIMITED", "message": "Demasiadas solicitudes. Intenta de nuevo.", "details": [] } }
```
Headers: mismos `RateLimit-*` (`Remaining: 0`) + `Retry-After: 37` (segundos). `Cache-Control: no-store`.

### Matriz resumida (vinculante, ver spec §4.1)
Sensible 10/min-IP (register/login/reset/pless/federated-authz), verify/mfa/step-up 5-20/min, lecturas 60-100/min, logout/refresh 10-30/min, globales 5/hora, progresivo 50×429→block 15min. Cambios solo enmendando la tabla (con `config_version` en `/metrics`).

## 2. Eventos Asíncronos (Kafka)

Sin eventos por cada `429` a tasa total (muestreo 10% flood). Siempre: `rate.ip_blocked`.

* **Tópico:** `auth.audit.v1` — `{action:"rate.limited", route, scope, ip_hash, trace_id}` (10% flood) + `{action:"rate.ip_blocked", ip_hash, trace_id}` (100%). Schemas BACKWARD, DLQ `auth.dlq.v1`. Sin SMTP (el 429 es informativo, no incidente).
