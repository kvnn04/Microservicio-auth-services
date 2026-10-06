# Contratos de Integración: CU-SEC-03

## 1. Contrato HTTP (API REST)

> **Sin rutas ni campos nuevos.** Transversal pre-Issue en `POST /login`, `POST /passwordless/verify (+GET alias)`, `GET /federated/*/callback`. El `202 forced_mfa` es byte-idéntico al MFA normal (sin `reason`); el `200 alerted` es idéntico al login normal (el riesgo solo viaja por email/audit + `session.high_risk` interno).

* Sin headers de riesgo al cliente (no se filtra umbral/ciudades/velocidad por HTTP).
* Sin códigos nuevos (reusa `mfa_required` / `active` / `401` opacos de cada flujo).

## 2. Eventos Asíncronos (Kafka)

Vía outbox del login que evalúa (en su Tx o justo después). Sin `lat/lon/IP` (solo ciudad/distancia/velocidad). Key `user_id`.

* **Tópico:** `auth.travel.v1` — **Key:** `user_id`
```json
{ "event_id": "uuid", "event_type": "travel.forced_mfa", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid", "from_city": "Lima, PE", "to_city": "Madrid, ES",
    "dist_km": 7900, "speed_kmh": 39000, "decision": "forced_mfa" } }
{ "event_id": "uuid", "event_type": "travel.alerted", "occurred_at": "...",
  "payload": { "user_id": "uuid", "from_city": "Lima, PE", "to_city": "Madrid, ES",
    "dist_km": 7900, "decision": "alerted" } }
```
* **Tópico:** `auth.audit.v1` — `{action:"travel.check", from_city, to_city, dist_km, speed_kmh, risk, decision, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email `impossible_travel` (ciudades+hora+device + `suggest_mfa` si sin MFA) vía worker.
