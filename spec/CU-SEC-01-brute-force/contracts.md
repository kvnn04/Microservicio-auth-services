# Contratos de Integración: CU-SEC-01

## 1. Contrato HTTP (API REST)

> **Sin rutas ni códigos nuevos.** Transversal: los 4 flujos cubiertos mantienen sus contratos (`401` opacos de CU-AUTH-01/02/06, CRED-02). Prohibido `423`/`429-por-lock`/`Retry-After-por-lock` (assert `no-423` en CI).

* **Flujos cubiertos:** `POST /login`, `POST /mfa/verify` (TOTP+backup), `POST /step-up/challenge`, `POST /password/change` (current). Todos: forma→SEC-02-rate→BruteGuard→verify/dummy→`401` opaco habitual si fallo/lock.
* **Respuesta en lock:** idéntica al fallo normal del flujo (mismo `code/body/tiempo`, sin `hasta`, sin `Retry-After`). La hora `hasta HH:MM` solo viaja en el email al dueño (canal verificado).

## 2. Eventos Asíncronos (Kafka)

Vía outbox del flujo que bloquea (no request nuevo). Sin secretos (solo hashes/counts). Key `user_id` o `account_hash`.

* **Tópico:** `auth.security.brute_lock.v1` — **Key:** `user_id`/`account_hash`
```json
{ "event_id": "uuid", "event_type": "brute.locked", "occurred_at": "...", "trace_id": "4bf92f...",
  "payload": { "user_id": "uuid-or-null", "account_hash": "sha256:...", "flow_first": "login",
    "fails": 5, "lock_until": "...+15min", "lock_count_24h": 1 } }
```
* **Tópico:** `auth.audit.v1` — `{action:"brute.check", account_hash, user_id?, flow, fails, locked, backoff_until?, trace_id}`. Schemas BACKWARD, DLQ `auth.dlq.v1`. Email `brute_lock` (hasta HH:MM + IP/UA/hora + links) vía worker, 1er + throttle 1/hora, solo user conocido.
