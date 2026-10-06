# Spec: CU-SES-03 - Listado y Terminación Selectiva de Sesiones Activas

## 1. Contexto y Propósito
Dar visibilidad ("¿dónde estoy logueado?") y bisturí (matar la del ciber sin tocar la actual). Lectura sin Step-Up + revocación remota sin Step-Up (defensa inmediata, igual logout), con metadatos enmascarados (nunca tokens) y email aviso. Supuestos aplicados para Q4/Q5 sin respuesta (a confirmar): Q4 → `404 SESSION_NOT_FOUND` idéntico (muerta/ajena/inexistente); Q5 → `last_seen` en Issue+Rotate (+touch gateway best-effort), sin heartbeat.

Decisiones (Q1-Q3,Q6,Q7 Recommended + Q4/Q5 supuesto Recommended):
- Q1 Sin Step-Up + rate list 60/min + revoke 20/hora, Q2 Masked + `current`, Q3 Actual → `400 USE_LOGOUT`, Q6 Triple-capa objetivo + email, Q7 Sin paginar (≤20) + métricas/audit.

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado ACTIVE (Bearer válido; si expirado → `401`, no lista nada).
* **Precondiciones:**
  * `sessions` del `sub` (0..20). Rate libre (`list:user 60/min`, `revoke-one:user 20/hora`).

## 3. Flujo Principal (Happy Path)
### A. Lista
1. Usuario llama `GET /api/v1/auth/sessions` + Bearer + `X-Request-ID`.
2. El back valida JWT base (firma/exp/sub; sin frescura/Step-Up) + rate (excede → `429`).
3. Lee `sessions WHERE user_id=$sub ORDER BY last_seen DESC` (PG verdad; Redis `sess:by_user` como fast-path con fallback PG si miss — la lista NUNCA se sirve solo de Redis evictado: si Redis miss → PG; documentado).
4. Mapea cada fila a DTO público: `{sid, device_label:"Chrome · Windows", ip_masked:"203.0.113.xxx", location:"Lima, PE" (o null sin GeoIP), created_at, last_seen_at, current:(sid==Bearer.sid)}`. Nunca `jti/family/tokens/hashes`. Ordenada, `current` primero o marcada (decisión: orden `last_seen DESC`, `current` con flag, no reordenada al frente — el front la destaca).
5. Retorna `200 {sessions:[...], total:N}` + `no-store` (sin paginar; N≤20 por `MAX_SESSIONS`).
### B. Revocación selectiva
6. Usuario llama `DELETE /api/v1/auth/sessions/:sid` + Bearer (el `:sid` objetivo ≠ actual; si `==actual` → `400 USE_LOGOUT {message:"Usa POST /logout para esta sesión."}` sin tocar nada).
7. Valida `sid` formato UUID (malforma → `400 VALIDATION_FAILED`); rate revoke (excede → `429`); lookup `sessions WHERE sid=$target AND user_id=$sub` (miss → `404 SESSION_NOT_FOUND` idéntico sea ajena/inexistente/muerta — supuesto Q4).
8. Triple-capa objetivo (igual SES-01 pero por `sid` target): Tx PG `UPDATE families revoked WHERE family=target.family` + `DELETE sessions target` + outbox (`session.revoked_one{target_sid}`) + audit; Redis `DEL sess:<target> + DEL fam:<target.family>` + `SET jti:<target.jti_actual> revoked EX=restante Access` (el `jti_actual` se lee de `sessions.jti_actual` antes de borrar; si ya rotó (SES-04) se denylistea el actual conocido).
9. Retorna `200 {status:revoked, sid}` (actual intacta: su `sess/fam` no tocadas, su Access sigue). Email siempre `Cerraste la sesión de <device_label> (<ip_masked>)` + hora + `si no fuiste tú cambia tu clave` (sin throttle; si SMTP cae, outbox reintenta).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** sin Bearer/malo/expirado → `401`; `:sid` no-UUID → `400`; actual → `400 USE_LOGOUT`; body ignorado.
* **4.2. No encontrada (supuesto Q4):** target de otro user / inexistente / ya muerta (logout individual/global/previa selectiva/evicción) → `404 SESSION_NOT_FOUND` idéntico (mismo body/tiempo ±jitter 10-20ms; no distingue). No revela si el `sid` existe en otra cuenta.
* **4.3. Infra:** PG down → `500` (lista vacía NO se finge: `500`, no `200 []`; revoke no ejecuta); Redis down → PG verdad + `WARN` (lista correcta, revoke PG + reconcilia Redis al volver); Kafka down → `200` (outbox pendiente; email puede tardar).
* **4.4. Rate:** `429 + Retry-After` (sin ejecutar). Sin locks cuenta (lectura/revoke propio no autentica secreto).
* **4.5. `last_seen` (supuesto Q5):** se escribe en `Issue` (creación), `Rotate` (cada refresh, SES-04), y `touch` best-effort si el gateway envía `X-Session-Touch: <sid>` en APIs (el Auth lo acepta sin validar de más, `UPDATE last_seen` async con debounce 5min por `sid` para no escribir por request — documentado). Sin heartbeat dedicado (el front NO hace polling de touch).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Sin Step-Up/frescura (lista y revoke remota son defensa). Rate list 60/min/user (+60/min/IP), revoke 20/hora/user.
* **RN-02:** Solo propias (`user_id==sub` en TODAS las queries; el `sid` es aleatorio 122-bit, no secuencial — no enumerable).
* **RN-03:** Actual protegida por contrato (`400 USE_LOGOUT`); global en SES-02; pares en CRED-02 (mantiene actual por otro camino — consistente).
* **RN-04:** Metadatos masked: `ip_masked` (`/24` + `xxx`, nunca completa), `location` ciudad/país o null (GeoIP best-effort, sin precisión calle), `device_label` familia UA (sin UA crudo), sin `jti/family/tokens/hashes`. `device_label` se calcula al Issue y se guarda (no se re-parsea en lista).
* **RN-05:** Orden `last_seen DESC`, sin paginar (N≤20). `total` = len.
* **SEC-01:** Sin tokens en lista/logs/eventos (solo `sid` + labels). El `sid` es identificador de sesión — exponerlo al dueño es necesario (para revocar); a terceros no (auth exigida + `sid` aleatorio).
* **SEC-02:** Revoke-one no distingue ajena/muerta (`404` único, con jitter para no filtrar por tiempo DB-hit/miss).
* **SEC-03:** Email siempre en revoke-one (el dueño ve cierres ajenos; si el atacante cierra las del dueño, el dueño recibe aviso por cada una — throttle? No: cada revoke legítimo avisa; flood de revokes ajenos lo frena el rate 20/hora).

## 6. Requerimientos de Observabilidad
* **Métrica:** `sessions_listed_total{result}` + `session_revoked_one_total{result=ok|use_logout|not_found|rate_limited}` + duraciones. Vía MetricsPort + middleware.
* **Trazabilidad:** Raíces `UseCase.ListSessions`, `UseCase.RevokeSession` (hijos: `jwt.verify`, `ratelimit`, `db.sessions.select|revoke (Tx)`, `cache.*`, `outbox.insert`). Atributos `target_sid` (propio), nunca tokens.
* **Auditoría:** `auth.audit.v1 {action:"session.list|revoke_one", target_sid?, result, trace_id}` + eventos `session.listed?` (no: listar no emite evento Kafka, solo audit/métrica — decisión para no spamear bus; revoke-one sí `session.revoked_one.v1` key `user_id`). Sin PII.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Lista con 3 + actual marcada, sin tokens**
  * **Dado** 3 vivas (A actual PC-Lima, B móvil, C ciber).
  * **Cuando** `GET /sessions` con A.
  * **Entonces** `200 {total:3, sessions[3]}` con `current:true` solo A, `ip_masked` sin octeto final, `device_label` legible, 0 campos `token/jti/family/hash`, orden `last_seen DESC`. Con Redis down → mismo `200` vía PG. Sin Bearer → `401`.
* **Escenario 2: Revoca remota sin tocar actual**
  * **Dado** A/B/C vivas.
  * **Cuando** `DELETE /sessions/C` con A.
  * **Entonces** `200 revoked C` + C muerta (API con C → `401`, Refresh C → `401`) + A/B vivas + email `Cerraste <device C>` + `revoked_one` 1. `DELETE /sessions/A` (actual) → `400 USE_LOGOUT` + A viva. `DELETE /sessions/ajeno-o-muerto` → `404` idénticos.
* **Escenario 3: Rate + PG-down**
  * **Dado** flood lista 70/min y 25 revokes/hora; PG down.
  * **Cuando** excede + lista con PG down.
  * **Entonces** 61º list → `429`; 21º revoke/hora → `429` (0 cambios); PG-down list → `500` (no `200 []` falso) y revoke → `500` (0 cambios). Redis-down → `200` correctos vía PG.
