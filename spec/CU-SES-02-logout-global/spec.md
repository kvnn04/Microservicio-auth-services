# Spec: CU-SES-02 - Cierre de Sesión Global (Revocación Masiva)

## 1. Contexto y Propósito
Cortar todo de una vez ante robo/pérdida: una Tx bump `tokens_valid_after=now` (mata todos los Access por `iat`) + revoca todas las families + borra todas las `sessions` (incluida la que llama) + barre Redis. Sin Step-Up (la defensa no puede esperar frescura), con rate anti-loop, email siempre e idempotencia. Los pre-tokens efímeros (5-15min, otro `aud`) expiran solos (best-effort DEL).

Decisiones (2026-10-05, todas Recommended):
- Q1 Sin Step-Up + rate 5/hora/user, Q2 Tx única `valid_after` + revoke-all + DEL, Q3 Mueren todas incluida actual + Clear-Cookie, Q4 `200` idempotente + email siempre, Q5 Best-effort challenges + ventana residual documentada, Q6 Sin N-denylist (gateway cache `valid_after` 60s, ventana ≤60s), Q7 Métricas/audit/eventos/email.

## 2. Actores y Precondiciones
* **Actores:** Usuario Autenticado (Bearer con `sub`, cualquier `auth_time`, vigente o no-expirado; si expirado → `401` pues no identifica `sub`).
* **Precondiciones:**
  * `users` existe (si fue borrado → `401/404` base, nada que cortar).
  * Rate `logout-global:user 5/hora` + `logout-global:ip 20/hora` libre.

## 3. Flujo Principal (Happy Path)
1. Cliente envía `POST /api/v1/auth/logout-global` + Bearer + `X-Request-ID`.
2. El back valida JWT base (firma/kid/iss/aud/exp/sub; NO frescura/Step-Up/denylist/valid_after para entrar — el corte debe funcionar aunque el llamante esté en denylist por logout individual previo o con `valid_after` viejo de otro corte).
3. Rate-check (excede → `429`, sin tocar nada).
4. En UNA Tx PG: `UPDATE users SET tokens_valid_after=now() WHERE id=$sub RETURNING valid_after` (siempre bumpea, incluso repeat — harmless) + `UPDATE refresh_families SET revoked=true WHERE user_id=$sub` (cuenta N) + `DELETE sessions WHERE user_id=$sub` (cuenta M) + `INSERT outbox(session.revoked_all{N,M})` + audit. Redis post-commit: `DEL sess:by_user:<sub>/*` (cada `sess:<sid>`, `fam:*` del user vía índice `by_user`) + `DEL` challenges indexados (`mfa:challenge:by_user:<sub>`, `stepup` si indexado; pless/verify/reset se dejan expirar por TTL + `WARN` residual) + `PUBLISH auth.session.revoked_all` (además de outbox/Kafka, para gateways suscritos a invalidación inmediata `valid_after`, reduciendo ventana 60s a ~1s donde hay pub/sub).
5. Retorna `200 {status:logged_out_global, sessions_revoked:M}` + Clear-Cookie refresh actual + `no-store`. Email siempre `Cerraste todas tus sesiones (N dispositivos)` con hora/IP + `si no fuiste tú cambia tu clave` (sin throttle; si SMTP cae, outbox reintenta).
6. Efecto: cualquier Access con `iat<valid_after` → gateways `401` (cache `valid_after` 60s ⇒ residual ≤60s + pub/sub ~1s); cualquier Refresh → `401 FAMILY_REVOKED`; `sess:*` miss. El llamante también muere (su siguiente request → `401`).

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación:** sin Bearer/malo/expirado → `401` (0 cambios). Body ignorado (≤4KB).
* **4.2. Idempotencia:** repeat con Bearer de sesión ya muerta pero no-expirada (firma OK, `iat<valid_after`) → entra igual (no exige `valid_after` para entrar) → re-bumpea + revoca 0 + `200` con `M=0` (mismo shape). No distingue primer/repeat (salvo counts).
* **4.3. Infra:** PG down → `500` SIN Clear-Cookie (reintentable, no finge). Redis down → PG verdad + `WARN` (barrido Redis pendiente a reconciliador; gateway depende de `valid_after` PG-cache, ventana igual ≤60s) + `200`. Kafka down → `200` (outbox pendiente; pub/sub Redis compensa lo inmediato). SMTP down → `200` + email pendiente.
* **4.4. Rate/abuso:** `429 + Retry-After` (sin corte). Hijack que hace loop global → dueño re-loguea con password (el atacante no la tiene salvo robo total, que es CRED-01/SEC-05); rate 5/hora frena el loop + email alerta cada corte (el dueño ve actividad ajena).
* **4.5. Residuales:** pre/step-up/mfa-challenge/pless/verify/reset vivos ≤15min tras el corte (otro `aud`, no cubiertos por `valid_after`): best-effort DEL indexados + documenta ventana (atacante con pre-token robado de 5min podría completar MFA dentro de la ventana — riesgo aceptado y auditado; mitigación total en CU-SEC-04 con `global_epoch` por `aud` — fuera de este CU).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Todas (incluida actual). Sin flag `keep_current` (eso es SES-03).
* **RN-02:** Sin Step-Up/frescura (defensa inmediata). Rate 5/hora/user + 20/hora/IP.
* **RN-03:** `valid_after=now()` por corte (monótono; re-bump en repeat). `families revoked` + `sessions DELETE` en la misma Tx (0 vivas post-commit).
* **RN-04:** Sin N-denylist `jti` (ineficiente); gateway: `iat<valid_after → 401` (cache 60s) + pub/sub `revoked_all` para ~1s donde suscrito.
* **RN-05:** Idempotencia RequestID 24h (mismo RequestID → mismo `200` sin re-bumpear? No: re-bumpear es harmless pero genera outbox duplicado; con mismo RequestID se dedupica outbox por `event_id=hash(RequestID)` — documentado).
* **SEC-01:** Sin tokens en logs/eventos (solo `sub`, counts, `valid_after`). Email sin links sensibles salvo `login`/`forgot` genéricos.
* **SEC-02:** El corte no distingue causa (robo/pérdida/voluntario) — mismo `200`/email base + `reason:user_request` en audit (si lo invoca el sistema por robo SES-04, `reason:reuse_detected` — mismo efecto, distinto audit).
* **SEC-03:** `POST` + Bearer (no GET/CSRFable).

## 6. Requerimientos de Observabilidad
* **Métrica:** `logout_global_total{result="ok|rate_limited|invalid|error"}` + `sessions_revoked_count` Histogram (buckets 1,2,5,10,20) + `logout_global_duration_seconds`.
* **Trazabilidad:** Raíz `UseCase.LogoutGlobal` (hijos: `jwt.verify`, `ratelimit`, `db.global_revoke (Tx)`, `cache.sweep+pub`, `outbox.insert`). Atributos `revoked_sessions/families`, nunca tokens.
* **Auditoría:** `auth.audit.v1 {action:"session.logout_global", user_id, sessions:M, families:N, valid_after, trace_id}` + evento `session.revoked_all.v1` (key `user_id`). Sin PII.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Corte total con 3 sesiones**
  * **Dado** 3 vivas (A actual + B + C).
  * **Cuando** `POST /logout-global` con A.
  * **Entonces** `200 {sessions_revoked:3}` + Clear-Cookie + 0 `sessions` + N `families revoked` + `valid_after≈now`; A/B/C en API → `401` (gateway `valid_after`); Refresh cualquiera → `401`; email 1 + `revoked_all` 1. Repetir con A (no-expirado) → `200` con `0`.
* **Escenario 2: Rate + inválido**
  * **Dado** flood 7/hora mismo user; Bearer expirado.
  * **Cuando** 6º corte + corte expirado.
  * **Entonces** 6º → `429` (5 cortes previos `200`); expirado → `401` (0 cambios). Hijack-loop frenado + dueño alertado por email cada corte real.
* **Escenario 3: Residual ≤60s + PG/Redis-down**
  * **Dado** gateway con cache `valid_after` 60s + suscrito pub/sub; PG down; Redis down.
  * **Cuando** corte.
  * **Entonces** con pub/sub el gateway rechaza en ~1s (sin él ≤60s); PG-down → `500` sin cookie ni filas; Redis-down → `200` vía PG + `WARN` + barrido pendiente reconciliado. Pre-token robado pre-corte podría usarse ≤5min (ventana documentada, audit).
