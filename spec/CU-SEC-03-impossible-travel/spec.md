# Spec: CU-SEC-03 - Detección de Viaje Imposible (Impossible Travel)

## 1. Contexto y Propósito
Frenar sesiones con geografía físicamente imposible sin castigar viajeros/VPN: compara último login contra el actual (haversine − accuracy / dt) y, si supera 1000 km/h, escala a MFA obligatorio (con MFA) o alerta high (sin MFA). Actúa pre-Issue en los 3 logins que emiten sesión, con GeoIP local y skip elegante ante unknown/VPN.

Decisiones (2026-10-05, todas Recommended):
- Q1 login+passwordless+federado pre-Issue (no APIs/refresh), Q2 MFA→`202` forzado / sin-MFA→permite+email high (nunca bloqueo duro), Q3 >1000 km/h con filtros (dt>24h, accuracy>500km, primer login = skip), Q4 MaxMind local (<5ms, unknown→skip), Q5 Guarda últimas 2 posiciones ciudad+hash (sin IP cruda), Q6 Mismo ASN→skip (VPN), Q7 3 puertos + métricas/audit sin coords exactas.

## 2. Actores y Precondiciones
* **Actores:** Usuario (viajero o atacante con credencial), Microservicio Auth, DB MaxMind, Worker SMTP.
* **Precondiciones:**
  * Credencial primaria OK (password/passwordless/federado verificado) y cuenta `ACTIVE` (si falla antes, este CU no corre).
  * `users.last_login_geo` con ≥1 posición previa (si nunca → `skipped_first_login`, sin evaluar).
  * GeoIP DB cargada (`GEOIP_MMDB` path; si ausente/corrupta al arrancar → `WARN` + todo `skipped_no_geoip`, fail-open documentado).

## 3. Flujo Principal (Happy Path)
1. Tras validar secreto (antes de `Issue`/pre-token), el servicio obtiene `IP` real (reuso `ResolveIP` CU-SEC-02: RemoteAddr salvo trusted-proxy XFF) y resuelve `GeoIP(ip) → {lat, lon, accuracy_km, city, country, asn}` local (<5ms; si IP privada/reservada/desconocida/sin ciudad → `skipped_unknown` + sigue flujo normal sin demora).
2. Carga `last{lat,lon,acc,at}` del user (PG `users.last_login_geo` + penúltima en `login_locations` si existe; si `last==null` → `skipped_first`).
3. Filtros skip (sin evaluar velocidad, con métrica `skipped_*`): `dt>24h` → normal (viaje plausible en avión real); `accuracy_actual>500` o `accuracy_last>500` → skip (ruido); `mismo ASN` (actual==last, ambos conocidos) → skip (VPN/proxy); `distancia<100km` → normal directo (ruido urbano, sin cálculo).
4. Calcula `dist = max(0, haversine(lat1,lon1,lat2,lon2) − acc1 − acc2)`, `dt = now − last.at` (si `dt≤60s` exige `dist>100km` para no dividir por ~0 con jitter GPS; si `dt≤0` (reloj) → skip), `speed = dist/dt`.
5. Si `speed ≤1000 km/h` → normal (`risk=low`): sigue a Issue/pre-token habitual + actualiza `last_login_geo=actual` post-éxito (en la Tx Issue o justo después con `UPDATE ... WHERE id` best-effort + outbox `login.location`).
6. Si `speed >1000` → `risk=high` + `impossible_travel_total{action}`:
   a. Con `mfa_enabled` → ignora rama sin-MFA: emite `202 mfa_required` + pre-token (aunque el llamador iba a `200` directo) + email `Acceso inusual: te pedimos el segundo factor (Lima → Madrid en 12min)` + audit `forced_mfa` (el atacante sin TOTP muere aquí; el viajero con TOTP pasa).
   b. Sin MFA → permite `200` (no bloquea) + email high `¿Fuiste tú? Nuevo acceso desde Madrid` + `suggest_enable_mfa` + audit `alerted` + marca `session.high_risk=true` (el gateway puede exigir Step-Up en ops críticas aunque `auth_time` sea fresco — gancho CU-AUTH-06 futuro, documentado).
7. En ambos casos de éxito (directo o tras MFA posterior) actualiza posición (la posición del login anómalo se guarda solo tras completar el 2º factor si lo hubo; si fue `alerted` sin MFA se guarda igual con `risk=high` para no alertar dos veces el mismo salto).

## 4. Flujos Alternativos y Excepciones
* **4.1. Skips (no son errores):** primer login, unknown/private, DB ausente, `dt>24h`, accuracy pésima, mismo ASN, `dist<100km` → flujo normal + `skipped_*` (sin email, sin delay extra). `GET /sessions` muestra `location` con `risk` histórico? No (este CU no cambia SES-03 salvo `last_seen`; el `risk` vive en audit).
* **4.2. VPN/datacenter:** ASN hosting conocido (lista `DATACENTER_ASNS` opcional) → trata como mismo-ASN (skip) + `skipped_datacenter`. Sin blocklist manual MVP (Q6).
* **4.3. Infra:** GeoIP DB corrupta → `skipped_no_geoip` + `WARN` + métrica (fail-open, 0 bloqueos por geografía ciega). PG `last_geo` down → el login ya daría `500` (sin evaluar). Kafka down → `200/202` igual (email pendiente).
* **4.4. Rate:** sin buckets propios (hereda login/pless/federado). Sin locks (esto no autentica secreto).
* **4.5. Federado sin email/IP fiable:** callback tras consentimiento Google trae IP del servidor? No: trae IP del browser en callback (igual login). Misma evaluación.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Solo pre-Issue en 3 logins (no APIs, no refresh, no verify-OTP de registro). `refresh` no re-evalúa (el robo por Refresh lo caza SES-04 por reuse, no por geo).
* **RN-02:** Nunca bloqueo duro por geo (falsos VPN/viaje). Escalada = MFA o alerta. (Futura política `ENFORCE_GEO_BLOCK=true` vetada en MVP — documentada como no-Go sin MFA universal.)
* **RN-03:** Umbral `1000 km/h`, `haversine − accuracies`, `dt` desde último ÉXITO (no intento), filtros §3.3. `speed` con `dt≤60s` exige `dist>100km`.
* **RN-04:** Posición = ciudad (`lat/lon` centro ciudad MaxMind + `accuracy_km` + `city/country/asn`), 2 últimas (`last` + `prev` en `login_locations` si se crea; mínimo `users.last_login_geo` JSONB). Sin IP cruda (solo `ip_hash`), sin calle/GPS.
* **RN-05:** Mismo ASN → skip (con `asn==0/unknown` NO skip — unknown-ASN se evalúa normal salvo otro skip).
* **SEC-01:** Sin coords exactas en logs/eventos (solo `city/country/distancia_km/velocidad`, `city_hash`). `lat/lon` solo memoria request + PG `last_login_geo` (acceso DB restringido, documentado PII media).
* **SEC-02:** El email high incluye ciudades + hora + device (para que el dueño reconozca), nunca `lat/lon` exactas ni IP completa.
* **SEC-03:** `forced_mfa` no revela al atacante que fue detectado por geo (el `202 mfa_required` es idéntico al MFA normal — sin campo `reason`, para no enseñar el umbral).

## 6. Requerimientos de Observabilidad
* **Métrica:** `impossible_travel_total{action="normal|forced_mfa|alerted|skipped_first|skipped_unknown|skipped_asn|skipped_accuracy|skipped_dt|skipped_nogeoip"}` + `travel_speed_kmh` Histogram (solo evaluados) + `travel_distance_km` Histogram.
* **Trazabilidad:** Hijo `Defense.ImpossibleTravel` pre-Issue en los 3 `UseCase.*` (hijos: `geo.resolve (<5ms)`, `db.last_location`, `travel.eval`). Atributos `dist_km, speed_kmh, risk`, nunca `lat/lon` (solo `city`).
* **Auditoría:** `auth.audit.v1 {action:"travel.check", from_city, to_city, dist_km, speed_kmh, risk, decision, trace_id}` + eventos `travel.forced_mfa|travel.alerted` (key `user_id`). Sin coords/IP.

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Imposible con MFA → desafío indistinguible**
  * **Dado** último Lima hace 12min, actual Madrid (7900km ⇒ ~39000 km/h), `mfa=true`.
  * **Cuando** login password OK.
  * **Entonces** `202 mfa_required` idéntico al MFA normal (sin `reason`) + email inusual + audit `forced_mfa`; TOTP posterior OK → `200` + posición=Madrid. Sin este CU habría sido `200` directo.
* **Escenario 2: Imposible sin MFA → permite + alerta**
  * **Dado** mismo salto, `mfa=false`.
  * **Cuando** login OK.
  * **Entonces** `200` + email high `¿Fuiste tú?` + `suggest_enable_mfa` + audit `alerted` + `session.high_risk=true`. Nada bloqueado.
* **Escenario 3: Skips (24h, ASN, unknown, primero)**
  * **Dado** 4 casos: último hace 30h mismo salto; mismo ASN distinto país (VPN); IP privada; primer login.
  * **Cuando** logins OK.
  * **Entonces** 4× `200/202` normales sin email travel (métricas `skipped_*`), posiciones actualizadas. `dist<100km` en 2min → normal (no `speed` loca por dt~0).
* **Escenario 4: GeoIP down + PG down**
  * **Dado** mmdb ausente; PG `last_geo` down (login ya 500).
  * **Cuando** login.
  * **Entonces** mmdb-ausente → `200/202` normales + `WARN` + `skipped_nogeoip` (0 GEO-bloqueos); PG-down → `500` base (sin travel). Kafka-down → `200/202` + emails pendientes.
