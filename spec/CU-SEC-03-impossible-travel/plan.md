# Plan de Implementación Técnica: CU-SEC-03

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/auth/` (`travel.go` — matemática pura, testeable sin I/O).
* **Entidades / Value Objects:**
  ```go
  const (
    MaxPlausibleKmh=1000; MinDistKm=100; MaxDtHours=24; MaxAccuracyKm=500
  )
  type GeoPoint struct { Lat, Lon, AccuracyKm float64; City, Country, ASN string }
  type TravelDecision string // Normal | ForceMFA | Alert | Skipped
  func HaversineKm(a, b GeoPoint) float64
  func EvaluateTravel(last *GeoPoint, lastAt time.Time, cur GeoPoint, now time.Time, mfa bool) (decision TravelDecision, distKm, speedKmh float64, skipReason string)
  // Aplica filtros §3.3 en orden: nil-last→skipped_first; dt>24h→Normal; acc>500→skip; sameASN→skip; dist<100→Normal; speed>1000→ForceMFA|Alert
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/auth/travel_ports.go
  type GeoIPResolver interface { Resolve(ctx context.Context, ip string) (GeoPoint, error) } // ErrUnknown→skip
  type LastLocationStore interface {
    GetLast(ctx context.Context, userID string) (*GeoPoint, time.Time, error) // ErrNone→skipped_first
    SaveLogin(ctx context.Context, userID string, cur GeoPoint, risk string) error // UPDATE users.last_login_geo (+ INSERT login_locations si existe)
  }
  ```
  Reuso `SessionIssuer/MFAPreTokenIssuer` (el llamador bifurca), `EventPublisher/Outbox`.

### Capa de Aplicación (`internal/service/`)
* **Servicio:** Sin servicio nuevo. `internal/service/travel_guard.go` (helper):
  * `PreIssueCheck(ctx, userID, ip, mfa bool) → (forceMFA bool, risk string)` — resuelve GeoIP (<5ms con timeout 50ms; timeout→skip), carga last, `EvaluateTravel`, métrica/audit (sin email aquí — el llamador envía según decisión para reusar su outbox/Tx).
  * Injerto en `login.go` (tras `ok`, antes de `Issue/Challenge`), `passwordless_verify.go`, `register_federated.go` callback (mismo punto). Si `forceMFA` y el llamador iba a `200` sin MFA (passwordless sin MFA? No: sin MFA no hay a qué forzar — cae a `Alert`; federado sin MFA igual) → convierte a `202 mfa_required`? Si el user NO tiene MFA no puede forzar: cae a `Alert` (matriz decisión en `EvaluateTravel` con `mfa` flag — el guard no inventa enrollment).
* **Flujo Orquestado (en llamador):** secreto-ok→`PreIssueCheck`→(`Normal`? Issue habitual : `ForceMFA`? pre-token+email : `Alert`? Issue+email high+`high_risk`)→`SaveLogin` post-éxito (en Tx Issue o best-effort tras ella).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):** Sin rutas nuevas (transversal pre-Issue). El `202 forced_mfa` es byte-idéntico al MFA normal (sin `reason`); el `200 alerted` lleva header `X-Session-Risk: high`? No: no se filtra al cliente salvo email (decisión: sin header, solo audit/email + `session.high_risk` interno para futuro Step-Up en ops — documentado).
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/last_location_store.go` (`users.last_login_geo JSONB {lat,lon,acc,city,country,asn,at}` + tabla opcional `login_locations(user_id, at, geo JSONB)` últimos 10 por user para forense (cap con `DELETE` viejos); `SaveLogin` = `UPDATE users` + `INSERT locations` best-effort en la Tx Issue o justo después).
  * GeoIP: `internal/adapter/identity/geoip_resolver.go` (`oschwald/maxminddb-golang` + `GeoLite2-City.mmdb` montada por volumen/env `GEOIP_MMDB`, `Resolve` con timeout 50ms, private/reserved → `ErrUnknown`, sin red).
* **Salida (Mensajería):** `kafka` (`travel.forced_mfa|travel.alerted` → `auth.travel.v1` + audit `travel.check`); worker SMTP `impossible_travel` (ciudades+hora+device, sin coords/IP) + `suggest_mfa` si sin MFA.
* **Salida (Seguridad):** `security/geo.go` (haversine + Validación rangos lat/lon) — matemática en dominio, parseo en adapter.

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `impossible_travel_total{action}` (9 valores §6) + `travel_speed_kmh` + `travel_distance_km` + `geo_resolve_duration_seconds` (p95<5ms) + `geo_unknown_total{reason}`.
* **Tracing (OpenTelemetry):** Hijo `Defense.ImpossibleTravel` (hijos `geo.resolve`, `db.last_location`, `travel.eval`) pre-Issue. Atributos `dist_km, speed_kmh, risk, city` (no `lat/lon`).
* **Logs Estructurados:** `pkg/logger`: `INFO travel normal`, `WARN forced_mfa/alerted (ciudades, dist, speed)`, `DEBUG skipped_*`, `WARN nogeoip`. Sin `lat/lon/IP` (hash/ciudad).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_022_login_geo.up.sql` (+ down):
  ```sql
  ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_geo JSONB;
  CREATE TABLE IF NOT EXISTS login_locations (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    at TIMESTAMPTZ NOT NULL DEFAULT now(), geo JSONB NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_loginloc_user_at ON login_locations(user_id, at DESC);
  -- purga: DELETE FROM login_locations WHERE (user_id, at) NOT IN (SELECT user_id, at FROM (...) LIMIT 10 por user) — worker semanal (documentado, no trigger)
  ```
  Down: `DROP TABLE login_locations; ALTER TABLE users DROP COLUMN last_login_geo;`. mmdb fuera de PG (volumen `geo/GeoLite2-City.mmdb`, licencia documentada + update mensual cron).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `travel_test.go` (haversine Lima-Madrid ≈7900km ±5%, filtros dt/accuracy/ASN/dist, umbral 1000 borde 999/1001, dt≤60s con dist<100, primer-login) + `travel_guard_test.go` con fakes (forced indistinguible, alerted con email flag, skips sin email, nogeoip fail-open). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/travel_smoke.js`: 50 VUs login con IPs fijas (Lima/Madrid/NYC por pool) — normales locales `200`, saltos `forced/alerted` según MFA, p95 overhead travel <15ms (GeoIP local), `skipped_asn` con mismo-ASN-mock; mmdb-ausente (flag) → 100% `skipped_nogeoip` + 0 emails travel; PG `last_geo` down → login `500` base (sin travel).
