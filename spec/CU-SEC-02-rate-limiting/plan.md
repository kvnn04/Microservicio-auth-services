# Plan de Implementación Técnica: CU-SEC-02

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/shared/` (`rate_limit.go` — matrix + keys, sin I/O).
* **Entidades / Value Objects:**
  ```go
  type Scope string // ScopeIP, ScopeAccount, ScopeToken
  type Rule struct { Route, Scope string; Limit int; Window time.Duration }
  func Matrix() []Rule // tabla §4.1 vinculante (generada desde config, validada)
  func KeyFor(rule Rule, ip, account string) string // rl:<route>:<scope>:<id>
  func ResolveIP(remoteAddr, xff string, trusted []net.IPNet) string
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/shared/rate_ports.go
  type RateLimiter interface {
    Allow(ctx context.Context, rule Rule, id string) (allow bool, remaining int, reset time.Time, retryAfter time.Duration, err error)
  }
  ```
  (El servicio no decide números: recibe `Rule` de config validada.)

### Capa de Aplicación (`internal/service/`)
* **Servicio:** Sin servicio nuevo. `internal/service/rate_guard.go` (helper): `Check(limiter, rule, id)` → `ErrRateLimited{RetryAfter}` + métrica/audit. Lo invoca el middleware (no los casos de uso, salvo tests que lo fingen).
* **Flujo Orquestado:** `ResolveIP → KeyFor → Limiter.Allow (Lua)` → allow? inyecta headers + sigue : `429` + headers + audit + métrica. Exentos bypassan (pero loguean).

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Middleware `middleware/rate_limit.go` (central, PRIMERO tras `recover/request_id`): carga `Rule` por `método+ruta-template` (+ scope cuenta si hay Bearer/email identificable), llama puerto, escribe IETF headers siempre, corta `429` uniforme. `middleware/ip_resolver.go` (trusted proxies CIDRs env). `middleware/progressive_block.go` (`announcer:ip` 50/15min → `blocked:ip EX 900`, chequeado antes que reglas).
  * Config `config/ratelimit.yaml` (+ env override `RL_<ROUTE>_<SCOPE>=limit/window`) + `SIGHUP`/poll-30s hot-reload con validación (última-válida + gauge `rate_config_version`).
  * `errors/` reusa `RATE_LIMITED` (sin códigos nuevos).
  * Rutas: se cablea GLOBAL en `cmd/api/main.go` (antes de auth), con allowlist `healthz/metrics` exentas.
* **Salida (Persistencia):**
  * Redis: `persistencia/redis/rate_limiter.go` (`sliding_allow.lua`: `TIME` Redis + ZSET por key + `EXPIRE`; `announcer/blocked` con `INCR EX`/`SET EX`; `TIME` evita skew réplicas) + fallback memoria (`sync.Map` + mutex por key, cap 2x, purga lazy 1s) + `WARN` + métrica.
* **Salida (Mensajería):** `kafka` audit `rate.limited` (muestreo 10% flood) + `rate.ip_blocked` (siempre) + métricas; sin SMTP.
* **Salida (Seguridad):** sin cripto (hashes `sha256` email→account scope).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `rate_limited_total{route,scope}` + `rate_allow_total` (1% hot) + `rate_redis_fallback_total` + `rate_config_version` + `ip_blocks_total` (reuso SEC-01 `ip_blocks`? No: bloques aquí son `rate.ip_blocked`, métrica propia `rate_ip_blocks_total`).
* **Tracing (OpenTelemetry):** Hijo `Defense.RateCheck` primero (hijos `ip.resolve`, `redis.lua`). Atributos `route, limit, remaining`, nunca IP.
* **Logs Estructurados:** `pkg/logger`: `WARN rate_limited (route, scope)`, `WARN ip_blocked`, `WARN redis-fallback`, `INFO config_reloaded (version)`, `ERROR config_invalid (kept)`. Sin IP completa (hash).

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_021_ratelimit_noop.up.sql` (+ down): `SELECT 1;` (sin tablas; Redis ZSET efímeros). Documenta `TRUSTED_PROXIES` y `ratelimit.yaml` como Apéndice operativo (no DB).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** `rate_limit_test.go` (ResolveIP matriz trusted/spoof/v6, KeyFor, Matrix válida: sin rutas sin regla salvo exentas, límites>0) + `rate_guard_test.go` (allow/deny headers, progresivo 50→block, exentos nunca 429, config inválida conserva). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/ratelimit_smoke.js`: 11/min → 11º `429` + headers decrecientes + `Retry-After`; caballo-ventana (10+10) → 2ª tanda `429` (sliding); XFF-spoof ignorado; Redis-down → 0 `500` (2x local); `/healthz` 1000/min → 200; progresivo 50×429 → block 15min. Mock `TIME` Redis para determinismo.
