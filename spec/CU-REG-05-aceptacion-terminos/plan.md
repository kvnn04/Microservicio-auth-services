# Plan de Implementación Técnica: CU-REG-05

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/shared/legal.go` (transversal, sin import infra).
* **Entidades / Value Objects:**
  ```go
  type DocType string // DocTerms ("terms"), DocPrivacy ("privacy")
  type LegalDocument struct { DocType DocType; Version string; ContentHash, URL string; EffectiveFrom time.Time; IsActive bool }
  func (d LegalDocument) ValidateFormat() error // ^v\d{4}\.\d{2}$, hash hex64, url https
  type ConsentRecord struct { ID string; UserID string; DocType DocType; Version string; AcceptedAt time.Time; IPHash, UAHash, Source, RequestID string }
  func NewConsentRecord(userID string, doc DocType, ver, ipHash, uaHash, source, reqID string) (*ConsentRecord, error)
  func ValidateConsentInput(accepted bool, termsVer, privVer string) error // ErrTermsRequired | ErrInvalidFormat (previo a DB)
  ```
* **Puertos de Salida:**
  ```go
  // internal/domain/shared/legal_ports.go
  type LegalVersionProvider interface {
    GetActive(ctx context.Context) (terms, privacy LegalDocument, err error) // ErrInfra si DB+cache caen (register fail-closed)
  }
  type ConsentLedger interface {
    RecordTx(ctx context.Context, tx any, recs []ConsentRecord) error // INSERT ... ON CONFLICT DO NOTHING dentro de Tx negocio (tx opaca any para no importar pgx en dominio; adapter hace cast)
  }
  ```
  El servicio orquesta; la Tx la abre el adapter PG (puerto `TxManager` existente CU-REG-01, extendido para incluir `consent_records` en la misma Tx).

### Capa de Aplicación (`internal/service/`)
* **Servicio / Caso de Uso:** Sin servicio nuevo. `internal/service/legal_consent.go` (helper puro):
  * `func CheckConsentFast(accepted bool, tv, pv string) error` (formato + accepted, sin I/O, antes de rate-limit pesado/Probe).
  * `func CheckConsentAgainstActive(accepted bool, tv, pv string, activeT, activeP LegalDocument) error` (`ErrTermsRequired` | `ErrTermsOutdated{ActiveT, ActiveP}`).
  * Injerto en `register_user.go` y `register_federated.go` (y `federated_authorize` pre-302): orden vinculante `ValidateConsentFast → GetActive → CheckAgainstActive → Probe unicidad → DummyHash → Tx(users+consent+outbox)`. Falla antes de Probe (rápido, sin fuga timing de existencia).
  * `GetActive` con política cache: `LegalVersionProvider` implementa `Redis-hit? Redis : DB : ErrInfra` (GET tolera env-fallback, register no — ver adapter).
* **Flujo de Ejecución Orquestado:** parse DTO → `CheckFast` (400 inmediato) → `GetActive` (500 si infra en register) → `CheckAgainst` (400 outdated con activas) → resto del CU origen. En federado-authorize el mismo helper corre antes de `SaveState`. Métrica `consent_rejected_total` en el punto de rechazo + span hijo.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Nuevo handler lectura: `internal/adapter/http/handlers/legal_active.go` (`GET /api/v1/legal/active` → `200 {terms:{...}, privacy:{...}, stale:bool}`, `Cache-Control: public, max-age=3600`, rate-limit `legal:ip 60/min`).
  * Endurece: `dto/register_dto.go` (ya tiene campos; añade validación `terms_version/privacy_version` formato en handler antes del servicio) + `handlers/register.go` / `federated_authorize.go` (mapean `ErrTermsRequired→400 TERMS_REQUIRED`, `ErrTermsOutdated→400 TERMS_OUTDATED + meta.active`).
  * Errors: `errors/map.go` (+2 códigos, `meta` con activas solo en OUTDATED).
  * Rutas `cmd/api/main.go`: `GET /api/v1/legal/active` (pública, cacheable) junto a auth.
* **Salida (Persistencia):**
  * Postgres: `persistencia/postgres/legal_repository.go` (`GetActive`: `SELECT ... WHERE is_active`, 2 filas; `RecordTx`: `INSERT consent_records ... ON CONFLICT(user_id,doc_type,version) DO NOTHING` con `tx pgx.Tx` casteada; GRANTs `REVOKE UPDATE,DELETE ON consent_records, legal_versions FROM app_role` aplicados en migración).
  * Redis: `persistencia/redis/legal_cache.go` (`GET/SET legal:active {terms,privacy} EX 3600`, invalidada por publicación; `GET` handler la usa, `register` la usa como fast-path pero revalida DB si `terms_version` del request != cache — evita aceptar obsoleto por cache vieja: si request trae versión == cache pero DB ya avanzó, el `CheckAgainstActive(DB)` lo rechaza igual).
* **Salida (Mensajería):** reuso `colas/kafka/user_producer.go` + tipo `legal.consent_recorded` → tópico `auth.legal.v1` (1 evento con array 2 consents) + `auth.audit.v1 {action:legal.consent}`. Worker sin SMTP (solo ledger + auditoría; el email de bienvenida ya lo cubre registro).
* **Salida (Seguridad):** sin criptografía nueva (hashes `sha256` para `content_hash/ip/ua` con helpers `security/hash.go` reuso).

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** `consent_recorded_total{doc_type,source}`, `consent_rejected_total{reason=missing|outdated|invalid_format}`, `consent_outdated_total{doc_type}`, gauge `legal_active_version_info{doc_type,version}` (=1, actualizada en `GET` y en servicio), `legal_cache_hits_total{hit}`. Alerta `rate(outdated[1h])/rate(total[1h])>0.10`.
* **Tracing (OpenTelemetry):** Hijo `Legal.CheckConsent` (hijos `legal.versions.fetch`, `legal.validate`, `db.consent.insert` dentro de Tx negocio). Atributos `terms.version, privacy.version, source` (públicos).
* **Logs Estructurados:** `pkg/logger`: `INFO consent recorded` (con `user_id, versions`, sin texto), `WARN consent rejected (reason, versions pedidas vs activas)`, `ERROR legal_store_unavailable` (fail-closed). Sin texto legal ni IP completa en logs.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/20261005_005_legal_consent.up.sql` (+ down):
  ```sql
  CREATE TABLE legal_versions (
    doc_type TEXT NOT NULL CHECK (doc_type IN ('terms','privacy')),
    version TEXT NOT NULL CHECK (version ~ '^v[0-9]{4}\.[0-9]{2}$'),
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    url TEXT NOT NULL, effective_from TIMESTAMPTZ NOT NULL, is_active BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (doc_type, version)
  );
  CREATE UNIQUE INDEX uq_legal_active ON legal_versions(doc_type) WHERE is_active;
  CREATE TABLE consent_records (
    id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    doc_type TEXT NOT NULL, version TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_hash TEXT NOT NULL, ua_hash TEXT NOT NULL, source TEXT NOT NULL, request_id UUID NOT NULL,
    FOREIGN KEY (doc_type, version) REFERENCES legal_versions(doc_type, version),
    UNIQUE (user_id, doc_type, version)
  );
  CREATE INDEX idx_consent_user ON consent_records(user_id);
  INSERT INTO legal_versions(doc_type,version,content_hash,url,effective_from,is_active) VALUES
   ('terms','v2026.10','<sha256hex-artefacto-terms>','https://legal.example.com/terms/v2026.10',now(),true),
   ('privacy','v2026.10','<sha256hex-artefacto-privacy>','https://legal.example.com/privacy/v2026.10',now(),true);
  REVOKE UPDATE, DELETE ON legal_versions, consent_records FROM app_role; -- solo INSERT+SELECT (+ UPDATE is_active vía role admin/migración)
  GRANT SELECT, INSERT ON consent_records TO app_role; GRANT SELECT ON legal_versions TO app_role;
  ```
  Down: `DROP TABLE consent_records, legal_versions;`. Nota: el `REVOKE` exige roles `app_role/admin_role` (si no existen en local, la migración los crea-guarda como comentario idempotente). Publicar `v2026.11` = migración `006_*` (`INSERT + UPDATE is_active` en Tx + `SELECT pg_notify('legal_active_changed','')` para purgar Redis).
  Redis: `legal:active EX 3600` (JSON activas + `fetched_at`).

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** Dominio `legal_test.go` (formatos, accepted=false→Required, mismatch→Outdated con activas, ConsentRecord invariantes). Servicio `legal_consent_test.go` (fast-fail antes de Probe con mock que aserta `Probe` no llamado en rechazo; outdated incluye activas; replay mismo RequestID no duplica por `ON CONFLICT`). `go test -race` verde.
* **Pruebas de Estrés / Carga:** k6 `scripts/load/legal_smoke.js`: `GET /legal/active` 200 VUs (p95 <50ms cache-hit, hit-rate >95%) + `POST /register` con versión vieja 20% (100% `400 OUTDATED` p95 <60ms, 0 filas). Chaos PG-legal-down → `GET` stale `200` + `POST` 100% `500` fail-closed (0 `users` huérfanos); Redis-down → `GET` DB-directo p95 <150ms. Alerta outdated simulada (>10% viejas) dispara webhook mock.
