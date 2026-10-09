# PRODUCCIÓN — Runbook de despliegue y operación

> Stack 100% dockerizado: `cp .env.example .env` → completar claves →
> `docker compose up -d --build` → servicio sano. Esta guía cubre el
> checklist previo, la operación diaria y los límites conocidos.

## 1. Levantada completa desde cero

```bash
cp .env.example .env        # completa las claves CAMBIAR (ver §2)
docker compose up -d --build
docker compose ps           # postgres/redis/migrate(ok)/api/worker/mailhog
curl http://localhost:8080/healthz          # ok
curl http://localhost:8080/api/v1/legal/active  # versiones legales (seed auto)
# Bandeja de correos dev: http://localhost:8025
```

Orden de arranque garantizado por compose: `postgres/redis (healthy)` →
`migrate` (01–19 en `scripts/migrations`, idempotente; los archivos se
llaman `NN_YYYYMMDD_SSS_*.sql` porque la herramienta migrate exige prefijo
numérico antes del primer `_`) → `api` + `worker`. Cada archivo viaja
COMPLETO en una query (sin `x-multi-statement`: su splitter rompería los
`;` de comentarios y bloques `DO $$`).
Apagado: `docker compose down` (con `-v` borra la DB local: **irreversible**).

Smoke mínimo post-deploy (register → login → refresh → logout):

```bash
RID=$(uuidgen)
curl -X POST localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" -H "X-Request-ID: $RID" \
  -d '{"email":"smoke@tu-dominio.com","password":"Sm0ke!Valida-2026","terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}'
```

## 2. Checklist previo a producción

| # | Ítem | Detalle |
|---|------|---------|
| 1 | Claves reales en vault | `SESSION_SIGNING_KEY` (generar: `go run ./scripts/gen_ed25519 [kid]`), `MFA_SECRETS_KEY` (64 hex), `PASSWORD_PEPPER` + `SESSION_SECRET`. Jamás en el repo (`.env` ignorado). Sin `MFA_SECRETS_KEY` la API no arranca (fail-fast intencional). |
| 2 | Worker corriendo | Sin worker no salen emails y `outbox` crece sin drenar. En compose ya va incluido. |
| 3 | Kafka: sí o no | **Con Kafka**: `docker compose --profile kafka up -d` (relay drena `outbox`). **Sin Kafka** (válido para MVP sin consumidores): verificado en código — el relay reintenta, marca `failed` tras ~50 intentos y **no crashea ni bloquea**; el mailer es independiente (SMTP directo) y sigue enviando. Costo: `outbox` acumula filas `failed` (ver §5 retención). |
| 4 | SMTP real + auth | `MAIL_SMTP_ADDR`/`MAIL_FROM`/`SMTP_USER`/`SMTP_PASS` con relay verificado; el worker soporta `PlainAuth` (STARTTLS, puerto **587** — no 465: sin TLS implícito). Gmail: 2FA + contraseña de aplicación (no tu clave), ~500/día, remitente = tu misma dirección pelada. TLS se termina en tu proxy/LB delante de `:8080` (el servicio sirve HTTP plano). Bitácora de la integración verificada: `docs/INTEGRACION-SMTP.md`. |
| 5 | Backups PG + Redis | `pg_dump` programado de `auth_db`; volumen `pgdata` en disco durable. Redis: la verdad vive en PG (caché reconstruible), pero configura `appendonly` si quieres sobrevivir reinicios sin rehidratación. |
| 6 | Migraciones | Aplicadas por el servicio `migrate` en cada `up` (idempotente). Verifica versión con `SELECT version FROM schema_migrations ORDER BY version;` (debe llegar a la 19). |
| 7 | Alertas | Mínimo: `reuse_detected_total{severity="critical"}` → pager P1 (robo de sesión confirmado); `rate(http 5xx)`; `postgres/redis down`; cola `email_queue pending` creciendo. Métricas en `:8080/metrics`, salud en `:8080/healthz`. |
| 8 | p95 en staging | Los SLO (`logout` 150ms, `logout-global` 300ms, `refresh` 250ms, `sessions` 120/200ms) se midieron en laptop contra Docker Desktop. Re-valídalos en staging antes de firmar el SLO (SES-01 lo dejó como condición documentada). |
| 9 | `POSTGRES_PASSWORD` | Cambiar el default `auth/auth` (ver `.env.example`). |

## 3. Credenciales necesarias (resumen)

| Variable | Para qué | Formato / cómo generarla |
|---|---|---|
| `SESSION_SIGNING_KEY` | Firma Ed25519 de Access JWT | base64 32B/64B. `go run ./scripts/gen_ed25519 [kid]` |
| `SESSION_SIGNING_KID` | `kid` del header JWT | texto libre, cámbialo en cada rotación (`2026-11-a`) |
| `MFA_SECRETS_KEY` | Cifrado AES-256-GCM de secretos TOTP | 64 hex (`openssl rand -hex 32`). Obligatoria |
| `PASSWORD_PEPPER` | Endurece hashes Argon2/códigos | cadena larga aleatoria; rotación con `PEPPER_PREV` |
| `SESSION_SECRET` | Pre-tokens MFA + compat legacy HS256 | 32+ caracteres aleatorios |
| `POSTGRES_PASSWORD` | DB del compose | larga aleatoria |
| `FEDERATED_GOOGLE_CLIENT_SECRET` | Login con Google (opcional) | consola Google Cloud (si vacío, ese flujo da error y el resto funciona) |
| `MAIL_SMTP_ADDR` / `MAIL_FROM` / `SMTP_USER` / `SMTP_PASS` | Envío de correos | relay verificado + remitente válido + usuario/pass SMTP (vacío = anónimo, solo dev). Gmail: `smtp.gmail.com:587` + app password |

## 4. Rotación manual de claves (no hay automática: CU-CRYP-02 pendiente)

1. Genera el par nuevo offline: `go run ./scripts/gen_ed25519 2026-XX-a` (privada al vault, pública reservada para el futuro JWKS).
2. (Opcional, inventario) actualiza `signing_keys`: `UPDATE signing_keys SET retired_at=now() WHERE kid='<viejo>'; INSERT INTO signing_keys(kid, pub_b64) VALUES ('<nuevo>','<pub>');`
3. Despliega con `SESSION_SIGNING_KEY=<nueva>` + `SESSION_SIGNING_KID=<nuevo>` (rolling restart de `api`).
4. **Impacto real (acotado)**: los Access en circulación mueren al instante (`kid` desconocido, vida ≤15min); las sesiones **sobreviven vía Refresh** (el nuevo `POST /refresh` ya firma con la clave nueva). Sin corte masivo.
5. Destruye la privada vieja y agenda la próxima (sugerido: 90 días).

## 5. Retención (tablas que crecen sin purga automática)

El worker actual NO purga (relay + mailer + reconciliador de verificación). Programa este mantenimiento (cron semanal sugerido):

```sql
DELETE FROM outbox WHERE status = 'sent' AND created_at < now() - INTERVAL '30 days';
DELETE FROM outbox WHERE status = 'failed' AND created_at < now() - INTERVAL '7 days';
DELETE FROM email_queue WHERE status = 'sent' AND created_at < now() - INTERVAL '30 days';
DELETE FROM revoked_jtis WHERE expires_at < now();  -- denylist ya vencida
```

## 6. Límites conocidos (no sorpresas)

- **Email de verificación inicial**: RESUELTO 2026-10-07 (specs CU-REG-01
  F-16..F-18 + CU-REG-02 V-16..V-17). El registro encola `email_queue`
  (link+OTP) en la misma Tx (fail-closed) y el worker lo entrega por SMTP
  sin depender de Kafka (probado: Mailhog recibe "Verifica tu cuenta" y el
  link activa → login OK). El evento Kafka `auth.email.verification_requested`
  sigue disponible para consumidores externos.
- Sin endpoint JWKS/discovery propio (CU-CRYP-01): otros servicios no pueden validar Access offline; llaman a esta API o comparten clave por vault.
- Sin API de borrado de cuenta (CU-SEC-05): anótalo en roadmap con fecha por compliance.
- Gateways (`valid_after`/denylist) y alertas se implementan del lado consumidor con los datos/eventos de este servicio.
- Ventana residual documentada: pre-tokens de otro `aud` sobreviven ≤TTL a un corte global (mitigación total en CU-SEC-04).
