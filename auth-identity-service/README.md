# auth-identity-service — Guía de consumo (MVP)

> Centro de identidad y acceso: registro, login (con MFA), sesiones,
> tokens, recuperación y gestión de cuenta. Lee esto para **usarlo**;
> para operarlo en producción ver [`docs/PRODUCCION.md`](./docs/PRODUCCION.md).

**Estado MVP: listo para usar** (módulos 1–4 completos y verificados E2E).
Condiciones previas: claves reales en `.env` (ver `.env.example`),
worker corriendo y SMTP configurado. Límites conocidos al final (§10).
Bitácoras de pruebas vivas: [`docs/INTEGRACION-SMTP.md`](./docs/INTEGRACION-SMTP.md) ·
[`docs/INTEGRACION-GOOGLE.md`](./docs/INTEGRACION-GOOGLE.md) ·
[`docs/INTEGRACION-MFA.md`](./docs/INTEGRACION-MFA.md) ·
[`docs/INTEGRACION-CREDENCIALES.md`](./docs/INTEGRACION-CREDENCIALES.md) ·
[`docs/INTEGRACION-LINK.md`](./docs/INTEGRACION-LINK.md) ·
[`docs/INTEGRACION-SESIONES.md`](./docs/INTEGRACION-SESIONES.md) ·
[`docs/INTEGRACION-STEPUP-EMAIL.md`](./docs/INTEGRACION-STEPUP-EMAIL.md).

---

## 1. Puesta en marcha (2 comandos)

```bash
cp .env.example .env   # completa las claves CAMBIAR
docker compose up -d --build
curl http://localhost:8080/healthz   # ok
```

Esto levanta: `postgres` + `redis` + `migrate` (01–19 automático) + `api`
+ `worker` + `mailhog` (bandeja dev en http://localhost:8025).
Con Kafka: `docker compose --profile kafka up -d --build`.
Base URL de aquí en más: `http://localhost:8080`.

## 2. Convenciones (valen para todo)

- Todo es JSON: éxito `{success:true, data:{...}}`, error
  `{success:false, error:{code, message, details:[]}}`.
- Header `X-Request-ID: <uuid>` recomendado (trazabilidad; si falta o es
  inválido el servidor genera uno y lo devuelve en el response).
- Respuestas sensibles traen `Cache-Control: no-store`.
- Códigos comunes: `200/201/202` ok · `400` validación · `401` auth inválida
  (mensaje siempre genérico, no distingue causa) · `404` no encontrado ·
  `429 + Retry-After` rate-limit · `413` body grande · `500` error interno.
- **Nativo (apps móviles/desktop):** manda `X-Client-Type: native` y el
  refresh llega en el **body** (`refresh_token`); sin ese header va en
  **cookie** `HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/refresh`.

## 3. Modelo de sesión (léelo una vez)

- **Access JWT** (15 min, Ed25519): va en `Authorization: Bearer <jwt>`.
  Contiene `sub/sid/jti/amr/roles` — sin email ni PII.
- **Refresh opaco** (32B, cookie o body): sliding 30 días, absoluto 90 días.
  **Single-use estricto**: cada uso lo rota (mismo `sid`, nuevo `jti`).
- Qué hacer ante cada `401` del refresh:
  | Código | Significado | Acción del cliente |
  |---|---|---|
  | `INVALID_REFRESH` | token desconocido | login de nuevo |
  | `SESSION_EXPIRED` | venció sliding/absoluto | login de nuevo |
  | `FAMILY_REVOKED` | cerraste sesión en otro lado | login de nuevo |
  | `SESSION_COMPROMISED` | reuso detectado: **cerramos todo** | login + banner de incidente + sugerir cambio de clave |
  | `CONCURRENT_ROTATION` (`409`) | race legítimo | re-lee el jar y **reintenta UNA vez** tras 200ms (ver §5) |

## 4. Flujo principal: registro → verificación → login → refresh → logout

```bash
RID=$(uuidgen)

# 1. Registro (siempre 201 genérico, exista o no la cuenta: anti-enumeración)
curl -X POST localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' -H "X-Request-ID: $RID" \
  -d '{"email":"usuaria@ejemplo.com","password":"Str0ng!Passw0rd-2026",
       "terms_accepted":true,"terms_version":"v2026.10","privacy_version":"v2026.10"}'
# → {"success":true,"data":{"status":"pending_verification",...}}
# Le llega email "Verifica tu cuenta" con link + código (8 dígitos, 15 min).

# 2. Verificar (link del email o código manual)
curl "localhost:8080/api/v1/auth/verify-email?token=<b64url-del-email>" \
  -H "X-Request-ID: $(uuidgen)"
# → {"success":true,"data":{"status":"active",...}}
# ¿No llegó? POST /api/v1/auth/resend-verification {"email":"..."}
# (siempre 202 genérico; cooldown 60s, cuota 5/24h)

# 3. Login
curl -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' -H "X-Request-ID: $(uuidgen)" \
  -d '{"email":"usuaria@ejemplo.com","password":"Str0ng!Passw0rd-2026"}'
# → 200 con access_token (úsalo como Bearer) + refresh en cookie
# → 202 con mfa_token si tiene TOTP (ver §6)

# 4. Usar la API (ejemplo: ver mis sesiones)
curl localhost:8080/api/v1/auth/sessions \
  -H "Authorization: Bearer <access_token>"

# 5. Renovar (antes de los 15 min, o cuando el access expire)
curl -X POST localhost:8080/api/v1/auth/refresh \
  -H "X-Request-ID: $(uuidgen)" --cookie "refresh_token=<refresh>"
# → 200 rotated (mismo sid) + cookie nueva. El viejo queda muerto.

# 6. Cerrar sesión actual
curl -X POST localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer <access_token>" -H "X-Request-ID: $(uuidgen)"
# → 200 logged_out (o already_logged_out si ya estaba muerta)
```

## 5. Referencia de endpoints

**Registro y verificación**

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/v1/auth/register` | no | Crear cuenta (201 genérico siempre). Body ≤32KB |
| POST · GET(`?token=`) | `/api/v1/auth/verify-email` | no | Activar con link u OTP (`{"token"}` o `{"code"}`) |
| POST | `/api/v1/auth/resend-verification` | no | Reenviar email (202 genérico siempre) |
| GET | `/api/v1/legal/active` | no | Versiones vigentes de términos/privacidad |

**Login y factores**

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/v1/auth/login` | no | Login (200 sesión · 202 `mfa_token` si tiene TOTP · 401 genérico) |
| POST | `/api/v1/auth/passwordless/start` | no | Envía secreto al email |
| POST | `/api/v1/auth/passwordless/verify` | no | Login sin contraseña (también `GET /passwordless`) |
| GET · GET-callback | `/api/v1/auth/federated/{provider}/authorize` · `.../callback` | no | Login con Google (solo `google`) |
| POST | `/api/v1/auth/mfa/totp/setup` | sí + step-up | Inicia enrolamiento TOTP (devuelve secreto/QR) |
| POST | `/api/v1/auth/mfa/totp/enable` | sí + step-up | Confirma enrolamiento |
| POST | `/api/v1/auth/mfa/verify` | `mfa_token` | Completa login con TOTP o código de respaldo |
| DELETE | `/api/v1/auth/mfa/totp` | sí + step-up | Desactiva TOTP |
| GET | `/api/v1/auth/mfa/status` | sí | Estado MFA |
| POST | `/api/v1/auth/mfa/backup-codes/regenerate` | sí + step-up | Nuevos códigos de respaldo (los viejos mueren) |
| POST | `/api/v1/auth/step-up/challenge` | sí | Prueba de identidad fresca para acciones sensibles |
| POST · GET-callback | `/api/v1/auth/federated/{provider}/link` | sí + step-up | Vincular Google a cuenta existente |
| DELETE · POST-unlink · GET-linked | `/api/v1/auth/federated/{provider}` … | sí + step-up | Desvincular / listar vinculadas |

**Credenciales**

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST · GET | `/api/v1/auth/password/reset/start` · `/reset/confirm` · `/password/reset` | no | Recuperación por email (link de 1 uso) |
| POST | `/api/v1/auth/password/change` | sí (+ actual o step-up) | Cambio con sesión (revoca las demás, conserva la actual) |
| POST · POST/GET-confirm | `/api/v1/auth/email/change/start` · `/confirm` · `/email/change` | sí + step-up | Cambio de email con doble aviso |

**Sesiones y tokens**

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/v1/auth/refresh` | refresh¹ | Rotar par (ver §3; 409 = reintentar 1 vez) |
| GET | `/api/v1/auth/sessions` | sí | Inventario propio enmascarado (`ip 203.0.113.xxx`, `current`) |
| DELETE | `/api/v1/auth/sessions/{sid}` | sí | Cerrar OTRA sesión (la propia → `400 USE_LOGOUT`; ajena/muerta → `404` idéntico) |
| POST | `/api/v1/auth/logout` | sí | Cerrar la actual (idempotente) |
| POST | `/api/v1/auth/logout-global` | sí | Cerrar TODO (incluida la actual; útil ante robo) |

¹ Sin Bearer: el refresh (cookie o `{"refresh_token"}`) manda.
Operativos: `GET /healthz` (ok) · `GET /metrics` (Prometheus).

## 6. MFA en 3 pasos (para tu front)

1. Loguea: si hay TOTP recibes `202 {mfa_token, methods:["totp"]}`.
2. Pide el código de la app y llama `POST /mfa/verify` con el `mfa_token`.
3. Recibes la sesión normal. Guarda los backup codes del setup en lugar seguro (son de un solo uso y se agotan avisando).

## 7. Rate limits (lo que tu cliente debe respetar)

`register` 10/min/IP · `login` 10/min/IP + 5/min/cuenta (+bloqueo progresivo) · `refresh` 30/min/IP + 10/min/token · `logout` 30/min/user · `logout-global` 5/hora/user · `sessions:list` 60/min · `revoke-one` 20/hora · `verify` 10/min/IP · `resend` con cooldown 60s + cuota 5/24h. Todo `429` trae `Retry-After`: respétalo con backoff en vez de reintentar en caliente.

## 8. Errores que sí o sí maneja tu front

- `401 INVALID_CREDENTIALS` en login (genérico a propósito: no distingue usuario/clave/estado).
- `STEP_UP_REQUIRED` (+ `max_age`): re-autenticar antes de acciones sensibles.
- `USE_LOGOUT`: quisiste cerrar la sesión actual por el endpoint de ajenas → usa `POST /logout`.
- `SESSION_COMPROMISED`: muestra login + banner de incidente (ya cerramos todo + P1 + email al usuario).
- Sesión expirada en cualquier endpoint negocio → manda a login (o prueba `POST /refresh` primero si tienes refresh).

## 9. Integración típica (web SPA)

1. Formularios register → muestra "revisa tu email" → el link activa → login.
2. Guarda access en memoria (nunca en `localStorage`) y deja la cookie HttpOnly al navegador.
3. Interceptor HTTP: ante `401` no-login, intenta **un** `POST /refresh`; si da `401` → login; si `409` → espera 200ms y reintenta **una vez** con el jar actualizado.
4. `logout` al salir; ofrece "ver sesiones" (`GET /sessions`) y "cerrar todo" ante sospecha.

## 10. Límites conocidos (léelo antes de prometer de más)

- **Sin JWKS/discovery propio**: terceros no validan Access offline; te llaman a esta API o comparten clave por vault (ver `docs/PRODUCCION.md`).
- **Sin borrado de cuenta**: anótalo en roadmap por compliance.
- Los gateways (`valid_after`/denylist) los implementas tú del otro lado.
- SLO de latencia medidos en laptop: re-validar en staging.
- Operación completa (secretos, backups, alertas, rotación de claves, retención): `docs/PRODUCCION.md`.
