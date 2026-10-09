# Sesiones a fondo E2E — bitácora 2026-10-09

> Listado, revoke selectivo, rotación con reuso y logout global contra el
> stack dockerizado, con usuario de prueba. Operativa general:
> [`PRODUCCION.md`](./PRODUCCION.md).

## 1. Flujo probado (verde E2E)

1. Doble `POST /login` → `GET /sessions` lista ambas (`sid`, `device_label`,
   `ip_masked` con último octeto `xxx`, `current:true/false`, `location:null`
   sin geo).
2. `DELETE /sessions/{sid}` → `revoked`; el listado ya no la trae.
3. `POST /refresh {"refresh_token"}` (nativo con `X-Client-Type: native`,
   si no el par nuevo viaja en cookie HttpOnly y el body viene vacío) →
   `200 rotated` con par nuevo.
4. Reuso del refresh padre: 1.º–3.º → `409 CONCURRENT_ROTATION` (reintentable,
   ventana de gracia anti-flap); 4.º → `401 SESSION_COMPROMISED` (familia
   muerta); 5.º → `FAMILY_REVOKED`. Escalada exacta según diseño.
5. `POST /logout-global` → `logged_out_global`; `GET /sessions` → `total:0`.
   El access JWT sigue validando (stateless) pero sin sesiones.

## 2. Notas operativas

- Ráfagas de login disparan `429 RATE_LIMITED` (SEC-02 vive): espaciar
  logins de prueba ~1 min o rotar usuarios.
- Nativo (`X-Client-Type: native`) = par en body; web = refresh en cookie
  `refresh_token` (`Path=/api/v1/auth/refresh`, HttpOnly, Lax). El access
  nunca va en cookie.
- Fixture: `e2e-pless@mail.test` / `N3w-E2E!Pless-2026` (0 sesiones al cierre).
- **Nota 2026-10-09:** fixture eliminado de la DB por corridas E2E (borran
  tablas). Re-registrar si se necesita.
