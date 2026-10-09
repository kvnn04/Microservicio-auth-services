# Vinculación Google E2E — bitácora 2026-10-09

> Link/unlink de cuenta Google a cuenta local existente contra el stack
> dockerizado, con OAuth real. Operativa general: [`PRODUCCION.md`](./PRODUCCION.md).

## 1. Flujo probado (verde E2E)

1. `POST /login` fresco (fast-pass 5 min) + `POST /federated/google/link`
   con `{"current_password":"..."}` → `200` con `url` (Google OAuth con
   PKCE S256 + `state`, 10 min) y `expires_in:600`.
   Sin `current_password` responde `401 INVALID_STEP_UP` (RN-03: el link
   exige clave aunque haya step-up token/frescura).
2. El usuario autoriza en navegador → Google redirige a
   `.../link/callback?code=...&state=...`. El navegador muestra
   `401 UNAUTHORIZED` (no manda Bearer): normal. Se copia `code+state`
   de la barra de direcciones y se ejecuta el callback autenticado.
3. `GET .../link/callback?code&state` (Bearer) → `{"status":"linked"}`.
4. `GET /federated/linked` → `[{provider:google, email_masked, sub_hash,
   linked_at}]`. El `sub` nunca se expone (solo hash 8).
5. `POST /federated/google/unlink {"current_password"}` → `unlinked`;
   `GET /linked` → `[]`. Cuenta dejada como estaba.

## 2. Notas operativas

- El link usa redirect URI **distinta** a la del login:
  `.../federated/google/link/callback`. Hay que registrarla aparte en
  Google Cloud (si no: `400 redirect_uri_mismatch`).
- La cuenta Google vinculada era institucional (`hd=pioix.edu.ar`), distinto
  email que la local: el match es por `state` ligado al usuario, no por email.
- Ventana: login fresco + state 10 min; si expira, re-iniciar desde el paso 1.
