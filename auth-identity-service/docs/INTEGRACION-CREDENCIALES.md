# Passwordless + Reset E2E — bitácora 2026-10-09

> Login sin clave y recuperación de contraseña contra el stack dockerizado,
> con usuario de prueba. Operativa general: [`PRODUCCION.md`](./PRODUCCION.md).

## 1. Flujo probado (verde E2E)

1. `POST /register {"email":"e2e-pless@mail.test",...,"terms_accepted":true,
   "terms_version":"v2026.10","privacy_version":"v2026.10"}` → `pending_verification`.
   Ojo: sin `terms_accepted:true` + versiones vigentes (`GET /legal/active`)
   responde `400 TERMS_REQUIRED`.
2. Token de verificación leído de la cola (`email_queue.body_text`) →
   `POST /verify-email {"token"}` → `active`.
3. `POST /passwordless/start {"email"}` → `if_exists_sent` (genérico siempre).
   El correo trae **enlace + código** (10 min, un solo uso).
4. `POST /passwordless/verify {"code":"<8 dígitos>"}` → `200` sesión completa
   con `amr:["otp-email"]`.
5. Reuso del mismo código → `401 INVALID_OR_EXPIRED`.
6. `POST /password/reset/start` con email existente y con email inexistente →
   **respuesta idéntica** `if_exists_sent`; para el inexistente no se encola
   nada (`count(email_queue)=0`): anti-oráculo OK.
7. `POST /password/reset/confirm {"token","new_password"}` (solo enlace,
   15 min, un solo uso) → `password_changed`; reuso → `INVALID_OR_EXPIRED`.
8. Login con clave nueva → `200 active`; con la vieja → `INVALID_CREDENTIALS`.

## 2. Notas operativas

- El stack quedó apuntando a Gmail real (pruebas SMTP); los correos a
  dominios falsos igual se encolan como `sent` y el cuerpo queda en
  `email_queue`, de ahí se extrajeron los tokens para esta prueba.
  Con Mailhog (`MAIL_SMTP_ADDR=mailhog:1025`) se leerían en `:8025`.
- El correo passwordless trae token Y código; el de reset trae solo enlace.
- El usuario `e2e-pless@mail.test` queda como fixture reutilizable con clave
  `N3w-E2E!Pless-2026`.
