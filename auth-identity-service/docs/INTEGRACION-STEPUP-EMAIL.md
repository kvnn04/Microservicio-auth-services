# Step-up + cambio de email E2E — bitácora 2026-10-09

> Re-autenticación scopeada y actualización de correo con doble aviso,
> contra el stack dockerizado, con usuario de prueba. Operativa general:
> [`PRODUCCION.md`](./PRODUCCION.md).

## 1. Flujo probado (verde E2E)

1. Registro + verificación de `e2e-mail@mail.test` (vía `email_queue`,
   igual que en `INTEGRACION-CREDENCIALES.md`).
2. `POST /step-up/challenge {"scope":"cred:change-email","password"}` →
   `200` con `step_up_token` (5 min, un uso, un scope).
3. `POST /email/change/start {"new_email"}` con sesión fresca → `202`
   `confirmation_sent` **sin necesidad del token** (fast-pass: `auth_time`
   ≤5 min vale como step-up; el token es alternativo, no adicional).
4. Se encolan **dos** correos: aviso al viejo (`Aviso: cambio de correo
   solicitado`) + link al nuevo (`Confirma tu nuevo correo`, 15 min,
   un solo uso). El `new_email` vuelve enmascarado (`e***@mail.test`).
5. `POST /email/change/confirm {"token"}` → `email_changed` (sin sesión:
   exige re-login).
6. Login con el nuevo (`e2e-mail2@mail.test`) → `active`; con el viejo →
   `INVALID_CREDENTIALS`.
7. Negativo `SAME_EMAIL` (cambiar al mismo) → `400` correcto.

## 2. Notas operativas / cuotas

- `POST /email/change/start`: **3/hora por usuario** (`rl:emailchange:user`).
  Agotada la cuota, todo da `RATE_LIMITED`, incluidos los casos que serían
  `SAME_EMAIL`/`EMAIL_TAKEN`. Los negativos se probaron con otro fixture.
- `EMAIL_TAKEN` (409) no se ejercitó en vivo por cuota; tiene cobertura en
  `handlers/email_change_test.go:181` (start y confirm lo chequean).
- Fixture final: `e2e-mail2@mail.test` / `T3st-E2E!Mail-2026` (el viejo
  `e2e-mail@mail.test` ya no existe como login).
