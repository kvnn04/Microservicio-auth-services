# Integración SMTP real (Gmail) — bitácora 2026-10-07

> Cómo se habilitó el envío real de correos, qué se cambió y cómo se probó.
> Operativa general: ver [`PRODUCCION.md`](./PRODUCCION.md).

## 1. Problema inicial

El mailer solo sabía SMTP **anónimo** (`smtp.SendMail` con auth `nil`):
alcanzaba para Mailhog pero ningún relay real (Gmail incluido) lo acepta.
Además las variables `SMTP_USER`/`SMTP_PASS` no existían en el sistema.

## 2. Cambios implementados (sin regresión)

| Archivo | Cambio |
|---|---|
| `internal/adapter/colas/kafka/mailer.go` | `NewEmailMailerWithAuth(pool, addr, from, user, pass)` + `smtpAuth()` con `PlainAuth` (STARTTLS). Sin usuario = anónimo como antes |
| `cmd/worker/main.go` | Lee `SMTP_USER`/`SMTP_PASS` del entorno |
| `compose.yml` | `SMTP_USER`/`SMTP_PASS` interpolados al worker |
| `.env.example` | Vars + notas Gmail (puerto 587, app password, remitente pelado) |
| `docs/PRODUCCION.md` | Checklist y tabla actualizadas |

Sin `SMTP_USER` el comportamiento es idéntico al anterior (Mailhog).

## 3. Configuración válida (Gmail)

```
MAIL_SMTP_ADDR=smtp.gmail.com:587   # 587 con STARTTLS (NO 465: sin TLS implícito)
MAIL_FROM=<tu-cuenta>@gmail.com     # pelada: es remitente envelope, Gmail la exige igual a la cuenta
SMTP_USER=<tu-cuenta>@gmail.com     # idem (tienen que coincidir)
SMTP_PASS=<contraseña de aplicación de 16 letras>  # requiere 2FA; NUNCA la clave normal
```

Límite aprox. 500 envíos/día. Si cae en spam: normal en remitente nuevo;
en producción usar dominio propio (SPF/DKIM) o proveedor transaccional.

## 4. Verificación E2E realizada (stack dockerizado, sin Kafka)

1. Registro → `email_queue pending` → worker → `sent`.
2. Email "Verifica tu cuenta" (link + código) recibido en bandeja real.
3. Link → `active` → login OK con la sesión creada.
4. Cambio de clave → `password_changed` + email de aviso recibido; vieja clave `401`, nueva OK.
5. Logout → `logged_out` → replay `already_logged_out`.

## 5. Diagnóstico aprendido (reutilizable)

- `email_queue` en `pending` con `attempts` creciendo = el relay **llega**
  al SMTP pero es **rechazado** (credencial muerta/revocada o bloqueo de
  Google). Red OK se confirma con `Test-NetConnection smtp.gmail.com -Port 587`.
- `failed` tras 25 intentos = el worker deja de insistir (rearmar la fila a
  `pending` para reintentar tras corregir credenciales).
- Credenciales expuestas en chat/archivos: rotar la app password en Google
  y reemplazarla (este `.env` no se commitea, pero la higiene manda).
