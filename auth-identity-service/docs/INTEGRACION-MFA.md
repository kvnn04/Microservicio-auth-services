# MFA TOTP E2E — bitácora 2026-10-07

> Enrolamiento + login con segundo factor contra el stack dockerizado,
> con app autenticadora real. Operativa general: [`PRODUCCION.md`](./PRODUCCION.md).

## 1. Flujo probado (verde E2E)

1. `POST /login` con clave → sesión normal (MFA aún apagado).
2. `POST /mfa/totp/setup` (Bearer fresco, vale como step-up) → `200` con
   `secret_b32` (una sola vez) + `otpauth_url`. Se carga manual en la app
   (nombre = email, clave = `secret_b32`).
3. `POST /mfa/totp/enable {"code":"<6 dígitos actuales>"}` → `200 enabled`
   + **10 backup codes** (se muestran una sola vez, único respaldo si se
   pierde el teléfono).
4. `POST /logout`, luego `POST /login` → **`202`** con `mfa_token`
   (desafío, no sesión) en vez de `200`.
5. `POST /mfa/verify` con `mfa_token` + código vigente → sesión completa
   (el Access resultante trae `amr:["pwd","totp"]`).
6. Login con backup code (`backup_code` en vez de `code`) también abre
   sesión y **quema ese código** (`backup_remaining -1`).
7. `POST /mfa/backup-codes/regenerate` (sesión fresca) → 10 códigos
   **nuevos** e invalida el set anterior completo.
8. `DELETE /mfa/totp` → `disabled`; `GET /mfa/status` → `enabled:false`,
   `backup_remaining:0`; el login vuelve a ser directo (sin `mfa_token`).

Probado E2E 2026-10-07 hasta el punto 8 (cuenta dejada limpia, MFA
apagado). Ventana de tolerancia TOTP ±1 paso + leeway, verificada en
`domain/auth/mfa_totp.go` (`Candidates`: `counter-1/counter/counter+1`).

Notas operativas del camino: el stack había quedado sin contenedores
(`docker compose ps` vacío); con `up -d` volvió solo porque el volumen
`pgdata` sobrevivió — dato intacto. Si el volumen se borra (`-v`), hay que
re-registrar usuarios.

## 2. Qué pasa con un token/código incorrecto

Todo error de segundo factor responde genérico, sin decir qué falló:

| Caso | Respuesta | Efecto lateral |
|---|---|---|
| Código TOTP erróneo (enable o verify) | `401 INVALID_MFA` | ninguno: el secreto staged/enrolado sigue; reintenta con el código vigente (rotan cada 30s, hay tolerancia de ±1 ventana) |
| Código con formato inválido (no 6 dígitos) | `400 VALIDATION_FAILED` | no consume nada |
| Reintento con un código **ya usado** | `401 INVALID_MFA` | anti-replay: cada código vale una vez (`mfa_used_counters`, ventana 90s) |
| `mfa_token` ausente/inválido en verify | `401` | el desafío expira a los 5 min; tras eso, nuevo login |
| Backup code erróneo | `401` | no consume; los intentos fallidos no queman códigos ajenos |
| Backup code correcto | `200` sesión | **ese código muere** (`backup_remaining -1`; aviso al agotarse) |
| Enable sin setup previo / secreto vencido | `400 NO_STAGED_SECRET` | repetir `setup` (el staged es efímero) |
| Enable con MFA ya activo | `400 MFA_ALREADY_ENABLED` | idempotente por estado, no por reintento |
| Desactivar el último factor | `400 LAST_AUTH_FACTOR` | exige vincular otro acceso antes (no quedas sin entrada) |
| Flood al verify | `429 + Retry-After` | 20/min/IP; no quema nada |

Regla práctica: ante cualquier `401` de MFA, pide **un código nuevo** al
usuario y reintenta una vez; si repite, manda a re-login (nuevo `mfa_token`).
Nunca reintentes el mismo código: el anti-replay lo rechaza aunque sea el
"correcto" de hace un minuto.
