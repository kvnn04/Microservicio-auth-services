# Integración Google OAuth (federado) — bitácora 2026-10-07

> Prueba real del login federado contra Google + los dos problemas
> encontrados en el camino y sus fixes. Operativa general:
> [`PRODUCCION.md`](./PRODUCCION.md).

## 1. Configuración necesaria (cuenta Google, una vez)

1. Google Cloud Console → APIs y servicios → Credenciales → ID de cliente
   OAuth (aplicación web).
2. En **URIs de redirección autorizados** agregar exactamente:
   `http://localhost:8080/api/v1/auth/federated/google/callback`
   (en prod, la URL pública equivalente).
3. Copiar ID + secreto a `.env` (`FEDERATED_GOOGLE_CLIENT_ID/SECRET`) y
   recrear la API (`docker compose up -d api`).

## 2. Flujo probado (verde E2E)

`GET /federated/google/authorize` (+ términos aceptados) → 302 a Google
con PKCE S256 + `nonce` + `state` → login en navegador → callback local →
`200 {status:active, access_token (EdDSA, kid vigente), sid}` + usuario
`ACTIVE` e identidad `google` vinculada en DB.

## 3. Problemas encontrados

### 3a. `400 redirect_uri_mismatch` (config, no código)

Google rechaza el callback si no está en la lista de URIs autorizados
del cliente OAuth. Fix: agregarlo en la consola (ver §1). Tarda 1–2 min
en propagar; los `state` son de un solo uso (si expira, generar link nuevo).

### 3b. `VALIDATION_FAILED` (`request_id INVALID_FORMAT`) en el callback (bug real, fixeado)

**Causa**: el navegador no envía header `X-Request-ID`; el middleware
`RequestID` generaba el ID solo en contexto/respuesta pero no lo devolvía
al header del request, y ~20 handlers (incluido el callback federado) lo
leen del header → llegaba vacío → el servicio lo rechazaba.
Afectaba a todos los flujos de navegador (callbacks OAuth, magic links).

**Fix** (`internal/adapter/http/middleware/request_id.go`): normalizar
siempre —parsea o genera— y setearlo en header + contexto + respuesta.
Sin cambio de comportamiento para clientes API (mismo valor de vuelta).
Verificado: suites `handlers/middleware/service` verdes + callback real OK.
