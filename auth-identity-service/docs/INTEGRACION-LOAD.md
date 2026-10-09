# Carga k6 — bitácora 2026-10-09

> 24 scripts en `scripts/load/` (k6 v2.1.0, laptop Windows + Docker).
> Operativa general: [`PRODUCCION.md`](./PRODUCCION.md).

## 1. Preparación (qué se hizo antes de correr)

- Los 5 JSON generados (`bearers*.json`, `pairs.json`) se sacaron del
  tracking (`git rm --cached`, ~300KB); se regeneran por corrida.
- Los 20 scripts que apuntaban a `:8081/:8082` se retargetearon a `:8080`.
- Siembra: 8750 usuarios bulk (hash Argon2 compartido) + 2000 con pool
  `k6e-*`; 6000 tokens de verificación directos en DB (hash `hex(sha256)`,
  con TTL extendido a 3h solo para la prueba — el path de lectura es el
  mismo); MFA habilitado a 450 usuarios vía API con TOTP calculado
  (0 fallos), cosechando 2500 backup codes.
- Stack en modo Mailhog (cero mails reales) para toda la corrida.

## 2. Resultados (lo importante)

| Script | Escala | Checks | Latencia | Veredicto |
|---|---|---|---|---|
| register_smoke | 10VU/30s | 100% | p95 10.6s | OK funcional; Argon2 satura laptop |
| uniqueness_timing | — | 100% | p95 4.7s | OK |
| harvest_abuse | 62 iters | 100% | — | 10×201 → 52×429 con Retry-After |
| legal_smoke | — | 100% | p95 135ms | OK (8% "failed" son 400 esperados) |
| login_smoke | 5VU | 100% (5 ramas) | good p50 1.6s | OK; a 15VU colapsa (capacidad) |
| verify_smoke | 15VU/45s | 99.9% | p50 100ms p95 333ms (umbral <300) | OK, marginal en p95 |
| pless start | 50VU | 100% (15623) | p95 ~400ms | OK |
| pwdreset start | 50VU | 100% (27165) | p95 316ms | OK |
| mfa_smoke | 3VU | 100% (incl. replay) | p95 342ms | OK |
| backup_smoke | — | parcial | — | Cuentas frescas pasan; pools reusados caen por buckets de cuenta (ver §3) |
| rotation_iso | 10VU/200it | 199/200 | p50 75ms p95 362ms (umbral <250) | OK |
| rotation_race | 2VU/20it | 95% | — | El 4.º reuso por bearer da COMPROMISED (diseño); el script esperaba nunca |
| sessions_iso | 8VU/100it | 100% | list p95 2.4s, revoke p95 567ms | OK; list lento bajo carga |
| sessions_smoke | 8VU | 100% | — | OK |
| logout_iso | 10VU/200it | 100% | p95 146ms | OK |
| logout_smoke | 10VU | 100% | — | OK |
| logout_global_iso | 10VU/200it | 100% | p95 180ms | OK |
| logout_global_smoke | 8VU | 92% | — | Falla el borde de cuota 5/hora/usuario en pool compartido |
| link_smoke | 5VU | 100% | initiate p95 2.8s, list p95 213ms | OK (exige Bearer con <5min por fast-pass) |
| federated_smoke | — | — | — | BLOQUEADO: exige pares code/state de Google real |
| step-up | 8+12VU | 100% | challenge p95 2.5s, guard p95 524ms | OK |
| pwdchange | 5VU | 100% | p95 5.9s (doble Argon2) | OK |
| emailchange start | sonda | 100% | ramas 202/400/409 OK | OK; a escala excede su cuota 3/hora/usuario |
| issue | 8VU | 100% | p95 7-10s (login dentro) | OK |

## 3. Hallazgos (lectura obligada antes de repetir)

1. **Los pools son de un solo uso por ventana**: re-correr sobre las mismas
   cuentas degrada resultados (buckets 5/min por cuenta, 3/h en email-change,
   10/h en link). Para repetir: pool fresco o esperar la ventana.
2. **Los Bearer viven 15 min y el fast-pass 5 min**: generar fixtures y
   correr enseguida; si no, todo da 401 y parece un bug (no lo es).
3. **Escenarios sin `X-Forwarded-For`** (pless-verify, pwdreset-confirm):
   comparten la IP del socket → 429 a partir de ~10 req. En k6 distribuido
   no pasa; en localhost sí. Limitación del harness, no del servicio.
4. **Bug menor real**: el bloqueo progresivo usa `RemoteAddr` con puerto
   (`middleware/rate_limit.go:clientIP`), así que `blocked:ip:*` nunca
   matchea una conexión nueva — el bloqueo de 15 min no llega a aplicarse.
   Evidencia: `harvest_abuse` nunca activa `blocked_probe`.
5. **Cuello de laptop**: Argon2 (`m=64MB,t=3,p=4`) × VUs concurrentes domina
   todas las latencias con login dentro. Los p95 de register/login/issue/
   pwdchange miden la máquina, no el servicio. Stress real requiere staging
   o Argon2 reducido en env de prueba.
