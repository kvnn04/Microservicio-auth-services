# Spec: CU-CRYP-01 - Publicación de Metadatos y Claves Públicas (JWKS Discovery)

## 1. Contexto y Propósito
Exponer lo público para verificación descentralizada: `/.well-known/jwks.json` (JWK OKP multikey) + `/.well-known/openid-configuration` (doc mínimo), con cache 10min + ETag y norma refetch-ante-kid-desconocido. Las privadas jamás salen del signer/KMS (test anti-fuga en CI). Base de CU-CRYP-02 (rotación) y CU-CRYP-03 (desastre).

Decisiones (2026-10-05, todas Recommended):
- Q1 Ambos endpoints, Q2 OKP Ed25519 multikey (actual+overlap, kid desc), Q3 `max-age=600 + must-revalidate + ETag` + refetch-on-unknown-kid, Q4 Solo-públicas en memoria + scanner anti-`d/priv/seed`, Q5 Memoria + reload-hook + 100/min sin auth, Q6 Discovery mínimo OIDC, Q7 `KeyDirectory` + extiende `signing_keys` (sin privada en PG: pub + `priv_ref`).

## 2. Actores y Precondiciones
* **Actores:** Servicios/Gateway (verificadores offline), Microservicio Auth (publicador).
* **Precondiciones:**
  * ≥1 clave activa en `signing_keys` (`retired_at IS NULL`) con `pub_b64` válida 32B + `kid` único + `priv_ref` (KMS/env, nunca PG-plaintext).
  * Memoria `KeyDirectory` cargada al arranque (si 0 claves → `/healthz` `degraded` + JWKS `500` + P1, fail-fast documentado).

## 3. Flujo Principal (Happy Path)
1. Consumidor envía `GET /.well-known/jwks.json` (sin auth, con `If-None-Match` si cachea). El back (memoria, sin DB por request) responde `200 {keys:[{kty:OKP, crv:Ed25519, x:<b64url-pub>, use:sig, kid, alg:EdDSA}, ...]}` ordenadas `kid DESC` (actual primero, previas en overlap después) + headers `Cache-Control: public, max-age=600, must-revalidate` + `ETag: "<hex(sha256(canonical keys))>"` (+ `304` si `If-None-Match` coincide, sin body).
2. SDK estándar arranca en `GET /.well-known/openid-configuration` → `200 {issuer, jwks_uri, authorization_endpoint, token_endpoint, id_token_signing_alg_values_supported:[EdDSA], scopes_supported, response_types_supported:[code], grant_types_supported:[authorization_code,refresh_token,client_credentials]}` (URLs exactas del servicio por env `PUBLIC_BASE_URL`; `Cache-Control: public, max-age=3600` — cambia poco).
3. El consumidor cachea JWKS (10min) y verifica Access/M2M offline (firma `kid` + `iss/aud/exp` + `roles_ver`/`valid_after` según su dominio). Ante `kid` desconocido DEBE refetchear (sin cache negativa) y reintentar UNA vez antes de `401` (norma cliente documentada en contracts + ejemplo).
4. Rotación (CU-CRYP-02) publica evento interno `keys.rotated` → `KeyDirectory.Reload()` (<1s) + nuevo `ETag` (los clientes con cache vieja siguen con `kid` previo válido hasta su retiro; los que ven `kid` nuevo refetchean).

## 4. Flujos Alternativos y Excepciones
* **4.1. Sin claves / DB-keys down:** 0 activas → `500 JWKS_UNAVAILABLE` (sin `keys:[]` vacío que rompa verificadores en `kid` miss silencioso) + P1 + `jwks_keys_count=0`. Arranque sin claves → no levanta tráfico (fail-fast `/ready`).
* **4.2. `kid` desconocido persistente:** tras refetch sigue miss (token forjado o `kid` inventado) → el CONSUMIDOR da `401` (no Auth; Auth solo sirve el set). Auth nunca valida por el consumidor aquí.
* **4.3. Rate:** `100/min/IP` (matriz SEC-02) → `429` (sin auth igual). `/openid-configuration` mismo bucket generoso.
* **4.4. Privada pedida:** no existe endpoint que la sirva (cualquier `GET` con `?private`/`?seed` se ignora; el scanner CI + test `no-priv` lo garantizan; si un futuro endpoint la filtrara, es P0 + rollback).
* **4.5. Algoritmo inesperado:** solo `EdDSA` (si CU-CRYP-02 introduce `ES256` futuro, aparece como segunda familia JWK `EC` con su `kid`; este CU lo soporta por diseño multikey/multialg — documentado forward-compat).

## 5. Reglas de Negocio y Seguridad
* **RN-01:** Solo `use:sig`, `kty:OKP/OKP-Ed25519` hoy (+`EC` futuro), `kid` único inmutable por clave, `x` 32B b64url. Orden `kid DESC`.
* **RN-02:** Incluye TODAS no-retiradas (`retired_at IS NULL`): actual + overlap (CRYP-02) — nunca solo-actual durante rotación.
* **RN-03:** Cache 600s + `ETag` + `304`; norma refetch-on-unknown-kid (cliente) obligatoria para interoperar con rotación.
* **RN-04:** Sin auth, sin PII (solo material criptográfico público + URLs).
* **SEC-01:** Privada jamás en PG-respuesta-memoria-JWKS (solo `pub_b64` + `priv_ref` opaco como `kms:key-id` o `env:SESSION_SIGNING_KEY#<kid>`; el `priv_ref` NUNCA se sirve — solo interno).
* **SEC-02:** Scanner CI (`scripts/jwks_priv_scan.sh` + test `TestJWKSNoPrivateMaterial` con regex `"d"\s*:|private|seed|secret` sobre bodies ejemplo + fuzz de rotación) falla el merge si hay fuga.
* **SEC-03:** `openId-configuration` URLs exactas `https` en prod (en `dev` permite `http://localhost` + `WARN`; documentado).

## 6. Requerimientos de Observabilidad
* **Métrica:** `jwks_requests_total{result="200|304|429|500", endpoint="jwks|openid"}` + `jwks_keys_count` (gauge) + `jwks_reload_total{reason}` + `jwks_redis?` No (sin Redis aquí).
* **Trazabilidad:** Sin span por request (hot path público; solo `KeyDirectory.Reload` con span + `http.server` métricas base). `ETag` en logs DEBUG únicamente.
* **Auditoría:** Sin audit por lectura (ruido); rotaciones/retiros sí auditan (`keys.rotated|retired` en CRYP-02/03).

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: JWKS multikey + discovery + cache**
  * **Dado** 2 activas (`kid B` actual + `kid A` overlap).
  * **Cuando** `GET /jwks.json` (+ `If-None-Match`) y `GET /openid-configuration`.
  * **Entonces** `200` con 2 JWK OKP ordenadas `[B,A]` + `ETag` + `max-age=600`; re-`GET` con `ETag` → `304` vacío; discovery `200` con `jwks_uri` exacto + `EdDSA` + 3 grants. Scanner `d/priv` negativo. p95 <20ms (memoria).
* **Escenario 2: Refetch-on-unknown-kid**
  * **Dado** cliente con cache vieja (solo `A`), Auth emite con `B` (rotación).
  * **Cuando** cliente verifica JWT `kid=B` (miss) → refetch → re-verifica.
  * **Entonces** 2º intento `200` verificado (ejemplo SDK en contracts). Sin refetch habría `401` falso (test del ejemplo lo demuestra).
* **Escenario 3: Sin claves / rate / privada**
  * **Dado** 0 activas (simulado) + flood 120/min + grep `d` en body.
  * **Cuando** `GET` + flood + scan.
  * **Entonces** 0-claves → `500` + P1 (no `[]`); 101º/min → `429`; scan `d/priv/seed/secret` → 0 hits (CI verde). Arranque sin claves → `/ready` rojo.
