# Contratos de Integración: CU-CRYP-01

## 1. Contrato HTTP (API REST)

* **Rutas públicas (sin auth):**
  * `GET /.well-known/jwks.json` → `200 {keys:[JWK]}` (+ `304` con `If-None-Match`)
  * `GET /.well-known/openid-configuration` → `200 {issuer, jwks_uri, ...}`
* **Rate-limit:** `jwks:ip 100/min` → `429`. `Cache-Control: public, max-age=600, must-revalidate` (jwks) / `public, max-age=3600` (discovery). `ETag` en jwks.

```bash
curl http://localhost:8080/.well-known/jwks.json
# 200 { "keys": [
#   {"kty":"OKP","crv":"Ed25519","x":"...43ch...","use":"sig","kid":"2026-10-b","alg":"EdDSA"},
#   {"kty":"OKP","crv":"Ed25519","x":"...43ch...","use":"sig","kid":"2026-10-a","alg":"EdDSA"} ] }
curl http://localhost:8080/.well-known/openid-configuration
# 200 { "issuer": "https://auth.example.com", "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
#   "authorization_endpoint": "https://auth.example.com/api/v1/auth/federated/google/authorize",
#   "token_endpoint": "https://auth.example.com/api/v1/auth/oauth2/token",
#   "id_token_signing_alg_values_supported": ["EdDSA"], "scopes_supported": ["openid","profile","api"],
#   "response_types_supported": ["code"], "grant_types_supported": ["authorization_code","refresh_token","client_credentials"] }
```

### Norma cliente refetch-on-unknown-kid (vinculante para interoperar con CRYP-02)
```js
// 1. Verifica con JWKS cacheada. 2. Si kid miss -> GET jwks.json (If-None-Match) -> re-verifica UNA vez.
// 3. Si sigue miss -> 401 (token forjado o kid inventado).
```

## 2. Eventos Asíncronos (Kafka)

* Sin tópico propio (lecturas no auditan). Rotaciones/retiros emiten `keys.rotated|retired` en **CU-CRYP-02/03** (este CU solo recarga memoria ante ellos por pub/sub interno `keys.rotated`, no bus).
