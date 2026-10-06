#!/bin/sh
# CU-AUTH-04 T-08: genera par Ed25519 para SESSION_SIGNING_KEY (deploy).
# Uso: go run ./scripts/gen_ed25519 [kid]
# Salida: privada base64 (→ KMS/env SESSION_SIGNING_KEY) + pública (→ signing_keys.pub_b64).
# Nunca commitear la privada al repo.
set -eu
KID="${1:-2026-10-a}"
go run ./scripts/gen_ed25519 "$KID"
