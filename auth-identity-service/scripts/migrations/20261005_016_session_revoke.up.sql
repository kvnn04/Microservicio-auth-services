-- CU-SES-01: denylist corta de jti + índice inverso refresh.
-- revoked_jtis: fallback PG de la denylist Redis jti:* (gateway la lee
-- si Redis miss). TTL corto ≤15min; el worker la purga cada 5min.
CREATE TABLE IF NOT EXISTS revoked_jtis (
  jti UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_exp ON revoked_jtis(expires_at);
-- Índice inverso refresh_hashes(family) para RevokeByRefreshHash
-- (hash PK ya existe; este índice acelera family→hashes si se necesita).
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_hashes(family);
-- Purga por worker (documentado, no cron PG):
-- DELETE FROM revoked_jtis WHERE expires_at < now();
