-- CU-CRED-01: link único 32B (SHA-256 guardado), 1 activo por supersede.
-- Reuso users.tokens_valid_after + sessions/families (010) para el corte global.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  consumed BOOLEAN NOT NULL DEFAULT FALSE,
  superseded BOOLEAN NOT NULL DEFAULT FALSE,
  ctx_ip_hash TEXT NOT NULL,
  ctx_ua_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pwdreset_user_active ON password_reset_tokens(user_id) WHERE consumed = FALSE;
