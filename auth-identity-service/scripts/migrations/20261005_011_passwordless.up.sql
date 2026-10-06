-- CU-AUTH-05: secreto efímero dual por email (link 32B + OTP 8d).
-- Solo hashes SHA-256 hex; planos solo transitorios al email_queue interno.
CREATE TABLE IF NOT EXISTS passwordless_tokens (
  token_hash TEXT PRIMARY KEY,
  otp_hash TEXT NOT NULL UNIQUE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  consumed BOOLEAN NOT NULL DEFAULT FALSE,
  superseded BOOLEAN NOT NULL DEFAULT FALSE,
  ctx_ip_hash TEXT NOT NULL,
  ctx_ua_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pless_user_active ON passwordless_tokens(user_id) WHERE consumed = FALSE;
CREATE INDEX IF NOT EXISTS idx_pless_otp ON passwordless_tokens(otp_hash) WHERE consumed = FALSE;

-- Último acceso con secreto efímero (auditoría, no bloquea).
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;
