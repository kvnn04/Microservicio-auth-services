-- CU-CRED-03: prueba de control del NUEVO correo (link 32B, 1 uso, 1 activo).
-- Solo hashes SHA-256 hex: el plano vive una vez en el SMTP al nuevo buzón.
CREATE TABLE IF NOT EXISTS email_change_tokens (
  token_hash TEXT PRIMARY KEY,
  requester UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  new_normalized CITEXT NOT NULL,
  new_original TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  consumed BOOLEAN NOT NULL DEFAULT FALSE,
  superseded BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_emailchange_req_active ON email_change_tokens(requester) WHERE consumed = FALSE;
