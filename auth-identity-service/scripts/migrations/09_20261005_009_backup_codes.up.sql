-- CU-AUTH-03: backup codes definitivos (PK global code_hash + auditoría).
-- Reemplaza la tabla interina de CU-AUTH-02 (solo dev, sin datos prod).
DROP TABLE IF EXISTS mfa_backup_codes;
CREATE TABLE mfa_backup_codes (
  code_hash TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  used_at TIMESTAMPTZ,
  used_challenge_id UUID,
  superseded BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_backup_user ON mfa_backup_codes(user_id) WHERE NOT used;
