-- CU-REG-04: identidades federadas (MVP google, CHECK ampliable en deltas).
CREATE TABLE IF NOT EXISTS federated_identities (
  provider TEXT NOT NULL CHECK (provider IN ('google')),
  sub TEXT NOT NULL CHECK (char_length(sub) BETWEEN 1 AND 255),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email_at_link CITEXT NOT NULL,
  iss TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, sub)
);
CREATE INDEX IF NOT EXISTS idx_fed_user ON federated_identities(user_id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS federated_only BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_source TEXT;
-- Federados sin password: relaja NOT NULL + CHECK admite NULL.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_password_hash_check;
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_password_hash_check
  CHECK (password_hash IS NULL OR password_hash LIKE '$argon2id$%');
