-- CU-AUTH-02: secretos TOTP staged + replay fallback + challenges fallback
-- + backup codes interinos (dueño CU-AUTH-03, misma tabla que extenderá).
CREATE TABLE IF NOT EXISTS mfa_totp_secrets (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc BYTEA NOT NULL,
  staged BOOLEAN NOT NULL DEFAULT TRUE,
  staged_expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '10 minutes',
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  enabled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS mfa_used_counters (
  user_id UUID NOT NULL,
  counter BIGINT NOT NULL,
  used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, counter)
);
CREATE TABLE IF NOT EXISTS mfa_challenges (
  challenge_id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  consumed BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id) WHERE NOT consumed;
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  consumed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, code_hash)
);
