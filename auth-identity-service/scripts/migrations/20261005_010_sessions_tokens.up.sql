-- CU-AUTH-04: sesiones enterprise + families rotativas + signing keys.
-- Access Ed25519 15min (JWKS) + Refresh opaco 32B (family UUIDv7, chain).
CREATE TABLE IF NOT EXISTS sessions (
  sid UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family UUID NOT NULL,
  jti_actual UUID NOT NULL,
  device_hash TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '90 days'
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_seen ON sessions(user_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_sessions_family ON sessions(family);

CREATE TABLE IF NOT EXISTS refresh_families (
  family UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  current_hash TEXT NOT NULL UNIQUE,
  parent_hash TEXT NOT NULL DEFAULT '',
  counter INT NOT NULL DEFAULT 0,
  absolute_exp TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_families_user ON refresh_families(user_id);

CREATE TABLE IF NOT EXISTS refresh_hashes (
  hash TEXT PRIMARY KEY,
  family UUID NOT NULL REFERENCES refresh_families(family) ON DELETE CASCADE,
  counter INT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hashes_family ON refresh_hashes(family);

CREATE TABLE IF NOT EXISTS signing_keys (
  kid TEXT PRIMARY KEY,
  alg TEXT NOT NULL DEFAULT 'EdDSA',
  pub_b64 TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at TIMESTAMPTZ
);
INSERT INTO signing_keys(kid, pub_b64) VALUES ('2026-10-a','<ed25519-pub-b64-placeholder>') ON CONFLICT DO NOTHING;

-- Revocación masiva (SES-02) + denylist corta (SES-01) se apoyan aquí.
ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z';
