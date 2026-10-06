-- CU-REG-01: usuarios + outbox + tokens verificación + idempotencia
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email_normalized CITEXT NOT NULL UNIQUE,
  email_original TEXT NOT NULL,
  password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
  password_algo TEXT NOT NULL DEFAULT 'argon2id',
  status TEXT NOT NULL CHECK (status IN ('PENDING_VERIFICATION','ACTIVE','LOCKED','SOFT_DELETED')) DEFAULT 'PENDING_VERIFICATION',
  terms_version TEXT NOT NULL,
  privacy_version TEXT NOT NULL,
  terms_accepted_at TIMESTAMPTZ NOT NULL,
  ip_hash TEXT,
  user_agent_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

CREATE TABLE IF NOT EXISTS verification_tokens (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 3,
  consumed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, token_hash)
);

CREATE TABLE IF NOT EXISTS outbox (
  event_id UUID PRIMARY KEY,
  event_type TEXT NOT NULL,
  aggregate_id UUID NOT NULL,
  topic TEXT NOT NULL,
  payload JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
  attempts INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_outbox_status_created ON outbox(status, created_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS idempotency_keys (
  request_id UUID PRIMARY KEY,
  response_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours'
);
