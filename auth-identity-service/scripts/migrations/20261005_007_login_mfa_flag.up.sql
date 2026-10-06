-- CU-AUTH-01: flag MFA denormalizado (el secreto TOTP vive en 008).
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_users_mfa ON users(id) WHERE mfa_enabled;
