-- CU-REG-05: catálogo legal versionado + ledger inmutable de consentimientos.
CREATE TABLE IF NOT EXISTS legal_versions (
  doc_type TEXT NOT NULL CHECK (doc_type IN ('terms', 'privacy')),
  version TEXT NOT NULL CHECK (version ~ '^v[0-9]{4}\.[0-9]{2}$'),
  content_hash TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
  url TEXT NOT NULL,
  effective_from TIMESTAMPTZ NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (doc_type, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_legal_active ON legal_versions(doc_type) WHERE is_active;

CREATE TABLE IF NOT EXISTS consent_records (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  doc_type TEXT NOT NULL,
  version TEXT NOT NULL,
  accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip_hash TEXT NOT NULL,
  ua_hash TEXT NOT NULL,
  source TEXT NOT NULL,
  request_id UUID NOT NULL,
  FOREIGN KEY (doc_type, version) REFERENCES legal_versions(doc_type, version),
  UNIQUE (user_id, doc_type, version)
);
CREATE INDEX IF NOT EXISTS idx_consent_user ON consent_records(user_id);

-- Seed v2026.10 (hashes sha256 reales de los artefactos canónicos).
INSERT INTO legal_versions(doc_type, version, content_hash, url, effective_from, is_active) VALUES
 ('terms', 'v2026.10', '778cf7fca6229d5e3e3d6326e0aa660fb21bda531e8c31fe1cd7d38dcd8c1d83', 'https://legal.example.com/terms/v2026.10', now(), true),
 ('privacy', 'v2026.10', '7877f82b2ded1d423053a59f4ea797fd0aee1885d40fe499fde977babfaa2996', 'https://legal.example.com/privacy/v2026.10', now(), true)
ON CONFLICT (doc_type, version) DO NOTHING;

-- Append-only para el rol de app (RN-03). Idempotente en local/dev.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_role') THEN
    CREATE ROLE app_role NOLOGIN;
  END IF;
END
$$;
GRANT SELECT ON legal_versions TO app_role;
GRANT SELECT, INSERT ON consent_records TO app_role;
REVOKE UPDATE, DELETE ON legal_versions, consent_records FROM app_role;
