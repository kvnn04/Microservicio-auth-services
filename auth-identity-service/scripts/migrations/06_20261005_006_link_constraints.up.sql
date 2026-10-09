-- CU-REG-06: 1 sub/provider por cuenta (RN-01). PK(provider,sub) ya existe (004).
CREATE UNIQUE INDEX IF NOT EXISTS uq_fed_provider_user ON federated_identities(provider, user_id);
