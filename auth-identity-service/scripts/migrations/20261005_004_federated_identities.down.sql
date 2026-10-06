-- CU-REG-04 down (solo dev; en prod los NULLs impedirían reimponer NOT NULL).
DROP TABLE IF EXISTS federated_identities;
ALTER TABLE users DROP COLUMN IF EXISTS terms_source;
ALTER TABLE users DROP COLUMN IF EXISTS federated_only;
