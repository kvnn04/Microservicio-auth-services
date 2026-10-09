-- CU-AUTH-04 down: revierte sesiones enterprise (solo dev: en prod se rota, no se borra).
DROP TABLE IF EXISTS refresh_hashes;
DROP TABLE IF EXISTS refresh_families;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS signing_keys;
ALTER TABLE users DROP COLUMN IF EXISTS tokens_valid_after;
