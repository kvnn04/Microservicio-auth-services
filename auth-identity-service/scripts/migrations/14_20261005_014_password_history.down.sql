-- CU-CRED-02 down: revierte historial y versión (solo dev).
DROP TABLE IF EXISTS password_history;
ALTER TABLE users DROP COLUMN IF EXISTS password_ver;
