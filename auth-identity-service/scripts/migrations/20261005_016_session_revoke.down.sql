-- CU-SES-01 down: revierte denylist (solo dev; en prod se deja expirar).
DROP TABLE IF EXISTS revoked_jtis;
DROP INDEX IF EXISTS idx_refresh_family;
