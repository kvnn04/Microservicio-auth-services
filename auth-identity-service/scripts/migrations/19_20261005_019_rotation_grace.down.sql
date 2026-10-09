-- CU-SES-04 down: revierte columnas de rotación (solo dev).
ALTER TABLE sessions DROP COLUMN IF EXISTS roles_ver;
ALTER TABLE sessions DROP COLUMN IF EXISTS roles;
ALTER TABLE sessions DROP COLUMN IF EXISTS amr;
ALTER TABLE sessions DROP COLUMN IF EXISTS auth_time;
ALTER TABLE refresh_families DROP COLUMN IF EXISTS device_hash;
ALTER TABLE refresh_families DROP COLUMN IF EXISTS last_rotated_at;
