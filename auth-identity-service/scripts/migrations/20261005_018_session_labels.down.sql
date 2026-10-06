-- CU-SES-03 down: revierte columnas de labels (solo dev).
ALTER TABLE sessions DROP COLUMN IF EXISTS location;
ALTER TABLE sessions DROP COLUMN IF EXISTS ip_masked;
ALTER TABLE sessions DROP COLUMN IF EXISTS device_label;
