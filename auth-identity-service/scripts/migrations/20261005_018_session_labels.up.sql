-- CU-SES-03: metadatos visibles de sesión (denormalizados al Issue).
-- device_label legible ("Chrome · Windows"), ip_masked sin octeto final,
-- location ciudad/país o NULL (sin GeoIP: NULL hasta backfill futuro).
-- Filas viejas (pre-018) quedan 'unknown'/NULL y la lista las muestra tal
-- cual sin romper (backfill posterior las marca 'migrated').
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_label TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_masked TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS location TEXT;
-- Backfill una vez: distingue filas pre-018 de futuras (el Issue siempre
-- escribe labels reales desde 018, así que 'unknown' == fila vieja).
UPDATE sessions SET device_label='migrated', ip_masked='migrated'
  WHERE device_label='unknown';
