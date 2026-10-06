-- CU-AUTH-06: sin tablas nuevas (jti single-use en Redis EX 300; scopes son enum en código).
-- Guarda de compatibilidad para ENFORCE_STEP_UP_TOKEN futuro:
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS stepup_enforced BOOLEAN NOT NULL DEFAULT FALSE;
SELECT 1;
