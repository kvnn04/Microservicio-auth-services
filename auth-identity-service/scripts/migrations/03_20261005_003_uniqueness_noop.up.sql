-- CU-REG-03: sin cambios de negocio (decisión Q6: reuso).
-- La unicidad usa UNIQUE(email_normalized) de 001 (verificado idempotente abajo).
-- Tabla forense OPCIONAL desactivada por defecto (ver plan §3):
--   CREATE TABLE IF NOT EXISTS uniqueness_probes (
--     id BIGSERIAL PRIMARY KEY, email_hash TEXT NOT NULL, ip_hash TEXT NOT NULL,
--     found BOOLEAN NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
--   ):
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_normalized ON users(email_normalized);
-- Claim atómico del mailer (CU-REG-03 notify): estado intermedio 'sending'.
ALTER TABLE outbox DROP CONSTRAINT IF EXISTS outbox_status_check;
ALTER TABLE outbox ADD CONSTRAINT outbox_status_check CHECK (status IN ('pending', 'sending', 'sent', 'failed'));
SELECT 1;
