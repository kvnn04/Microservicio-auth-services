-- CU-REG-03 down: solo revierte lo creado por este script (no toca 001).
ALTER TABLE outbox DROP CONSTRAINT IF EXISTS outbox_status_check;
ALTER TABLE outbox ADD CONSTRAINT outbox_status_check CHECK (status IN ('pending', 'sent', 'failed'));
DROP INDEX IF EXISTS uq_users_email_normalized;
