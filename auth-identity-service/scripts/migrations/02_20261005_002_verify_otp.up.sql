-- CU-REG-02: OTP dual + supersede + auditoría de activación.
-- Filas legacy CU-REG-01 (solo token_hash) siguen válidas por link hasta expirar.
ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS otp_hash TEXT UNIQUE;
ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS superseded BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS burned_reason TEXT;
ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS activated_by TEXT;
ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_vtokens_otp ON verification_tokens(otp_hash) WHERE consumed = FALSE;
CREATE INDEX IF NOT EXISTS idx_vtokens_user_active ON verification_tokens(user_id) WHERE consumed = FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS activated_method TEXT CHECK (activated_method IN ('link', 'otp'));

-- Cola durable de emails con secreto plano para el worker SMTP.
-- El plano NUNCA va a Kafka: es tabla interna consumida por el worker.
CREATE TABLE IF NOT EXISTS email_queue (
  id UUID PRIMARY KEY,
  to_email TEXT NOT NULL,
  subject TEXT NOT NULL,
  body_text TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
  attempts INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_email_queue_pending ON email_queue(created_at) WHERE status = 'pending';
