-- CU-CRED-02: historial append-only de hashes (ventana móvil N=5) + versión.
-- Sin UNIQUE global: un hash que salió de la ventana puede re-insertarse.
CREATE TABLE IF NOT EXISTS password_history (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pwdhist_user_created ON password_history(user_id, created_at DESC);
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_ver INT NOT NULL DEFAULT 1;
