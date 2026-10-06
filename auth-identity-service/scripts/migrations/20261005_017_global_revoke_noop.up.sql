-- CU-SES-02: revocado masivo sin tablas nuevas (reusa
-- users.tokens_valid_after (010) y sessions/families (010)).
-- Acelera el barrido por usuario del corte global:
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
-- Parcial sobre no-revocadas (si el nombre ya existe por 010, IF NOT EXISTS
-- lo deja intacto — el índice de 010 ya cubre user_id):
CREATE INDEX IF NOT EXISTS idx_families_user_active ON refresh_families(user_id) WHERE NOT revoked;
-- Redis: índice sess:by_user:<sub> (SET de sids, EX 90d) mantenido desde
-- Issue (SessionCache.Save SADD) y barrido en el corte (DEL set + miembros);
-- si falta (sesiones pre-017), el worker lo repara con SCAN acotado + WARN.
