-- CU-SES-02 down: revierte solo lo propio de 017.
-- idx_families_user (010) NO se toca: pertenece a CU-AUTH-04.
DROP INDEX IF EXISTS idx_sessions_user;
DROP INDEX IF EXISTS idx_families_user_active;
