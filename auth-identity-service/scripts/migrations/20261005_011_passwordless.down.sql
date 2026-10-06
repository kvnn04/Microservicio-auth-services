-- CU-AUTH-05 down: revierte secreto efímero (solo dev; en prod se deja expirar).
DROP TABLE IF EXISTS passwordless_tokens;
ALTER TABLE users DROP COLUMN IF EXISTS last_login;
