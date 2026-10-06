-- CU-CRED-03 down: revierte tokens de cambio (solo dev; en prod se dejan expirar).
DROP TABLE IF EXISTS email_change_tokens;
