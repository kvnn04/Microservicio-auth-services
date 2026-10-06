-- CU-CRED-01 down: revierte tokens de reset (solo dev; en prod se dejan expirar).
DROP TABLE IF EXISTS password_reset_tokens;
