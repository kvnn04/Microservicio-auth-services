-- CU-SES-04: rotación con CAS + detección de reúso.
-- families: last_rotated_at (ventana de gracia 10s) + device_hash (huella
-- del Issue para el check mismo-device; '' en filas viejas = se omite el
-- check estricto y decide por ventana/flaps).
-- sessions: contexto de emisión para re-firmar el Access en cada rotate
-- preservando auth_time/amr/roles (RN-04: no rejuvenecer Step-Up).
-- (El plan pedía además last_parent_hash: innecesaria — parent_hash de 010
-- ya guarda el eslabón anterior; se documenta la omisión.)
ALTER TABLE refresh_families ADD COLUMN IF NOT EXISTS last_rotated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE refresh_families ADD COLUMN IF NOT EXISTS device_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS amr TEXT[] NOT NULL DEFAULT '{pwd}';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS roles TEXT[] NOT NULL DEFAULT '{user}';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS roles_ver INT NOT NULL DEFAULT 0;
-- idx_hashes_family ya existe por 010 (el IF NOT EXISTS del plan sería no-op).
