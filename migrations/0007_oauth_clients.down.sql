-- 0007_oauth_clients.down.sql — reverses 0007_oauth_clients.sql

BEGIN;

DROP TABLE IF EXISTS oauth_clients CASCADE;

COMMIT;
