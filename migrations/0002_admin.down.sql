-- 0002_admin.down.sql — reverses 0002_admin.sql

BEGIN;

DROP TABLE IF EXISTS dns_queries CASCADE;

COMMIT;
