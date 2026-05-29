-- 0005_feed_entries.down.sql — reverses 0005_feed_entries.sql

BEGIN;

DROP TABLE IF EXISTS feed_entries CASCADE;

COMMIT;
