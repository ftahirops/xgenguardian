-- 0008_feed_confidence.down.sql — reverses 0008_feed_confidence.sql
-- NOTE: The UPDATE statements that backfilled confidence values are NOT
-- reversed — those are data mutations on pre-existing rows and cannot be
-- safely undone without knowing prior state. Rolling back the column
-- itself removes all confidence data.

BEGIN;

DROP INDEX IF EXISTS idx_feed_entries_confidence;

ALTER TABLE feed_entries DROP COLUMN IF EXISTS confidence;

COMMIT;
