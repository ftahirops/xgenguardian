-- 0006_brand_phash.down.sql — reverses 0006_brand_phash.sql

BEGIN;

DROP INDEX IF EXISTS idx_brand_screenshots_dhash;
DROP INDEX IF EXISTS idx_brand_screenshots_phash;

ALTER TABLE brand_screenshots DROP COLUMN IF EXISTS dhash;
ALTER TABLE brand_screenshots DROP COLUMN IF EXISTS phash;

COMMIT;
