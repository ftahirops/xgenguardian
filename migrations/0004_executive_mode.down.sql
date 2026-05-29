-- 0004_executive_mode.down.sql — reverses 0004_executive_mode.sql

BEGIN;

-- Drop the index first (depends on the column)
DROP INDEX IF EXISTS idx_overrides_expiry;

-- Remove columns added to existing tables
ALTER TABLE overrides DROP COLUMN IF EXISTS expires_at;
ALTER TABLE users     DROP COLUMN IF EXISTS paranoid_enabled_at;
ALTER TABLE users     DROP COLUMN IF EXISTS paranoid_mode;
ALTER TABLE tenants   DROP COLUMN IF EXISTS paranoid_mode;

COMMIT;
