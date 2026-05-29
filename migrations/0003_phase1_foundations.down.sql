-- 0003_phase1_foundations.down.sql — reverses 0003_phase1_foundations.sql
-- Drop order: FKed children first, then columns added to existing tables,
-- then the new tables, and finally tenant seed data.

BEGIN;

-- Tables added in this migration (children before parents)
-- popup_edges and overrides reference tenants and users
DROP TABLE IF EXISTS popup_edges CASCADE;
DROP TABLE IF EXISTS overrides CASCADE;

-- users references tenants
DROP TABLE IF EXISTS users CASCADE;

-- Remove columns added to existing tables by this migration.
-- Indexes are dropped implicitly when columns are dropped or tables are altered.

-- urls columns added in this migration
ALTER TABLE urls DROP COLUMN IF EXISTS script_origin_fingerprint;
ALTER TABLE urls DROP COLUMN IF EXISTS form_fingerprint;
ALTER TABLE urls DROP COLUMN IF EXISTS redirect_fingerprint;
ALTER TABLE urls DROP COLUMN IF EXISTS page_fingerprint;
ALTER TABLE urls DROP COLUMN IF EXISTS next_rescan_at;
ALTER TABLE urls DROP COLUMN IF EXISTS ttl_seconds;
ALTER TABLE urls DROP COLUMN IF EXISTS page_class;
ALTER TABLE urls DROP COLUMN IF EXISTS grade;

-- tenant_id columns added to existing tables
ALTER TABLE scan_history  DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE evidence      DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE urls          DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE domains       DROP COLUMN IF EXISTS tenant_id;

-- Now drop tenants table (after all FK references are gone)
DROP TABLE IF EXISTS tenants CASCADE;

-- The seed INSERT is reversed by the CASCADE drop above, no explicit DELETE needed.

COMMIT;
