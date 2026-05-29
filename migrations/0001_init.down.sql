-- 0001_init.down.sql — reverses 0001_init.sql
-- Drop order is reverse dependency order: child tables before parents.

BEGIN;

-- prescan_queue has no FKs to the other tables
DROP TABLE IF EXISTS prescan_queue CASCADE;

-- scan_history references evidence
DROP TABLE IF EXISTS scan_history CASCADE;

-- evidence is referenced by urls (urls.evidence_id) — drop urls first
-- but urls is also referenced by nothing else here, so order: urls then evidence
DROP TABLE IF EXISTS urls CASCADE;

DROP TABLE IF EXISTS evidence CASCADE;

-- brand_screenshots references brands
DROP TABLE IF EXISTS brand_screenshots CASCADE;

DROP TABLE IF EXISTS brands CASCADE;

-- domains has no FKs in 0001 (tenant_id is added in 0003)
DROP TABLE IF EXISTS domains CASCADE;

-- Extensions are NOT dropped (shared with other databases; dropping is dangerous).
-- CREATE EXTENSION vector / pgcrypto are left in place.

COMMIT;
