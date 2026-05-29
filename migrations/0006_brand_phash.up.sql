-- XGenGuardian — perceptual-hash columns on brand_screenshots.
-- Backs the visual-match service's "cheap pre-filter under CLIP" pathway
-- (UNIFIED-PLAN.md §18.2). pHash and dHash give deterministic Hamming-distance
-- nearest-neighbour lookups in O(rows) — fine at our brand-registry scale
-- (50-500 entries) without needing another ANN index.

ALTER TABLE brand_screenshots
  ADD COLUMN IF NOT EXISTS phash TEXT,
  ADD COLUMN IF NOT EXISTS dhash TEXT;

-- Index for fast filtering once populated. Both hashes are 16-char hex
-- strings (64-bit) for ImageHash's default pHash/dHash output.
CREATE INDEX IF NOT EXISTS idx_brand_screenshots_phash ON brand_screenshots (phash) WHERE phash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_brand_screenshots_dhash ON brand_screenshots (dhash) WHERE dhash IS NOT NULL;
