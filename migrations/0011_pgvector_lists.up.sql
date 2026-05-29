BEGIN;
-- Recreate ivfflat index with lists=5 (was lists=50).
-- pgvector recommends lists = rows/1000 for small tables; ~500 rows → lists=5.
-- This also fixes probes tuning: with lists=50 and the default probes=1 the
-- index scanned only 2% of the index, giving <70% recall (Finding #9).
DROP INDEX IF EXISTS idx_brand_screenshots_embedding;
CREATE INDEX IF NOT EXISTS idx_brand_screenshots_embedding
  ON brand_screenshots USING ivfflat (embedding vector_cosine_ops)
  WITH (lists = 5);
COMMIT;
