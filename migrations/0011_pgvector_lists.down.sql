BEGIN;
DROP INDEX IF EXISTS idx_brand_screenshots_embedding;
CREATE INDEX IF NOT EXISTS idx_brand_screenshots_embedding
  ON brand_screenshots USING ivfflat (embedding vector_cosine_ops)
  WITH (lists = 50);
COMMIT;
