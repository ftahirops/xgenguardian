-- XGenGuardian — initial schema (Phase 1)
-- Run with: golang-migrate up

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------
-- domains
-- One row per domain ever seen. Verdict + lifecycle metadata.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS domains (
  domain              TEXT PRIMARY KEY,
  first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  registrar           TEXT,
  registrant          TEXT,
  registered_at       TIMESTAMPTZ,
  expires_at          TIMESTAMPTZ,
  current_asn         INTEGER,
  current_ip          INET[],
  current_cert_sha256 TEXT,
  cert_issued_at      TIMESTAMPTZ,
  cert_issuer         TEXT,
  category            TEXT[],
  brand_match         TEXT,
  brand_canonical     BOOLEAN NOT NULL DEFAULT FALSE,
  reputation_score    REAL,
  verdict             TEXT NOT NULL DEFAULT 'unknown',  -- clean | suspicious | malicious | unknown
  verdict_confidence  REAL,
  last_scanned_at     TIMESTAMPTZ,
  next_rescan_at      TIMESTAMPTZ,
  flags               TEXT[]
);
CREATE INDEX IF NOT EXISTS idx_domains_verdict       ON domains (verdict);
CREATE INDEX IF NOT EXISTS idx_domains_next_rescan   ON domains (next_rescan_at) WHERE next_rescan_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_domains_brand_match   ON domains (brand_match) WHERE brand_match IS NOT NULL;

-- ---------------------------------------------------------------
-- urls
-- Per-URL verdict cache (path matters; some paths on a clean domain are bad).
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS urls (
  url_hash            BYTEA PRIMARY KEY,        -- SHA256 of normalized URL
  url                 TEXT NOT NULL,
  domain              TEXT REFERENCES domains(domain),
  first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  redirect_chain      TEXT[],
  final_url           TEXT,
  verdict             TEXT NOT NULL DEFAULT 'unknown',
  verdict_confidence  REAL,
  evidence_id         UUID,
  last_scanned_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_urls_domain  ON urls (domain);
CREATE INDEX IF NOT EXISTS idx_urls_verdict ON urls (verdict);

-- ---------------------------------------------------------------
-- brands
-- Brand Protection Registry: one row per protected brand.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS brands (
  brand_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_name          TEXT UNIQUE NOT NULL,
  canonical_domains   TEXT[] NOT NULL,
  legitimate_asns     INTEGER[],
  legitimate_issuers  TEXT[],
  favicon_hashes      TEXT[],
  keywords            TEXT[],
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------
-- brand_screenshots
-- One row per (brand, page) screenshot. 512-dim CLIP ViT-B/32 embedding.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS brand_screenshots (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_id        UUID NOT NULL REFERENCES brands(brand_id) ON DELETE CASCADE,
  page_label      TEXT NOT NULL,     -- 'login', 'home', 'checkout', ...
  page_url        TEXT NOT NULL,
  embedding       vector(512) NOT NULL,
  screenshot_url  TEXT,
  captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_brand_screenshots_embedding
  ON brand_screenshots USING ivfflat (embedding vector_cosine_ops)
  WITH (lists = 50);
CREATE INDEX IF NOT EXISTS idx_brand_screenshots_brand ON brand_screenshots (brand_id);

-- ---------------------------------------------------------------
-- evidence
-- Per-verdict evidence bundle. Referenced by urls.evidence_id.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url_hash           BYTEA,
  screenshot_url     TEXT,
  dom_url            TEXT,
  har_url            TEXT,
  js_analysis_url    TEXT,
  visual_top_brand   TEXT,
  visual_top_score   REAL,
  favicon_match      TEXT,
  form_actions       TEXT[],
  signals            JSONB,
  llm_explanation    TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  retention_until    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_evidence_url_hash ON evidence (url_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_top_brand ON evidence (visual_top_brand) WHERE visual_top_brand IS NOT NULL;

-- ---------------------------------------------------------------
-- scan_history (append-only audit trail)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_history (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url_hash            BYTEA NOT NULL,
  scanned_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tier1_score         REAL,
  tier2_score         REAL,
  verdict             TEXT NOT NULL,
  verdict_confidence  REAL,
  evidence_id         UUID REFERENCES evidence(evidence_id),
  external_verdicts   JSONB           -- {gsb: clean, vt: 3/70, urlscan: malicious}
);
CREATE INDEX IF NOT EXISTS idx_scan_history_url_hash ON scan_history (url_hash);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history (scanned_at);

-- ---------------------------------------------------------------
-- prescan_queue
-- Domains queued for proactive scanning (CT log, NRD, related-domain pivot).
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS prescan_queue (
  id              BIGSERIAL PRIMARY KEY,
  domain          TEXT NOT NULL,
  reason          TEXT NOT NULL,     -- 'ct_log_brand_match' | 'nrd_with_keyword' | ...
  brand_hint      TEXT,
  enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  picked_up_at    TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_prescan_queue_pending ON prescan_queue (enqueued_at) WHERE picked_up_at IS NULL;
