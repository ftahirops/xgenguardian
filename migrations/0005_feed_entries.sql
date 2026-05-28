-- XGenGuardian — feed_entries for OSS threat-intel ingest
-- Consumed by:  services/scheduler/internal/feeds (URLhaus, PhishTank, OpenPhish)
-- Read by:      services/verdict-api during fusion (sets BlocklistHit on Inputs)
-- See:          docs/UNIFIED-PLAN.md §18.2

CREATE TABLE feed_entries (
  id            BIGSERIAL PRIMARY KEY,
  source        TEXT NOT NULL,                  -- 'urlhaus' | 'phishtank' | 'openphish'
  url           TEXT NOT NULL,
  domain        TEXT NOT NULL,
  category      TEXT NOT NULL,                  -- 'malware' | 'phishing'
  reference_id  TEXT,                            -- upstream id where available
  first_seen    TIMESTAMPTZ NOT NULL,
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (source, url)
);
CREATE INDEX idx_feed_entries_url    ON feed_entries (url);
CREATE INDEX idx_feed_entries_domain ON feed_entries (domain);
CREATE INDEX idx_feed_entries_recent ON feed_entries (last_seen DESC);
