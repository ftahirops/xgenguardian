-- 0008_feed_confidence.sql
-- Source-tier feed_entries so high-confidence sources (URLhaus, OpenPhish,
-- Web Risk, Straiker IOCs) trigger BLOCK on a single hit, while
-- weaker community-mirrored sources (PhishDB GitHub) require multi-source
-- consensus before blocking.
--
-- Rationale: PhishDB GitHub has 789k+ rows including known false positives
-- (https://www.Amazon.com being listed as phishing was the canonical case).
-- Treating its entries equal to URLhaus's curated malware feed produces
-- avoidable FPs. With explicit tiers, single PhishDB hits become advisory
-- (WARN + force Tier-2) rather than auto-block.

ALTER TABLE feed_entries
    ADD COLUMN IF NOT EXISTS confidence TEXT NOT NULL DEFAULT 'medium'
        CHECK (confidence IN ('high', 'medium', 'low'));

-- Backfill known sources to their canonical tiers.
UPDATE feed_entries SET confidence = 'high'
WHERE source IN (
    'urlhaus',          -- abuse.ch curated malware
    'openphish',        -- OpenPhish curated phishing
    'webrisk',          -- Google Web Risk
    'straiker_2026_05', -- manually-added confirmed IOCs from Straiker 2026-05-27 report
    'manual'            -- operator-curated
);
UPDATE feed_entries SET confidence = 'medium'
WHERE source IN (
    'phishdb_github',   -- GitHub community-mirrored phishing list — useful but noisy
    'crowdsec_community'  -- if/when ingested via CrowdSec hub
);
-- Anything else stays at the 'medium' default.

CREATE INDEX IF NOT EXISTS idx_feed_entries_confidence
    ON feed_entries (confidence, last_seen DESC);

COMMENT ON COLUMN feed_entries.confidence IS
    'Source tier: high = single-hit BLOCK; medium = needs 2+ sources for BLOCK or used as Tier-2 trigger; low = informational, never BLOCK alone.';
