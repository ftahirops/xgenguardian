-- XGenGuardian — Phase 1 foundations
-- Adds: multi-tenancy (tenants, users), trust-grade columns on urls,
--       page fingerprints for drift detection, overrides workflow,
--       popup_edges for lineage tracking.
-- Pre-req for: Executive Mode (0004), scheduler drift triggers (§6),
--              extension popup logic (§3), portal admin overrides (§9).

-- ---------------------------------------------------------------
-- tenants — one row per tenant. Single-tenant deployments use the
-- default row; multi-tenant deploys add as needed.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  tenant_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Tenant-default policy flags. Per-user values in `users` override.
  is_default    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_default_single
  ON tenants (is_default) WHERE is_default = TRUE;

INSERT INTO tenants (tenant_id, name, is_default)
VALUES ('00000000-0000-0000-0000-000000000000', 'default', TRUE)
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------
-- users — extension installations / accounts. Role drives UI prompts
-- (e.g. auto-prompt Executive Mode for role = 'executive').
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  user_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  email         TEXT,                       -- nullable for anonymous installs
  role          TEXT NOT NULL DEFAULT 'standard',
                                            -- 'standard' | 'executive' | 'board'
                                            -- 'ir_analyst' | 'journalist'
                                            -- 'sysadmin' | 'managed_family'
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email  ON users (email) WHERE email IS NOT NULL;

-- ---------------------------------------------------------------
-- Add tenancy to existing tables. Default tenant for legacy rows.
-- ---------------------------------------------------------------
ALTER TABLE domains       ADD COLUMN IF NOT EXISTS tenant_id UUID
  REFERENCES tenants(tenant_id)
  DEFAULT '00000000-0000-0000-0000-000000000000' NOT NULL;
ALTER TABLE urls          ADD COLUMN IF NOT EXISTS tenant_id UUID
  REFERENCES tenants(tenant_id)
  DEFAULT '00000000-0000-0000-0000-000000000000' NOT NULL;
ALTER TABLE evidence      ADD COLUMN IF NOT EXISTS tenant_id UUID
  REFERENCES tenants(tenant_id)
  DEFAULT '00000000-0000-0000-0000-000000000000' NOT NULL;
ALTER TABLE scan_history  ADD COLUMN IF NOT EXISTS tenant_id UUID
  REFERENCES tenants(tenant_id)
  DEFAULT '00000000-0000-0000-0000-000000000000' NOT NULL;

CREATE INDEX IF NOT EXISTS idx_domains_tenant      ON domains (tenant_id);
CREATE INDEX IF NOT EXISTS idx_urls_tenant         ON urls (tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_tenant     ON evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_tenant ON scan_history (tenant_id);

-- ---------------------------------------------------------------
-- urls — trust-grade + drift-detection fingerprints.
-- Grade values: 'A+'|'A'|'B'|'C'|'D'|'F'|'F+'
-- page_class drives sensitive-class TTL caps (§4.2).
-- ---------------------------------------------------------------
ALTER TABLE urls ADD COLUMN IF NOT EXISTS grade        TEXT
  CHECK (grade IN ('A+','A','B','C','D','F','F+'));
ALTER TABLE urls ADD COLUMN IF NOT EXISTS page_class   TEXT
  CHECK (page_class IN (
    'generic','login','payment','oauth','admin','download','consent'
  )) DEFAULT 'generic';
ALTER TABLE urls ADD COLUMN IF NOT EXISTS ttl_seconds       INTEGER;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS next_rescan_at    TIMESTAMPTZ;

-- Fingerprints used by §4.3 drift triggers. Each is a SHA-256 hex of the
-- canonical representation of the field; scheduler diffs them on revisit.
ALTER TABLE urls ADD COLUMN IF NOT EXISTS page_fingerprint          TEXT;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS redirect_fingerprint      TEXT;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS form_fingerprint          TEXT;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS script_origin_fingerprint TEXT;

CREATE INDEX IF NOT EXISTS idx_urls_grade        ON urls (grade);
CREATE INDEX IF NOT EXISTS idx_urls_page_class   ON urls (page_class) WHERE page_class <> 'generic';
CREATE INDEX IF NOT EXISTS idx_urls_next_rescan  ON urls (next_rescan_at) WHERE next_rescan_at IS NOT NULL;

-- ---------------------------------------------------------------
-- overrides — admin / user allow-or-block exceptions to the verdict.
-- expires_at is added in 0004 alongside Executive Mode.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS overrides (
  id              BIGSERIAL PRIMARY KEY,
  tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  user_id         UUID REFERENCES users(user_id) ON DELETE CASCADE,
                                            -- NULL = tenant-wide override
  scope           TEXT NOT NULL,            -- 'url' | 'domain'
  match_value     TEXT NOT NULL,            -- exact URL or registrable domain
  action          TEXT NOT NULL,            -- 'allow' | 'block' | 'warn'
  reason          TEXT,
  created_by      TEXT NOT NULL,            -- admin email or 'system'
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_overrides_tenant_scope_value
  ON overrides (tenant_id, scope, match_value);
CREATE INDEX IF NOT EXISTS idx_overrides_user ON overrides (user_id) WHERE user_id IS NOT NULL;

-- ---------------------------------------------------------------
-- popup_edges — opener→target lineage. Feeds the §3 popup decision
-- matrix and the §9 popup-edge graph view.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS popup_edges (
  id               BIGSERIAL PRIMARY KEY,
  tenant_id        UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  opener_url_hash  BYTEA NOT NULL,
  target_url_hash  BYTEA NOT NULL,
  occurred_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  action           TEXT NOT NULL             -- 'allowed' | 'blocked' | 'isolated' | 'warned'
);
CREATE INDEX IF NOT EXISTS idx_popup_edges_opener ON popup_edges (opener_url_hash);
CREATE INDEX IF NOT EXISTS idx_popup_edges_target ON popup_edges (target_url_hash);
CREATE INDEX IF NOT EXISTS idx_popup_edges_recent ON popup_edges (occurred_at DESC);
