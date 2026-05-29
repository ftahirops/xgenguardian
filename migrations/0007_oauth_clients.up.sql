-- XGenGuardian — OAuth client_id reputation registry (UNIFIED-PLAN.md §16.4).
--
-- Catches the OAuth consent-phishing gap (matrix §15 "OAuth consent phishing"
-- → previously WEAK). When a user lands on a real identity-provider consent
-- screen for an unknown app requesting sensitive scopes, we want to block
-- before they grant.
--
-- Seed with Microsoft "verified publisher" + Google's vetted OAuth catalogue.
-- See seeds in tools/brand-seeder/oauth_clients.yaml (or operator-supplied).
CREATE TABLE IF NOT EXISTS oauth_clients (
  id                BIGSERIAL PRIMARY KEY,
  provider          TEXT NOT NULL,                    -- 'microsoft' | 'google' | 'github' | ...
  client_id         TEXT NOT NULL,                    -- the OAuth client_id seen in the consent URL
  app_name          TEXT NOT NULL,
  publisher         TEXT,                              -- 'Verified Publisher: Acme Corp'
  trust_level       TEXT NOT NULL DEFAULT 'verified', -- 'verified' | 'known' | 'unverified' | 'malicious'
  sensitive_scopes  TEXT[],                            -- which scopes triggered the trust review
  notes             TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, client_id)
);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_provider_client ON oauth_clients (provider, client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_trust ON oauth_clients (trust_level);
