-- 0009_brand_graph.sql
-- Brand-relationship graph: replaces flat trustreg hostname lists with
-- action-scoped (brand, host_pattern, scope, source) edges.
--
-- WHY: trustreg.go today is a flat list of hostnames per brand. Blanket
-- trust on a hostname is the wrong shape: stripe.com is trusted as a
-- payment-form destination, but if Stripe ever served a login page, we
-- shouldn't blanket-allow that. gstatic.com is trusted as a script source,
-- not as a credential sink. Action-scoping prevents one brand's CDN
-- domain from inheriting login-trust.
--
-- THE GRAPH:
--
--   brands(brand_id, brand_name, ...)   ← already exists from migration 0001
--      |
--      └── brand_hosts(brand_id, host_pattern, scope, source, confidence, ...)
--                                              ^^^^^
--                                              one of:
--                                                full-trust       ← canonical brand domain
--                                                login            ← trusted for auth flows
--                                                payment          ← trusted for payment sinks
--                                                oauth-redirect   ← trusted as OAuth callback target
--                                                script-source    ← CDN script delivery
--                                                cdn              ← static asset delivery
--                                                docs             ← documentation hosts
--                                                support          ← support/contact pages
--                                                app              ← user-facing app dashboard
--                                                api              ← API gateway
--
-- host_pattern can be:
--   - exact host:        'login.microsoftonline.com'
--   - suffix match:      '*.googleusercontent.com'
--   - punycode-aware exact match
--
-- source enum: 'manual' | 'crawled' | 'ct-log' | 'official-publisher'
--   tracks provenance so we can deprioritize entries we added by automated
--   crawl when manual-verified ones disagree.

CREATE TABLE IF NOT EXISTS brand_hosts (
    id            BIGSERIAL PRIMARY KEY,
    brand_id      UUID NOT NULL REFERENCES brands(brand_id) ON DELETE CASCADE,
    host_pattern  TEXT NOT NULL,
    scope         TEXT NOT NULL CHECK (scope IN (
                      'full-trust',
                      'login',
                      'payment',
                      'oauth-redirect',
                      'script-source',
                      'cdn',
                      'docs',
                      'support',
                      'app',
                      'api'
                  )),
    source        TEXT NOT NULL DEFAULT 'manual' CHECK (source IN (
                      'manual', 'crawled', 'ct-log', 'official-publisher'
                  )),
    -- 'high' = manually verified or signed by brand; 'medium' = inferred;
    -- 'low' = candidate, needs review.
    confidence    TEXT NOT NULL DEFAULT 'high' CHECK (confidence IN ('high', 'medium', 'low')),
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified TIMESTAMPTZ,
    notes         TEXT,

    UNIQUE (brand_id, host_pattern, scope)
);

CREATE INDEX IF NOT EXISTS idx_brand_hosts_pattern ON brand_hosts (host_pattern);
CREATE INDEX IF NOT EXISTS idx_brand_hosts_scope   ON brand_hosts (scope);
CREATE INDEX IF NOT EXISTS idx_brand_hosts_brand   ON brand_hosts (brand_id);

COMMENT ON TABLE brand_hosts IS
    'Brand relationship graph: per-brand host patterns with action-scoped trust. Replaces flat hostname lists in trustreg.';

COMMENT ON COLUMN brand_hosts.scope IS
    'Trust scope. A `cdn` entry trusts the host as a static-asset source but NOT as a login destination.';
