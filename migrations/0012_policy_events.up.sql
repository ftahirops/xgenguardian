-- 0012_policy_events.sql
-- Phase G — Data flywheel.
--
-- Captures override / FP-report / FN-report events from the extension and
-- portal. Pairs with the existing xgg_rule_fired_total Prometheus metric
-- to produce the weekly rule-health report:
--
--   override_rate(rule) = override_count / fire_count
--   fp_rate(rule)       = fp_report_count / fire_count
--
-- A rule with a rising override_rate is a strong candidate for review:
-- users are pushing past it, so either the rule is too aggressive (FP
-- factory) or the warn page is unclear.
--
-- Privacy invariants enforced at the application layer:
--   - Raw URL never stored. Only the host (for review) and a SHA-256 hex
--     of the URL minus query string (url_hash) so duplicates collapse.
--   - Raw client_id never stored. Only client_id_hash (SHA-256 hex).
--   - Endpoint is opt-in via XGG_TELEMETRY_ENABLED; disabled-state is a
--     silent 204 with no persistence and no log line.

BEGIN;

CREATE TABLE IF NOT EXISTS policy_events (
    id             BIGSERIAL PRIMARY KEY,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- 'override_warn'   — user clicked "proceed anyway" on a WARN page
    -- 'override_block'  — user clicked "proceed anyway" on a BLOCK page
    -- 'report_fp'       — user/operator flagged the verdict as wrong (clean)
    -- 'report_fn'       — user/operator flagged a missed bad site
    action         TEXT NOT NULL CHECK (action IN (
                       'override_warn',
                       'override_block',
                       'report_fp',
                       'report_fn'
                   )),
    -- 'extension' — POSTed by the browser extension
    -- 'portal'    — POSTed by the operator from the transparency portal
    source         TEXT NOT NULL CHECK (source IN ('extension', 'portal')),
    -- Host of the URL the event is about. Never the full URL.
    host           TEXT,
    -- SHA-256 hex of the URL minus its query string. 64 chars.
    url_hash       CHAR(64),
    -- What we said: ALLOW/WARN/BLOCK/ISOLATE.
    verdict        TEXT,
    -- Reason codes that fired in the verdict the user is reacting to.
    -- Stored as JSON array so we can index/aggregate per code.
    reason_codes   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- SHA-256 hex of the client_id. Used only to dedup repeat overrides
    -- from the same device for the same rule in a short window.
    client_id_hash CHAR(64),
    -- Optional operator note (portal flow only).
    note           TEXT,

    CONSTRAINT policy_events_codes_is_array
        CHECK (jsonb_typeof(reason_codes) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_policy_events_occurred ON policy_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_events_action   ON policy_events (action);
CREATE INDEX IF NOT EXISTS idx_policy_events_host     ON policy_events (host);

COMMENT ON TABLE policy_events IS
    'Phase G data-flywheel events: user overrides + FP/FN reports. Pairs with xgg_rule_fired_total to compute override_rate and fp_rate per reason code. Raw URLs/client_ids never stored.';

COMMENT ON COLUMN policy_events.url_hash IS
    'SHA-256 hex of the URL with its query string removed. Lets the report tool collapse duplicate events without retaining the URL itself.';

COMMENT ON COLUMN policy_events.client_id_hash IS
    'SHA-256 hex of the extension client_id. Used only for short-window dedup; never reverse-mapped.';

COMMIT;
