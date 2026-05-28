-- XGenGuardian — Executive Mode (a.k.a. Paranoid Mode)
-- Feature spec: docs/UNIFIED-PLAN.md §4.4
-- Implementation plan: §11.3
-- Depends on: 0003_phase1_foundations.sql (tenants, users, overrides)

-- Tenant-default strictness. Per-user value in users.paranoid_mode
-- overrides; NULL there means "inherit tenant default".
ALTER TABLE tenants
  ADD COLUMN paranoid_mode BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users
  ADD COLUMN paranoid_mode BOOLEAN;

-- Warmup window: when a user first enables paranoid mode, treat B as A
-- for 24 hours so the personal cache populates before the friction kicks
-- in. Set to NOW() at enable time; reset to NULL at disable.
ALTER TABLE users
  ADD COLUMN paranoid_enabled_at TIMESTAMPTZ;

-- All overrides expire. No silent forever-allowlists. The §11.3 hard
-- rule: paranoid users renew explicitly or lose the exception.
ALTER TABLE overrides
  ADD COLUMN expires_at TIMESTAMPTZ NOT NULL
  DEFAULT (NOW() + INTERVAL '7 days');

CREATE INDEX idx_overrides_expiry
  ON overrides (expires_at) WHERE expires_at IS NOT NULL;
