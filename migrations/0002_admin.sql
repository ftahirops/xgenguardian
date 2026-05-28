-- 0002_admin.sql — DNS query log + admin support.
--
-- dns_queries — every DNS query the resolver answers, with the decision it
-- made. Append-only. Used for the operator-facing admin dashboard. The
-- resolver writes via a Redis stream which a small worker drains into here,
-- so the resolver's hot path remains free of synchronous DB writes.

CREATE TABLE dns_queries (
  id           BIGSERIAL PRIMARY KEY,
  ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  domain       TEXT NOT NULL,
  qtype        TEXT,            -- A / AAAA / TXT / ...
  client_ip    INET,
  client_id    TEXT,            -- "resolver", "extension/0.1.0", etc
  verdict      TEXT,            -- clean | block | warn | analyzing | unknown
  cache_hit    BOOLEAN NOT NULL DEFAULT FALSE,
  duration_ms  INTEGER,
  upstream     TEXT,            -- which upstream was used, if any
  sinkhole     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_dns_queries_ts        ON dns_queries (ts DESC);
CREATE INDEX idx_dns_queries_domain    ON dns_queries (domain);
CREATE INDEX idx_dns_queries_verdict   ON dns_queries (verdict);
CREATE INDEX idx_dns_queries_sinkhole  ON dns_queries (sinkhole) WHERE sinkhole;

-- Retention: keep 30 days by default; the operator can extend with
-- `ALTER TABLE dns_queries SET (autovacuum_enabled = true);` and a cron.
