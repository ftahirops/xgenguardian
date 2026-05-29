#!/usr/bin/env bash
# cleanup-expired.sh — delete expired/orphan rows from Postgres.
#
# Runs inside a single transaction; partial failure rolls back.
# Dry-run by default: set CLEANUP_CONFIRM=yes to actually delete.
#
# Required env:
#   PGPASSWORD               Postgres password (or ~/.pgpass)
#
# Optional env:
#   DATABASE_URL             postgres://user:pass@host:port/dbname
#   DNS_QUERIES_RETENTION_DAYS  rows older than this are deleted (default: 30)
#   CLEANUP_CONFIRM          set to "yes" to commit deletes (default: dry-run)

set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────
ts()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s] %s\n' "$(ts)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# ── config ────────────────────────────────────────────────────────────────────
DATABASE_URL="${DATABASE_URL:-postgres://xgg:xgg@localhost:15432/xgg}"
DNS_QUERIES_RETENTION_DAYS="${DNS_QUERIES_RETENTION_DAYS:-30}"
CLEANUP_CONFIRM="${CLEANUP_CONFIRM:-}"

# ── parse DATABASE_URL ────────────────────────────────────────────────────────
_url="${DATABASE_URL#postgres://}"
_url="${_url#postgresql://}"
_userinfo="${_url%%@*}"
_hostinfo="${_url#*@}"
PGUSER="${_userinfo%%:*}"
PGHOST="${_hostinfo%%:*}"
_portdb="${_hostinfo#*:}"
PGPORT="${_portdb%%/*}"
PGDATABASE="${_portdb#*/}"
PGDATABASE="${PGDATABASE%%\?*}"

export PGUSER PGHOST PGPORT PGDATABASE

# ── preflight ─────────────────────────────────────────────────────────────────
command -v psql >/dev/null 2>&1 || die "psql not found — install postgresql-client"

[[ -z "${PGPASSWORD:-}" ]] && \
  log "WARNING: PGPASSWORD not set — relying on ~/.pgpass or peer auth"

# ── mode ──────────────────────────────────────────────────────────────────────
if [[ "${CLEANUP_CONFIRM}" == "yes" ]]; then
  log "Mode: LIVE — rows will be permanently deleted"
  COMMIT_OR_ROLLBACK="COMMIT"
else
  log "Mode: DRY RUN — no rows will be deleted (set CLEANUP_CONFIRM=yes to commit)"
  COMMIT_OR_ROLLBACK="ROLLBACK"
fi

# ── SQL ───────────────────────────────────────────────────────────────────────
SQL=$(cat <<EOSQL
BEGIN;

-- 1. Orphan scan_history rows (evidence_id references nonexistent evidence)
WITH deleted AS (
  DELETE FROM scan_history
  WHERE evidence_id IS NOT NULL
    AND evidence_id NOT IN (SELECT evidence_id FROM evidence)
  RETURNING evidence_id
)
SELECT 'scan_history_orphans' AS table_name, COUNT(*) AS deleted_rows FROM deleted;

-- 2. Expired evidence rows
WITH deleted AS (
  DELETE FROM evidence
  WHERE retention_until IS NOT NULL
    AND retention_until < NOW()
  RETURNING evidence_id
)
SELECT 'evidence_expired' AS table_name, COUNT(*) AS deleted_rows FROM deleted;

-- 3. Old dns_queries rows
WITH deleted AS (
  DELETE FROM dns_queries
  WHERE created_at < NOW() - INTERVAL '${DNS_QUERIES_RETENTION_DAYS} days'
  RETURNING id
)
SELECT 'dns_queries_old' AS table_name, COUNT(*) AS deleted_rows FROM deleted;

-- 4. Old completed prescan_queue rows
WITH deleted AS (
  DELETE FROM prescan_queue
  WHERE completed_at IS NOT NULL
    AND completed_at < NOW() - INTERVAL '7 days'
  RETURNING id
)
SELECT 'prescan_queue_old' AS table_name, COUNT(*) AS deleted_rows FROM deleted;

${COMMIT_OR_ROLLBACK};
EOSQL
)

# ── run ───────────────────────────────────────────────────────────────────────
log "Connecting to ${PGUSER}@${PGHOST}:${PGPORT}/${PGDATABASE}"
log "DNS_QUERIES_RETENTION_DAYS=${DNS_QUERIES_RETENTION_DAYS}"

RESULTS="$(psql --no-psqlrc --tuples-only --expanded \
  --dbname="${PGDATABASE}" \
  --command="${SQL}" 2>&1)"

log "Cleanup results:"
while IFS= read -r line; do
  log "  ${line}"
done <<< "${RESULTS}"

if [[ "${CLEANUP_CONFIRM}" == "yes" ]]; then
  log "Cleanup committed."
else
  log "Dry run complete — no changes persisted."
fi
