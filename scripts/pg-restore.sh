#!/usr/bin/env bash
# pg-restore.sh — restore a pg_dump custom-format (.dump or .dump.gz) file.
#
# DESTRUCTIVE: drops and recreates all objects before restore.
#
# Required env:
#   XGG_RESTORE_CONFIRM      must be set to "yes" to proceed
#   PGPASSWORD               Postgres password (or configure ~/.pgpass)
#
# Optional env:
#   DATABASE_URL             postgres://user:pass@host:port/dbname
#
# Usage:
#   XGG_RESTORE_CONFIRM=yes PGPASSWORD=secret \
#     ./scripts/pg-restore.sh /var/backups/xgg-postgres/xgg-postgres-20260528-030000.dump.gz

set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────
ts()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s] %s\n' "$(ts)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# ── safety gate ───────────────────────────────────────────────────────────────
[[ "${XGG_RESTORE_CONFIRM:-}" == "yes" ]] || \
  die "Set XGG_RESTORE_CONFIRM=yes to confirm this destructive operation"

# ── args ──────────────────────────────────────────────────────────────────────
DUMP_FILE="${1:-}"
[[ -n "${DUMP_FILE}" ]] || die "Usage: $0 <dump-file>"
[[ -f "${DUMP_FILE}" ]] || die "File not found: ${DUMP_FILE}"
[[ -r "${DUMP_FILE}" ]] || die "File not readable: ${DUMP_FILE}"

# ── config ────────────────────────────────────────────────────────────────────
DATABASE_URL="${DATABASE_URL:-postgres://xgg:xgg@localhost:15432/xgg}"

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
command -v pg_restore >/dev/null 2>&1 || die "pg_restore not found — install postgresql-client"

[[ -z "${PGPASSWORD:-}" ]] && \
  log "WARNING: PGPASSWORD not set — relying on ~/.pgpass or peer auth"

# ── decompress if needed ──────────────────────────────────────────────────────
RESTORE_FROM="${DUMP_FILE}"
TMPFILE=""

if [[ "${DUMP_FILE}" == *.gz ]]; then
  TMPFILE="$(mktemp /tmp/xgg-restore-XXXXXX.dump)"
  log "Decompressing ${DUMP_FILE} → ${TMPFILE}"
  gzip --decompress --stdout "${DUMP_FILE}" > "${TMPFILE}"
  RESTORE_FROM="${TMPFILE}"
  trap 'rm -f "${TMPFILE}"' EXIT
fi

# ── restore ───────────────────────────────────────────────────────────────────
log "Restoring from: ${DUMP_FILE}"
log "Target database: ${PGUSER}@${PGHOST}:${PGPORT}/${PGDATABASE}"
log "Using --clean --if-exists (objects will be dropped before restore)"

pg_restore \
  --no-owner \
  --no-acl \
  --clean \
  --if-exists \
  --dbname="${PGDATABASE}" \
  "${RESTORE_FROM}"

log "Restore complete: ${PGDATABASE} is now at the state captured in ${DUMP_FILE}"
