#!/usr/bin/env bash
# pg-backup.sh — dump Postgres to /var/backups/xgg-postgres/ and prune old dumps.
#
# Required env:
#   PGPASSWORD               Postgres password (or configure ~/.pgpass)
#
# Optional env:
#   DATABASE_URL             postgres://user:pass@host:port/dbname
#                            (password in URL is ignored; use PGPASSWORD)
#   BACKUP_RETENTION_DAYS    how many days to keep dumps (default: 14)
#
# Usage:
#   PGPASSWORD=secret ./scripts/pg-backup.sh

set -euo pipefail

# ── helpers ──────────────────────────────────────────────────────────────────
ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log()  { printf '[%s] %s\n' "$(ts)" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

# ── config ───────────────────────────────────────────────────────────────────
DATABASE_URL="${DATABASE_URL:-postgres://xgg:xgg@localhost:15432/xgg}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
BACKUP_DIR="/var/backups/xgg-postgres"
TIMESTAMP="$(date -u '+%Y%m%d-%H%M%S')"
DUMP_FILE="${BACKUP_DIR}/xgg-postgres-${TIMESTAMP}.dump"
GZ_FILE="${DUMP_FILE}.gz"

# ── parse DATABASE_URL ────────────────────────────────────────────────────────
# Strip scheme
_url="${DATABASE_URL#postgres://}"
_url="${_url#postgresql://}"

# user:pass@host:port/dbname  — password is discarded; honour PGPASSWORD env
_userinfo="${_url%%@*}"
_hostinfo="${_url#*@}"
PGUSER="${_userinfo%%:*}"
PGHOST="${_hostinfo%%:*}"
_portdb="${_hostinfo#*:}"
PGPORT="${_portdb%%/*}"
PGDATABASE="${_portdb#*/}"
# Strip query string if any
PGDATABASE="${PGDATABASE%%\?*}"

export PGUSER PGHOST PGPORT PGDATABASE
# Do NOT export password; caller must set PGPASSWORD or use ~/.pgpass

# ── preflight ────────────────────────────────────────────────────────────────
command -v pg_dump >/dev/null 2>&1 || die "pg_dump not found — install postgresql-client"
command -v gzip    >/dev/null 2>&1 || die "gzip not found"

[[ -z "${PGPASSWORD:-}" ]] && \
  log "WARNING: PGPASSWORD not set — relying on ~/.pgpass or peer auth"

mkdir -p "${BACKUP_DIR}"

# ── dump ──────────────────────────────────────────────────────────────────────
log "Starting pg_dump: ${PGUSER}@${PGHOST}:${PGPORT}/${PGDATABASE}"
log "Output: ${GZ_FILE}"

pg_dump \
  --no-owner \
  --no-acl \
  --format=custom \
  --file="${DUMP_FILE}"

log "pg_dump complete ($(du -sh "${DUMP_FILE}" | cut -f1))"

# ── compress ──────────────────────────────────────────────────────────────────
log "Compressing → ${GZ_FILE}"
gzip --fast "${DUMP_FILE}"
log "Compressed ($(du -sh "${GZ_FILE}" | cut -f1))"

# ── retention pruning ────────────────────────────────────────────────────────
log "Pruning dumps older than ${BACKUP_RETENTION_DAYS} days"
find "${BACKUP_DIR}" -maxdepth 1 -name 'xgg-postgres-*.dump.gz' \
  -mtime "+${BACKUP_RETENTION_DAYS}" -print -delete \
  | while IFS= read -r f; do log "Deleted old dump: ${f}"; done

log "Backup finished successfully: ${GZ_FILE}"
