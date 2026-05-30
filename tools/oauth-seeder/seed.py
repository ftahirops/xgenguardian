#!/usr/bin/env python3
"""XGenGuardian — OAuth client registry seeder.

Reads tools/oauth-seeder/clients.yaml and UPSERTs each row into the
oauth_clients Postgres table. Existing rows with the same
(provider, client_id) get their non-key fields refreshed; new rows are
inserted. Removed entries are NOT auto-deleted (operators may add
tenant-specific apps that aren't in this file — preserving them is the
safe default).

Usage:
    python3 tools/oauth-seeder/seed.py
    PG_DSN=postgres://xgg:xgg@localhost:15432/xgg python3 tools/oauth-seeder/seed.py
    python3 tools/oauth-seeder/seed.py --dry-run     # print SQL, don't execute

The seeded set is intentionally small: every entry is a publicly
documented official OAuth app. Adding random apps without provenance
would weaken the entire OAUTH_UNKNOWN_CLIENT_ID signal — the whole
point is that "unknown == suspicious." See clients.yaml header for the
addition rules.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import psycopg2
except ImportError:
    sys.stderr.write("[error] psycopg2 required: pip install psycopg2-binary\n")
    sys.exit(2)

try:
    import yaml
except ImportError:
    sys.stderr.write("[error] pyyaml required: pip install pyyaml\n")
    sys.exit(2)


UPSERT_SQL = """
    INSERT INTO oauth_clients
        (provider, client_id, app_name, publisher, trust_level, sensitive_scopes, notes)
    VALUES
        (%(provider)s, %(client_id)s, %(app_name)s, %(publisher)s, %(trust_level)s, %(sensitive_scopes)s, %(notes)s)
    ON CONFLICT (provider, client_id) DO UPDATE SET
        app_name         = EXCLUDED.app_name,
        publisher        = EXCLUDED.publisher,
        trust_level      = EXCLUDED.trust_level,
        sensitive_scopes = EXCLUDED.sensitive_scopes,
        notes            = EXCLUDED.notes
"""


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--dsn",
        default=os.environ.get(
            "PG_DSN", "postgres://xgg:xgg@localhost:15432/xgg"
        ),
    )
    p.add_argument(
        "--clients",
        default=str(Path(__file__).parent / "clients.yaml"),
    )
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    with open(args.clients, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    rows = doc.get("clients") or []
    if not rows:
        print("no clients to seed")
        return 0

    # Mild validation up front so a typo doesn't produce a half-seeded DB.
    required = {"provider", "client_id", "app_name", "trust_level"}
    for i, row in enumerate(rows):
        missing = required - set(row.keys())
        if missing:
            sys.stderr.write(
                f"[error] row {i} ({row.get('app_name','?')}): missing fields {sorted(missing)}\n"
            )
            return 2
        if row["trust_level"] not in (
            "verified",
            "known",
            "unverified",
            "malicious",
        ):
            sys.stderr.write(
                f"[error] row {i}: invalid trust_level {row['trust_level']!r}\n"
            )
            return 2

    if args.dry_run:
        for r in rows:
            print(f"UPSERT {r['provider']:<10} {r['client_id']:<46} {r['app_name']}")
        return 0

    conn = psycopg2.connect(args.dsn)
    inserted = updated = 0
    with conn, conn.cursor() as cur:
        for row in rows:
            payload = {
                "provider": row["provider"],
                "client_id": row["client_id"],
                "app_name": row["app_name"],
                "publisher": row.get("publisher"),
                "trust_level": row["trust_level"],
                "sensitive_scopes": row.get("sensitive_scopes") or [],
                "notes": row.get("notes"),
            }
            cur.execute(
                "SELECT 1 FROM oauth_clients WHERE provider=%s AND client_id=%s",
                (row["provider"], row["client_id"]),
            )
            exists = cur.fetchone() is not None
            cur.execute(UPSERT_SQL, payload)
            if exists:
                updated += 1
            else:
                inserted += 1
    print(f"seeded: {inserted} inserted, {updated} updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
