#!/usr/bin/env python3
"""xgg dnstwist-cron — nightly typosquat sweep.

For every canonical brand domain (read from Postgres), generate dnstwist
permutations, resolve the ones currently registered, and insert any
brand-impersonating registrations into `feed_entries` with
source='dnstwist' so verdict-api's `feed_entries` lookup blocks them on
first encounter.

Designed to be invoked by the scheduler service (Go) via subprocess.
Idempotent: re-running is cheap because `feed_entries` has a UNIQUE
(source, url) constraint.

Install once:
    pip install dnstwist

Run:
    DATABASE_URL=postgres://… python3 tools/dnstwist-cron/run.py
    python3 tools/dnstwist-cron/run.py --domain paypal.com --domain google.com
    python3 tools/dnstwist-cron/run.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

# psycopg2 (or psycopg3) is required by the rest of the stack; if missing we
# error early with a helpful message rather than silently failing later.
try:
    import psycopg  # type: ignore
    _PSYCOPG_VER = 3
except ImportError:
    try:
        import psycopg2 as psycopg  # type: ignore
        _PSYCOPG_VER = 2
    except ImportError:
        print("error: psycopg or psycopg2 not installed; pip install psycopg[binary]", file=sys.stderr)
        sys.exit(2)


DEFAULT_DSN = os.getenv(
    "DATABASE_URL",
    "postgres://xgg:xgg@localhost:5432/xgg",
)
MAX_RESULTS_PER_BRAND = 500
DNSTWIST_TIMEOUT = 180  # seconds per brand


def load_canonical_domains(dsn: str) -> list[tuple[str, str]]:
    """Yield (brand_name, canonical_domain) pairs from `brands`. We want one
    row per canonical domain so dnstwist runs against each apex separately."""
    out: list[tuple[str, str]] = []
    if _PSYCOPG_VER == 3:
        conn = psycopg.connect(dsn, autocommit=True)
    else:
        conn = psycopg.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT brand_name, canonical_domains FROM brands")
            for brand_name, canonicals in cur.fetchall():
                if not canonicals:
                    continue
                for d in canonicals:
                    out.append((brand_name, d.lower().strip()))
    finally:
        conn.close()
    return out


def run_dnstwist(domain: str) -> list[dict]:
    """Invoke `dnstwist --format json --registered <domain>` and return parsed
    results. `--registered` filters to permutations that currently resolve,
    which is what we want for the deny cache."""
    try:
        cmd = [
            "dnstwist", "--format", "json", "--registered", domain,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=DNSTWIST_TIMEOUT)
    except FileNotFoundError:
        print("error: dnstwist binary not in PATH. Install: pip install dnstwist", file=sys.stderr)
        sys.exit(3)
    except subprocess.TimeoutExpired:
        print(f"warning: dnstwist timed out on {domain}", file=sys.stderr)
        return []
    if r.returncode != 0:
        print(f"warning: dnstwist {domain} exit {r.returncode}: {r.stderr[:200]}", file=sys.stderr)
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        print(f"warning: dnstwist {domain} non-JSON output", file=sys.stderr)
        return []
    return data[:MAX_RESULTS_PER_BRAND]


def upsert_findings(
    dsn: str,
    brand_name: str,
    findings: list[dict],
    dry_run: bool,
) -> int:
    """Insert findings into feed_entries. Returns the number of rows
    inserted (excluding duplicates).
    """
    if not findings:
        return 0
    if dry_run:
        for f in findings:
            print(f"  [dry] {brand_name} → {f.get('domain')}  ({f.get('fuzzer')})")
        return 0
    if _PSYCOPG_VER == 3:
        conn = psycopg.connect(dsn, autocommit=False)
    else:
        conn = psycopg.connect(dsn)
    try:
        inserted = 0
        with conn.cursor() as cur:
            for f in findings:
                dom = (f.get("domain") or "").lower().strip()
                if not dom:
                    continue
                # We store the permutation in url form so feed_entries.url
                # can be queried directly. There's no URL path; the bare
                # domain is what the attacker registered.
                url = f"https://{dom}/"
                # Reason / "fuzzer" classification (typosquat type) goes into
                # reference_id so analysts can see how dnstwist classified it.
                fuzzer = f.get("fuzzer", "")
                cur.execute(
                    """
                    INSERT INTO feed_entries (source, url, domain, category, first_seen, reference_id, last_seen)
                    VALUES ('dnstwist', %s, %s, 'phishing', NOW(), %s, NOW())
                    ON CONFLICT (source, url) DO UPDATE SET
                      last_seen    = NOW(),
                      reference_id = EXCLUDED.reference_id
                    """,
                    (url, dom, f"{brand_name}:{fuzzer}"),
                )
                inserted += 1
        conn.commit()
        return inserted
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn",     default=DEFAULT_DSN, help="Postgres DSN")
    ap.add_argument("--domain",  action="append",     help="Override canonical domains; can be repeated")
    ap.add_argument("--dry-run", action="store_true", help="Print findings without writing to Postgres")
    ap.add_argument("--limit",   type=int, default=0, help="Stop after N brands (0 = all)")
    args = ap.parse_args()

    if args.domain:
        pairs = [(d, d) for d in args.domain]
    else:
        pairs = load_canonical_domains(args.dsn)
    if args.limit > 0:
        pairs = pairs[: args.limit]

    if not pairs:
        print("no canonical domains found; seed the brand registry first", file=sys.stderr)
        return 1

    total_findings = 0
    t0 = time.time()
    for brand_name, domain in pairs:
        print(f"→ {brand_name}: dnstwist {domain}", flush=True)
        findings = run_dnstwist(domain)
        ins = upsert_findings(args.dsn, brand_name, findings, args.dry_run)
        total_findings += ins
        print(f"  {len(findings)} registered permutations, {ins} new feed entries", flush=True)

    elapsed = int(time.time() - t0)
    print(f"=== dnstwist-cron: {len(pairs)} brand(s) scanned, "
          f"{total_findings} feed entries inserted, {elapsed}s elapsed ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
