#!/usr/bin/env python3
"""cleanup-minio.py — delete orphaned MinIO objects for xgg-evidence bucket.

Compares MinIO objects against evidence rows in Postgres.
Any object whose key does not appear in evidence.screenshot_url,
evidence.dom_url, or evidence.har_url is considered orphaned.

Required env:
    MINIO_ENDPOINT      e.g. http://127.0.0.1:19000
    MINIO_ACCESS_KEY
    MINIO_SECRET_KEY
    MINIO_BUCKET        e.g. xgg-evidence
    PGPASSWORD          Postgres password (or ~/.pgpass)

Optional env:
    DATABASE_URL        postgres://user:pass@host:port/dbname
    CLEANUP_CONFIRM     set to "yes" to actually delete (default: dry-run)
"""

import os
import sys
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import boto3
from botocore.client import Config
import psycopg

# ── logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

# Force UTC timestamps in log output
logging.Formatter.converter = lambda *args: datetime.now(timezone.utc).timetuple()


def require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        log.error("Required env var %s is not set", name)
        sys.exit(1)
    return val


def parse_database_url(url: str) -> dict:
    """Return psycopg conninfo keyword dict from a postgres:// URL."""
    p = urlparse(url)
    return {
        "host": p.hostname,
        "port": p.port or 5432,
        "dbname": p.path.lstrip("/"),
        "user": p.username,
        # password deliberately omitted — honour PGPASSWORD env
    }


def extract_key(url_value: str | None) -> str | None:
    """Extract the object key from a full URL or a bare path."""
    if not url_value:
        return None
    parsed = urlparse(url_value)
    if parsed.scheme in ("http", "https"):
        # e.g. http://minio:9000/xgg-evidence/screenshots/abc.png
        # key = everything after /bucket/
        path = parsed.path.lstrip("/")
        # Strip leading bucket prefix if present
        bucket = os.environ.get("MINIO_BUCKET", "xgg-evidence")
        if path.startswith(bucket + "/"):
            path = path[len(bucket) + 1:]
        return path or None
    # bare key
    return url_value.lstrip("/") or None


def main() -> None:
    endpoint = require_env("MINIO_ENDPOINT")
    access_key = require_env("MINIO_ACCESS_KEY")
    secret_key = require_env("MINIO_SECRET_KEY")
    bucket = require_env("MINIO_BUCKET")
    database_url = os.environ.get("DATABASE_URL", "postgres://xgg:xgg@localhost:15432/xgg")
    cleanup_confirm = os.environ.get("CLEANUP_CONFIRM", "").strip().lower() == "yes"

    if cleanup_confirm:
        log.info("Mode: LIVE — orphaned objects will be deleted")
    else:
        log.info("Mode: DRY RUN — no objects will be deleted (set CLEANUP_CONFIRM=yes to delete)")

    # ── connect to MinIO ──────────────────────────────────────────────────────
    log.info("Connecting to MinIO: %s (bucket=%s)", endpoint, bucket)
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )

    # List all objects in bucket
    minio_keys: set[str] = set()
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            minio_keys.add(obj["Key"])
    log.info("MinIO objects found: %d", len(minio_keys))

    # ── connect to Postgres ───────────────────────────────────────────────────
    conninfo = parse_database_url(database_url)
    log.info(
        "Connecting to Postgres: %s@%s:%s/%s",
        conninfo["user"], conninfo["host"], conninfo["port"], conninfo["dbname"],
    )
    with psycopg.connect(**conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT screenshot_url, dom_url, har_url FROM evidence"
            )
            rows = cur.fetchall()

    # Build set of all known keys from evidence URLs
    known_keys: set[str] = set()
    for screenshot_url, dom_url, har_url in rows:
        for u in (screenshot_url, dom_url, har_url):
            key = extract_key(u)
            if key:
                known_keys.add(key)
    log.info("Evidence URL keys in DB: %d", len(known_keys))

    # ── find orphans ──────────────────────────────────────────────────────────
    orphan_keys = minio_keys - known_keys
    log.info("Orphaned objects: %d", len(orphan_keys))

    if not orphan_keys:
        log.info("No orphaned objects found — nothing to do")
        return

    for key in sorted(orphan_keys):
        if cleanup_confirm:
            log.info("DELETING: %s", key)
            s3.delete_object(Bucket=bucket, Key=key)
        else:
            log.info("WOULD DELETE: %s", key)

    if cleanup_confirm:
        log.info("Deleted %d orphaned objects from MinIO bucket %s", len(orphan_keys), bucket)
    else:
        log.info(
            "Dry run: would delete %d objects. Set CLEANUP_CONFIRM=yes to proceed.",
            len(orphan_keys),
        )


if __name__ == "__main__":
    main()
