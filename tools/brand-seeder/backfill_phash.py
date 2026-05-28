#!/usr/bin/env python3
"""backfill_phash — populate brand_screenshots.{phash,dhash} for existing rows.

The brand-seeder originally inserted rows without computing pHash/dHash. The
visual-match service uses these for cheap deterministic perceptual-hash
matching before falling back to CLIP. Without them, the pHash path is dead.

Run once after seeding new brands.

Usage:
  python backfill_phash.py
  python backfill_phash.py --dry-run
"""
from __future__ import annotations

import argparse
import io
import os
import sys

import httpx
import imagehash
import psycopg
from PIL import Image

PG_DSN = os.getenv("DATABASE_URL", "postgres://xgg:xgg@localhost:15432/xgg")
S3_BASE = os.getenv("S3_PUBLIC_BASE", "http://localhost:19000/xgg-evidence")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conn = psycopg.connect(PG_DSN, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT bs.id, bs.screenshot_url, b.brand_name, bs.page_label
                FROM brand_screenshots bs
                JOIN brands b ON b.brand_id = bs.brand_id
                WHERE bs.phash IS NULL OR bs.dhash IS NULL
                ORDER BY b.brand_name, bs.page_label
            """)
            rows = cur.fetchall()

        if not rows:
            print("No rows need backfilling.")
            return 0
        print(f"Backfilling {len(rows)} screenshot rows...")

        ok, failed = 0, 0
        for id, url, brand, label in rows:
            try:
                img_bytes = _fetch(url)
                img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
                ph = str(imagehash.phash(img))
                dh = str(imagehash.dhash(img))
            except Exception as exc:
                print(f"  [SKIP] {brand}/{label}: {exc}")
                failed += 1
                continue

            if args.dry_run:
                print(f"  [dry] {brand:20s} {label:10s} phash={ph} dhash={dh}")
            else:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE brand_screenshots SET phash=%s, dhash=%s WHERE id=%s",
                        (ph, dh, id),
                    )
                print(f"  [ok]  {brand:20s} {label:10s} phash={ph}")
            ok += 1

        print(f"\nDone: {ok} backfilled, {failed} skipped.")
        return 0 if failed == 0 else 1
    finally:
        conn.close()


def _fetch(url: str) -> bytes:
    # Some screenshot URLs point at the internal MinIO; rewrite the public
    # base if the env override is set.
    if url.startswith("http://localhost:9000/") and S3_BASE != "http://localhost:9000/xgg-evidence":
        url = url.replace("http://localhost:9000/xgg-evidence", S3_BASE)
    with httpx.Client(timeout=10) as c:
        r = c.get(url)
        r.raise_for_status()
        return r.content


if __name__ == "__main__":
    sys.exit(main())
