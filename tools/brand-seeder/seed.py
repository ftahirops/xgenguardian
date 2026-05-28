"""XGenGuardian — Brand Registry seeder.

For each brand in brands.yaml:
  1. Try to render each login_url via the sandbox-render service.
  2. If rendering fails (timeout, CAPTCHA, blank page) AND the brand has a
     `manual_screenshots:` block, fall back to the local PNG for that
     page_label. See tools/brand-seeder/MANUAL.md.
  3. Embed the screenshot (URL or base64) via visual-match /embed.
  4. Insert into brands + brand_screenshots tables.
  5. Fetch favicon, compute pHash, append to brands.favicon_hashes.

Usage:
  python seed.py                 # full seed
  python seed.py --brand PayPal  # single brand
  python seed.py --dry-run       # don't write to DB
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import imagehash
import psycopg
import yaml
from PIL import Image

PG_DSN = os.getenv("DATABASE_URL", "postgres://xgg:xgg@localhost:5432/xgg")
SANDBOX_URL = os.getenv("SANDBOX_RENDER_URL", "http://localhost:8002")
VISUAL_URL = os.getenv("VISUAL_MATCH_URL", "http://localhost:8003")
BRANDS_YAML = Path(__file__).parent / "brands.yaml"
ROOT = Path(__file__).parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--brand", help="seed only this brand_name")
    ap.add_argument("--dry-run", action="store_true", help="skip DB writes")
    args = ap.parse_args()

    data = yaml.safe_load(BRANDS_YAML.read_text())
    brands = data["brands"]
    if args.brand:
        brands = [b for b in brands if b["name"].lower() == args.brand.lower()]
        if not brands:
            print(f"no brand named {args.brand!r} in brands.yaml", file=sys.stderr)
            return 2

    print(f"Seeding {len(brands)} brand(s)... (dry-run={args.dry_run})")

    if args.dry_run:
        conn = None
    else:
        conn = psycopg.connect(PG_DSN, autocommit=True)

    try:
        for b in brands:
            try:
                seed_brand(conn, b, dry_run=args.dry_run)
            except Exception as e:
                print(f"  [ERR] {b['name']}: {e}", file=sys.stderr)
                continue
    finally:
        if conn:
            conn.close()
    return 0


def seed_brand(conn: psycopg.Connection | None, b: dict[str, Any], *, dry_run: bool) -> None:
    name = b["name"]
    print(f"→ {name}")

    brand_id = None
    if conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO brands (brand_name, canonical_domains, keywords, legitimate_issuers)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (brand_name) DO UPDATE
                  SET canonical_domains = EXCLUDED.canonical_domains,
                      keywords = EXCLUDED.keywords,
                      legitimate_issuers = EXCLUDED.legitimate_issuers,
                      updated_at = NOW()
                RETURNING brand_id
                """,
                (
                    name,
                    b["canonical_domains"],
                    b.get("keywords", []),
                    [b.get("expected_issuer")] if b.get("expected_issuer") else [],
                ),
            )
            brand_id = cur.fetchone()[0]

    favicon_hashes: list[str] = []
    manual = {m["page_label"]: m for m in b.get("manual_screenshots", []) or []}

    with httpx.Client(timeout=30) as client:
        login_urls = b.get("login_urls", []) or []

        # Pages covered by either an auto-render attempt or a manual fallback.
        labels_seen: set[str] = set()

        for url in login_urls:
            page_label = label_of(url)
            labels_seen.add(page_label)

            screenshot_url = None
            screenshot_bytes = None
            page_url = url

            # 1) Try the auto path first.
            rr = try_render(client, url)
            if rr and rr.get("screenshot_url"):
                screenshot_url = rr["screenshot_url"]
                if rr.get("favicon_url"):
                    fh = try_favicon_hash(client, rr["favicon_url"])
                    if fh:
                        favicon_hashes.append(fh)

            # 2) Fall back to a manual screenshot if auto failed.
            if not screenshot_url and page_label in manual:
                m = manual[page_label]
                screenshot_bytes = load_manual_screenshot(m)
                page_url = m.get("page_url", url)
                print(f"   ↳ using manual screenshot {m['file']}")

            if not screenshot_url and not screenshot_bytes:
                print(f"   [SKIP] {url}: render failed and no manual fallback for label={page_label}")
                continue

            # 3) Embed.
            vec = embed(client, screenshot_url=screenshot_url, screenshot_bytes=screenshot_bytes)
            if vec is None:
                continue

            # 4) Insert.
            if conn and brand_id:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO brand_screenshots (brand_id, page_label, page_url, embedding, screenshot_url)
                        VALUES (%s, %s, %s, %s::vector, %s)
                        """,
                        (brand_id, page_label, page_url, vec, screenshot_url or "manual://" + str(m["file"])),
                    )

        # Manual-only pages (no matching login_url): still seed them.
        for label, m in manual.items():
            if label in labels_seen:
                continue
            screenshot_bytes = load_manual_screenshot(m)
            vec = embed(client, screenshot_bytes=screenshot_bytes)
            if vec is None or not conn or not brand_id:
                continue
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO brand_screenshots (brand_id, page_label, page_url, embedding, screenshot_url)
                    VALUES (%s, %s, %s, %s::vector, %s)
                    """,
                    (brand_id, label, m.get("page_url", ""), vec, "manual://" + str(m["file"])),
                )
            print(f"   ↳ manual-only entry for label={label}")

    if favicon_hashes and conn and brand_id:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE brands SET favicon_hashes = %s WHERE brand_id = %s",
                (sorted(set(favicon_hashes)), brand_id),
            )

    print(f"   ✓ {name}")


# --- helpers ---


def label_of(url: str) -> str:
    u = url.lower()
    if any(k in u for k in ("login", "signin", "sign-in", "auth", "account")):
        return "login"
    if "checkout" in u or "payment" in u:
        return "checkout"
    return "home"


def try_render(client: httpx.Client, url: str) -> dict | None:
    try:
        r = client.post(f"{SANDBOX_URL}/render", json={"url": url}, timeout=20)
    except Exception as e:
        print(f"   render error: {e}")
        return None
    if r.status_code != 200:
        print(f"   render http {r.status_code}: {r.text[:140]}")
        return None
    body = r.json()
    # Smoke-check: blank/tiny rendered page is often a WAF block.
    if not body.get("title") and not body.get("forms"):
        # Allow it anyway; visual match may still recognize a "Checking your
        # browser" page if it gets templated frequently, but log it.
        print(f"   note: empty title+forms; possible WAF page at {url}")
    return body


def try_favicon_hash(client: httpx.Client, favicon_url: str) -> str | None:
    try:
        r = client.get(favicon_url, timeout=10)
        if r.status_code != 200:
            return None
        img = Image.open(io.BytesIO(r.content)).convert("RGB")
        return str(imagehash.phash(img))
    except Exception:
        return None


def load_manual_screenshot(m: dict[str, Any]) -> bytes:
    p = ROOT / m["file"]
    if not p.exists():
        raise FileNotFoundError(f"manual screenshot not found: {p}")
    return p.read_bytes()


def embed(
    client: httpx.Client,
    *,
    screenshot_url: str | None = None,
    screenshot_bytes: bytes | None = None,
) -> list[float] | None:
    if screenshot_url:
        body = {"image_url": screenshot_url}
    elif screenshot_bytes:
        body = {"image_b64": base64.b64encode(screenshot_bytes).decode("ascii")}
    else:
        return None

    try:
        r = client.post(f"{VISUAL_URL}/embed", json=body, timeout=30)
    except Exception as e:
        print(f"   embed error: {e}")
        return None
    if r.status_code != 200:
        print(f"   embed http {r.status_code}: {r.text[:140]}")
        return None
    return r.json().get("vector")


if __name__ == "__main__":
    sys.exit(main())
