"""XGenGuardian — blocklist fetcher with confidence tiers.

Reads feeds.yaml, fetches every active feed, deduplicates, and produces
TWO output sets to keep false-positive rate near zero:

  STRICT (NXDOMAIN-able) — a domain enters strict if any of:
      * It appears in two or more independent feeds
      * It appears in any feed tagged category=phishing or category=malware
        (those feeds are tightly curated and the cost of FP is low)
    Stored in Redis SET `blocklist:strict` + file blocklist.strict.txt

  WEAK (WARN / flag only) — single-source ads/tracking/generic entries.
    Stored in Redis SET `blocklist:weak` + file blocklist.weak.txt

Per-domain metadata:
  Redis HASH `blocklist:meta`          domain → "<category>|<src1,src2,...>|<count>"
  Redis HASH `blocklist:stats`         source_name → per-source domain count
  Redis SET  `blocklist:exact`         union of strict ∪ weak (back-compat;
                                       resolver currently checks this set)

Per-feed fetch errors are logged but never fail the whole run.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import httpx
import redis
import yaml

REDIS_ADDR = os.getenv("REDIS_ADDR", "localhost:6379")
OUT_DIR    = Path(os.getenv("OUT_DIR", "./data"))
FEEDS_PATH = Path(os.getenv("FEEDS", Path(__file__).parent / "feeds.yaml"))
HTTP_TIMEOUT = 60
MAX_PARALLEL = 8

# Stricter than RFC: requires a dot and only [a-z0-9.-].
_VALID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,253}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,253}[a-z0-9])?)+$")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cfg = yaml.safe_load(FEEDS_PATH.read_text())
    feeds = [f for f in cfg["feeds"] if f.get("active", True)]
    print(f"Loaded {len(feeds)} active feeds from {FEEDS_PATH}", flush=True)

    rdb = redis.Redis.from_url(f"redis://{REDIS_ADDR}", decode_responses=True)

    # domain → {"cats": set(categories), "srcs": set(source_names)}
    domains: dict[str, dict] = {}
    urls: set[str] = set()
    per_source: dict[str, int] = {}
    failures: list[tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        futures = {pool.submit(_fetch_feed, f): f["name"] for f in feeds}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                feed, doms, us = fut.result()
                cat = feed["category"]
                src = feed["name"]
                for d in doms:
                    entry = domains.setdefault(d, {"cats": set(), "srcs": set()})
                    entry["cats"].add(cat)
                    entry["srcs"].add(src)
                urls.update(us)
                per_source[name] = len(doms)
                print(f"  ✓ {name:32s} {len(doms):>7} domains  · {cat}", flush=True)
            except Exception as e:
                failures.append((name, str(e)))
                print(f"  ✗ {name:32s} FAILED: {e}", file=sys.stderr, flush=True)

    # ── classify into strict vs weak ──────────────────────────────
    #
    # STRICT (NXDOMAIN-able) — domain enters strict only when at least one
    # source is a HIGH-PRECISION feed (a pure phishing or malware list,
    # not a mixed/aggregator threat-intel feed). Once a high-precision
    # feed lists it OR two independent high-precision feeds agree, we
    # consider the FP cost low enough to NXDOMAIN.
    #
    # Domains corroborated only by mixed/aggregator feeds (hagezi-tif,
    # hagezi-pro, stevenblack-hosts, oisd) go to WEAK regardless of how
    # many such feeds agree — these aggregates are designed for a "block
    # everything aggressive" UX, not for a security resolver that must
    # never break a legitimate site.
    STRICT_FEEDS = {
        "phishtank", "openphish", "cert-pl", "phishing-army-blocklist",
        "phishing-database-active", "phishing-database-links-active",
        "urlhaus", "threatfox", "malware-filter-urlhaus", "rpilist-malware",
        "cryptojacking-no-coin",
    }
    strict: dict[str, dict] = {}
    weak:   dict[str, dict] = {}
    for d, meta in domains.items():
        if meta["srcs"] & STRICT_FEEDS:
            strict[d] = meta
        else:
            weak[d] = meta

    print(f"\nTotal unique domains: {len(domains):,}   urls: {len(urls):,}", flush=True)
    print(f"  → strict (NXDOMAIN): {len(strict):,}", flush=True)
    print(f"  → weak (WARN only):  {len(weak):,}", flush=True)

    # Top categories breakdown (informational)
    cat_counts: dict[str, int] = {}
    for meta in domains.values():
        for c in meta["cats"]:
            cat_counts[c] = cat_counts.get(c, 0) + 1
    for c, n in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"      {c:15s} {n:>10,}", flush=True)

    # ── push to Redis ─────────────────────────────────────────────
    print("\nWriting to Redis...", flush=True)
    pipe = rdb.pipeline(transaction=False)
    for key in ("blocklist:strict", "blocklist:weak", "blocklist:exact",
                "blocklist:meta", "blocklist:source", "blocklist:stats"):
        pipe.delete(key)
    CHUNK = 5000

    def chunked_sadd(key, items):
        items = list(items)
        for i in range(0, len(items), CHUNK):
            pipe.sadd(key, *items[i:i+CHUNK])

    chunked_sadd("blocklist:strict", strict.keys())
    chunked_sadd("blocklist:weak",   weak.keys())
    # union — back-compat with anything still reading the old key
    chunked_sadd("blocklist:exact",  domains.keys())

    # Compact metadata: "primary_cat|src1,src2,...|tier"
    meta_map = {}
    PRIMARY_CATS = ("phishing", "malware", "cryptomining", "ads", "tracking", "generic")
    for d, m in domains.items():
        primary = next((c for c in PRIMARY_CATS if c in m["cats"]), next(iter(m["cats"])))
        tier = "strict" if d in strict else "weak"
        meta_map[d] = f"{primary}|{','.join(sorted(m['srcs']))}|{tier}"
    items = list(meta_map.items())
    for i in range(0, len(items), CHUNK):
        pipe.hset("blocklist:meta", mapping=dict(items[i:i+CHUNK]))

    if per_source:
        pipe.hset("blocklist:stats", mapping={k: str(v) for k, v in per_source.items()})
    pipe.set("blocklist:fetched_at", int(time.time()))
    pipe.set("blocklist:size", len(domains))
    pipe.set("blocklist:strict_size", len(strict))
    pipe.set("blocklist:weak_size", len(weak))
    pipe.execute()

    # ── write Bloom source files ─────────────────────────────────
    # Strict feeds the resolver's NXDOMAIN bloom; weak feeds the WARN-tier
    # bloom (will be wired in resolver next).
    (OUT_DIR / "blocklist.strict.txt").write_text("\n".join(sorted(strict.keys())))
    (OUT_DIR / "blocklist.weak.txt").write_text("\n".join(sorted(weak.keys())))
    # Keep the legacy combined file for back-compat until resolver migrates.
    (OUT_DIR / "blocklist.txt").write_text("\n".join(sorted(domains.keys())))
    (OUT_DIR / "blocklist.urls.txt").write_text("\n".join(sorted(urls)))
    print(f"✓ wrote {OUT_DIR}/blocklist.strict.txt ({len(strict):,}) "
          f"+ blocklist.weak.txt ({len(weak):,})", flush=True)

    if failures:
        print(f"\n{len(failures)} feed(s) failed:", file=sys.stderr)
        for n, e in failures:
            print(f"  - {n}: {e}", file=sys.stderr)

    return 0


def _fetch_feed(feed: dict) -> tuple[dict, set[str], set[str]]:
    """Returns (feed, domains, urls). Raises on hard failure."""
    url = feed["url"]
    fmt = feed["format"]
    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True,
                      headers={"user-agent": "xgg-blocklist-fetcher/1.0"}) as c:
        r = c.get(url)
        r.raise_for_status()
        body = r.content if fmt == "zip" else r.text

    if fmt == "domains":
        return feed, _parse_domains(body), set()
    if fmt == "hosts":
        return feed, _parse_hosts(body), set()
    if fmt == "urls":
        return feed, *_parse_urls(body)
    if fmt == "phishtank":
        return feed, *_parse_phishtank(body)
    if fmt == "urlhaus":
        return feed, *_parse_urlhaus(body)
    if fmt == "threatfox":
        return feed, *_parse_threatfox(body)
    if fmt == "adguard":
        return feed, _parse_adguard(body), set()
    raise ValueError(f"unknown format: {fmt}")


# ── parsers ──────────────────────────────────────────────────────

def _parse_domains(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith(("#", "!", "//", "/*")):
            continue
        # also strip OISD wildcard prefix
        if line.startswith("*."):
            line = line[2:]
        if _VALID.match(line):
            out.add(line)
    return out


def _parse_hosts(text: str) -> set[str]:
    """`/etc/hosts` format: `0.0.0.0 example.com` or `127.0.0.1 example.com`."""
    out = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, host = parts[0], parts[1]
        if ip in ("0.0.0.0", "127.0.0.1", "::") and _VALID.match(host) and host != "localhost":
            out.add(host)
    return out


def _parse_urls(text: str) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith("http"):
            continue
        urls.add(line)
        d = _host_of(line)
        if d:
            domains.add(d)
    return domains, urls


def _parse_phishtank(text: str) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # PhishTank now returns 403/HTML to unauth users. Skip silently.
        return set(), set()
    for entry in data:
        u = entry.get("url")
        if u and u.startswith("http"):
            urls.add(u)
            d = _host_of(u)
            if d:
                domains.add(d)
    return domains, urls


def _parse_urlhaus(text: str) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        # CSV with quoted fields. URL is the 3rd column.
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) >= 3 and parts[2].startswith("http"):
            urls.add(parts[2])
            d = _host_of(parts[2])
            if d:
                domains.add(d)
    return domains, urls


def _parse_threatfox(text: str) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return set(), set()
    # ThreatFox structure: {"YYYY-MM-DD": [ {ioc:"...", ...}, ... ], ...}
    if isinstance(data, dict):
        entries = []
        for v in data.values():
            if isinstance(v, list):
                entries.extend(v)
    else:
        entries = data if isinstance(data, list) else []
    for e in entries:
        ioc = (e or {}).get("ioc", "")
        if ioc.startswith("http"):
            urls.add(ioc)
            d = _host_of(ioc)
            if d:
                domains.add(d)
        elif _VALID.match(ioc.lower()):
            domains.add(ioc.lower())
    return domains, urls


def _parse_adguard(text: str) -> set[str]:
    """AdGuard filter format. We accept only the pure-domain rules:
       `||example.com^` (block all subpaths)
       `0.0.0.0 example.com` (rare)
    """
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("!", "#", "[")):
            continue
        m = re.match(r"^\|\|([a-z0-9.-]+)\^", line)
        if m:
            d = m.group(1).lower()
            if _VALID.match(d):
                out.add(d)
            continue
        # hosts-style fallback
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            d = parts[1].lower()
            if _VALID.match(d):
                out.add(d)
    return out


# ── helpers ──────────────────────────────────────────────────────

def _host_of(url: str) -> str | None:
    try:
        h = urlparse(url).hostname
        if not h:
            return None
        h = h.lower().strip(".")
        return h if _VALID.match(h) else None
    except Exception:
        return None


if __name__ == "__main__":
    sys.exit(main())
