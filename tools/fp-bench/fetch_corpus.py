#!/usr/bin/env python3
"""fetch_corpus — refresh benign + malicious URL corpora.

Pulls from authoritative sources, writes labeled files into corpus/.
Idempotent: re-runs replace yesterday's snapshot. Curated list is left alone.

Sources:
  benign-tranco.txt        — Tranco top-N (research-grade replacement for Alexa)
  malicious-urlhaus.txt    — URLhaus recent malware URLs (last 7 days)
  malicious-openphish.txt  — OpenPhish current phishing feed

Usage:
  python fetch_corpus.py                   # refresh all
  python fetch_corpus.py --tranco-n 1000   # smaller benign list
  python fetch_corpus.py --skip benign     # only refresh malicious
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
URLHAUS_RECENT = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"


def _fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "xgg-fp-bench/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_tranco(n: int) -> list[str]:
    """Tranco top-N. Returns full URLs (https://domain/)."""
    data = _fetch(TRANCO_URL, timeout=180)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        with z.open(z.namelist()[0]) as f:
            reader = csv.reader(io.TextIOWrapper(f, "utf-8"))
            domains = [row[1] for row in reader if len(row) >= 2]
    return [f"https://{d}/" for d in domains[:n]]


def fetch_urlhaus_recent() -> list[str]:
    """URLhaus recent malware URLs. CSV with comment lines."""
    raw = _fetch(URLHAUS_RECENT).decode("utf-8", errors="ignore")
    urls = []
    for line in raw.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        cols = next(csv.reader([line]), None)
        if cols and len(cols) >= 3:
            url = cols[2].strip('"')
            if url.startswith(("http://", "https://")):
                urls.append(url)
    return urls


def fetch_openphish() -> list[str]:
    """OpenPhish current feed — newline-separated URLs."""
    raw = _fetch(OPENPHISH_FEED).decode("utf-8", errors="ignore")
    return [
        line.strip()
        for line in raw.splitlines()
        if line.strip().startswith(("http://", "https://"))
    ]


def write_file(path: Path, header: str, urls: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(header)
        for u in urls:
            f.write(u + "\n")
    print(f"  wrote {len(urls):>6} URLs -> {path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco-n", type=int, default=1000)
    ap.add_argument("--skip", choices=["benign", "malicious", "none"], default="none")
    ap.add_argument("--max-malicious", type=int, default=500,
                    help="Cap malicious sample size (full feeds are huge).")
    args = ap.parse_args()

    if args.skip != "benign":
        print(f"[benign] fetching Tranco top-{args.tranco_n}...")
        urls = fetch_tranco(args.tranco_n)
        write_file(
            CORPUS_DIR / "benign-tranco.txt",
            f"# Tranco top-{args.tranco_n}, fetched {os.popen('date -uIs').read().strip()}\n",
            urls,
        )

    if args.skip != "malicious":
        print("[malicious] fetching URLhaus recent...")
        urlhaus = fetch_urlhaus_recent()[: args.max_malicious]
        write_file(
            CORPUS_DIR / "malicious-urlhaus.txt",
            f"# URLhaus recent, fetched {os.popen('date -uIs').read().strip()}\n",
            urlhaus,
        )

        print("[malicious] fetching OpenPhish...")
        try:
            phish = fetch_openphish()[: args.max_malicious]
        except Exception as exc:
            print(f"  WARN: OpenPhish fetch failed ({exc}); keeping previous file")
            phish = []
        if phish:
            write_file(
                CORPUS_DIR / "malicious-openphish.txt",
                f"# OpenPhish feed, fetched {os.popen('date -uIs').read().strip()}\n",
                phish,
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
