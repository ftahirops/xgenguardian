"""XGenGuardian — bulk URL scanner.

Feed it a file of URLs and it sends each through verdict-api /v1/check in
parallel, prints a colored table, and writes the full JSON to disk.

Input formats it accepts:
  - Plain text:        one URL per line, blank/# comments ignored
  - JSON list:         ["https://...","https://..."]
  - Chrome history:    History DB exported as JSON (key: urls[].url)
  - Firefox history:   places.sqlite SELECT moz_places (just pipe SQL to text)

Usage:
  python scan.py urls.txt
  python scan.py --api http://localhost:18080 --concurrency 16 urls.txt
  python scan.py --out report.json urls.txt
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table

console = Console()


def load_urls(p: Path) -> list[str]:
    text = p.read_text(errors="ignore").strip()
    # JSON list?
    if text.startswith("["):
        try:
            data = json.loads(text)
            return [u for u in data if isinstance(u, str) and u.startswith("http")]
        except Exception:
            pass
    # Chrome export?
    if text.startswith("{") and '"urls"' in text:
        try:
            data = json.loads(text)
            return [
                entry["url"]
                for entry in data.get("urls", [])
                if isinstance(entry, dict) and entry.get("url", "").startswith("http")
            ]
        except Exception:
            pass
    # Plain text.
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("http"):
            urls.append(line)
    return urls


async def check_one(client: httpx.AsyncClient, api: str, url: str) -> dict:
    try:
        r = await client.post(f"{api}/v1/check", json={"url": url, "client_id": "bulk-scan"}, timeout=15)
        r.raise_for_status()
        out = r.json()
        out["url"] = url
        return out
    except Exception as e:
        return {"url": url, "verdict": "ERROR", "error": str(e)}


async def main_async(args: argparse.Namespace) -> int:
    urls = load_urls(Path(args.file))
    if args.limit:
        urls = urls[: args.limit]
    if not urls:
        console.print("[red]No URLs found in input.[/red]")
        return 2

    console.print(f"[blue]Scanning {len(urls)} URLs against {args.api} (concurrency={args.concurrency})[/blue]")

    sem = asyncio.Semaphore(args.concurrency)
    results: list[dict] = []

    async with httpx.AsyncClient() as client:
        async def task(u: str):
            async with sem:
                res = await check_one(client, args.api, u)
                results.append(res)
                v = res.get("verdict", "?")
                color = {"BLOCK": "red", "WARN": "yellow", "CLEAN": "green", "ANALYZING": "cyan"}.get(v, "white")
                console.print(f"  [{color}]{v:9}[/{color}] {u[:100]}")
        await asyncio.gather(*(task(u) for u in urls))

    # summary
    summary: dict[str, int] = {}
    for r in results:
        summary[r.get("verdict", "?")] = summary.get(r.get("verdict", "?"), 0) + 1
    t = Table(title="Summary")
    t.add_column("Verdict")
    t.add_column("Count", justify="right")
    for v, n in sorted(summary.items()):
        t.add_row(v, str(n))
    console.print(t)

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
        console.print(f"[green]Wrote {args.out} ({len(results)} entries)[/green]")

    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="path to URL list / Chrome history JSON / text")
    ap.add_argument("--api", default="http://localhost:18080", help="verdict-api base URL")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0, help="cap number of URLs scanned (0 = no cap)")
    ap.add_argument("--out", help="write full JSON results to this path")
    args = ap.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
