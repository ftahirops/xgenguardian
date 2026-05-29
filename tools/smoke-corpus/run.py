#!/usr/bin/env python3
"""XGenGuardian smoke corpus runner.

Runs every case in cases.yaml through verdict-api's /v1/check endpoint,
classifies the actual verdict vs the expected band, and prints a
per-category confusion matrix + summary. Optionally writes a markdown
report.

Usage:
    python3 tools/smoke-corpus/run.py
    python3 tools/smoke-corpus/run.py --api http://127.0.0.1:18080 --out reports/smoke-$(date +%F).md
    python3 tools/smoke-corpus/run.py --force-rescan   # bypasses verdict cache
    python3 tools/smoke-corpus/run.py --concurrency 4  # parallel cases

This is the corpus the doc keeps demanding ("every change is measurable").
Pass/fail bands:

    allow      → ALLOW or CLEAN
    warn       → WARN
    block      → BLOCK
    isolate    → ISOLATE
    any-allow  → ALLOW or CLEAN
    any-deny   → WARN or BLOCK or ISOLATE
    any        → anything is accepted (use sparingly; only when the
                 expectation is genuinely ambiguous)

The script is designed to be cron-able and CI-able. Exits 0 when all
cases pass their expected band; exits 1 otherwise. The summary is the
last thing printed so it can be tailed cheaply.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "[error] pyyaml is required. pip install pyyaml — or apt install python3-yaml\n"
    )
    sys.exit(2)


# ---------- expectation matching ----------


def matches_expectation(verdict: str, expect: str) -> bool:
    """Return True when actual verdict satisfies the expected band."""
    v = (verdict or "").upper()
    e = expect.lower()
    if e == "any":
        return True
    if e == "any-allow":
        return v in ("ALLOW", "CLEAN")
    if e == "any-deny":
        return v in ("WARN", "BLOCK", "ISOLATE")
    if e == "allow":
        return v in ("ALLOW", "CLEAN")
    if e == "warn":
        return v == "WARN"
    if e == "block":
        return v == "BLOCK"
    if e == "isolate":
        return v == "ISOLATE"
    return False


# ---------- runner ----------


def fetch_verdict(api: str, url: str, timeout: float, force_rescan: bool) -> dict[str, Any]:
    body = json.dumps({"url": url, "force_rescan": force_rescan}).encode("utf-8")
    req = urllib.request.Request(
        f"{api.rstrip('/')}/v1/check",
        data=body,
        method="POST",
        headers={"content-type": "application/json"},
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read().decode("utf-8", errors="replace"))
    except urllib.error.URLError as e:
        return {"error": f"network: {e}", "latency_ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"error": f"exception: {e!s}", "latency_ms": int((time.time() - t0) * 1000)}
    payload["latency_ms"] = int((time.time() - t0) * 1000)
    return payload


def run_case(api: str, case: dict[str, Any], timeout: float, force_rescan: bool) -> dict[str, Any]:
    resp = fetch_verdict(api, case["url"], timeout, force_rescan)
    verdict = resp.get("verdict", "")
    err = resp.get("error", "")
    passed = (not err) and matches_expectation(verdict, case["expect"])
    return {
        "name": case["name"],
        "url": case["url"],
        "category": case.get("category", "uncategorized"),
        "expected": case["expect"],
        "actual": verdict or "ERROR",
        "error": err,
        "latency_ms": resp.get("latency_ms", 0),
        "reason_codes": resp.get("reason_codes") or [],
        "passed": passed,
    }


# ---------- reporting ----------


def category_table(results: list[dict[str, Any]]) -> str:
    cats: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in results:
        cats[r["category"]].append(r)

    lines = ["| Category | Pass | Fail | Total | Rate |", "| --- | ---: | ---: | ---: | ---: |"]
    for cat in sorted(cats.keys()):
        rows = cats[cat]
        passed = sum(1 for r in rows if r["passed"])
        total = len(rows)
        rate = (passed / total * 100) if total else 0.0
        lines.append(f"| {cat} | {passed} | {total - passed} | {total} | {rate:.0f}% |")
    return "\n".join(lines)


def detail_table(results: list[dict[str, Any]]) -> str:
    lines = [
        "| Case | Category | Expected | Actual | Latency | Pass |",
        "| --- | --- | --- | --- | ---: | :---: |",
    ]
    for r in sorted(results, key=lambda r: (r["category"], r["name"])):
        mark = "✓" if r["passed"] else "✗"
        actual = r["actual"] if not r["error"] else f"ERR: {r['error'][:30]}"
        lines.append(
            f"| `{r['name']}` | {r['category']} | `{r['expected']}` | `{actual}` | {r['latency_ms']} ms | {mark} |"
        )
    return "\n".join(lines)


def failures_block(results: list[dict[str, Any]]) -> str:
    fails = [r for r in results if not r["passed"]]
    if not fails:
        return "_No failing cases._"
    lines = ["", "| Case | Expected | Actual | Reason codes |", "| --- | --- | --- | --- |"]
    for r in fails:
        codes = ", ".join(r["reason_codes"][:4]) or "—"
        actual = r["actual"] if not r["error"] else f"ERR: {r['error'][:60]}"
        lines.append(f"| `{r['name']}` | `{r['expected']}` | `{actual}` | {codes} |")
    return "\n".join(lines)


def render_report(results: list[dict[str, Any]], api: str, duration_s: float) -> str:
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    rate = (passed / total * 100) if total else 0.0

    lines = [
        f"# Smoke corpus report",
        "",
        f"- API base: `{api}`",
        f"- Cases: **{total}**",
        f"- Pass: **{passed}**  /  Fail: **{total - passed}**  /  Rate: **{rate:.1f}%**",
        f"- Wall-clock: {duration_s:.1f} s",
        "",
        "## Per-category breakdown",
        "",
        category_table(results),
        "",
        "## Failing cases",
        "",
        failures_block(results),
        "",
        "## Detailed per-case results",
        "",
        detail_table(results),
        "",
    ]
    return "\n".join(lines)


# ---------- main ----------


def main() -> int:
    p = argparse.ArgumentParser(description="XGG smoke corpus runner")
    p.add_argument("--api", default="http://127.0.0.1:18080")
    p.add_argument(
        "--cases",
        default=str(Path(__file__).parent / "cases.yaml"),
        help="cases.yaml path (default: alongside run.py)",
    )
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--force-rescan", action="store_true", help="bypass verdict cache")
    p.add_argument("--out", default=None, help="write markdown report to PATH")
    p.add_argument(
        "--filter-category",
        default=None,
        help="only run cases whose category matches this substring",
    )
    args = p.parse_args()

    with open(args.cases, "r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh)
    cases = loaded.get("cases") or []
    if args.filter_category:
        cases = [c for c in cases if args.filter_category in c.get("category", "")]

    t0 = time.time()
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {
            pool.submit(run_case, args.api, c, args.timeout, args.force_rescan): c
            for c in cases
        }
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            results.append(r)
            mark = "✓" if r["passed"] else "✗"
            line = (
                f"  [{mark}] {r['category']:<18} {r['name']:<35} "
                f"expect={r['expected']:<10} actual={r['actual']:<10} ({r['latency_ms']:>5} ms)"
            )
            if r["error"]:
                line += f"  err={r['error'][:60]}"
            print(line)
    duration = time.time() - t0

    md = render_report(results, args.api, duration)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"\nWrote: {out}")

    # Summary on stderr so it's the last thing visible even when piping.
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    rate = (passed / total * 100) if total else 0.0
    sys.stderr.write(
        f"\nSummary: {passed}/{total} pass ({rate:.1f}%)  duration={duration:.1f}s\n"
    )
    # Exit non-zero when any case fails — useful for CI.
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
