#!/usr/bin/env python3
"""run_bench — measure verdict-API accuracy against labeled corpora.

Reads URLs from corpus/, classifies each via POST /v1/check, computes:
  - FP rate    (legit URLs that returned WARN/BLOCK/ISOLATE)
  - TP rate    (malicious URLs that returned WARN/BLOCK/ISOLATE)
  - Per-reason-code breakdown (which codes fire on benign — those are the FP drivers)
  - Per-grade distribution
  - Latency p50/p95/p99

Writes:
  reports/bench-<timestamp>.json    machine-readable
  reports/bench-latest.json         symlink to most recent
  reports/bench-<timestamp>.md      human-readable summary

Exit code is 0 always — use gate.py to convert metrics to pass/fail.

Usage:
  python run_bench.py                              # full run
  python run_bench.py --base http://localhost:18080
  python run_bench.py --concurrency 4
  python run_bench.py --limit 50                   # quick smoke run
  python run_bench.py --only benign                # benign-only
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"
REPORT_DIR = Path(__file__).parent / "reports"

# What counts as a "block" verdict (non-ALLOW). Tune if you add new states.
BLOCK_VERDICTS = {"WARN", "BLOCK", "ISOLATE", "REQUIRE_APPROVAL"}
ALLOW_VERDICTS = {"ALLOW", "CLEAN"}


@dataclasses.dataclass
class Result:
    url: str
    label: str            # "benign" | "malicious"
    verdict: str
    grade: str
    confidence: float
    page_class: str
    reason_codes: list[str]
    latency_ms: int
    error: str | None = None


def load_corpus(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def classify(base: str, url: str, timeout: int) -> Result:
    body = json.dumps({"url": url}).encode()
    req = urllib.request.Request(
        f"{base.rstrip('/')}/v1/check",
        data=body,
        headers={"content-type": "application/json"},
    )
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            v = json.loads(r.read())
        dt_ms = int((time.monotonic() - t0) * 1000)
        return Result(
            url=url,
            label="",  # filled by caller
            verdict=v.get("verdict", "?"),
            grade=v.get("grade", "-"),
            confidence=float(v.get("confidence", 0) or 0),
            page_class=v.get("page_class", "-"),
            reason_codes=list(v.get("reason_codes", []) or []),
            latency_ms=dt_ms,
        )
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        return Result(
            url=url, label="", verdict="ERROR", grade="-", confidence=0,
            page_class="-", reason_codes=[],
            latency_ms=int((time.monotonic() - t0) * 1000), error=str(exc),
        )


def run(base: str, urls: list[tuple[str, str]], concurrency: int, timeout: int) -> list[Result]:
    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(classify, base, u, timeout): (u, lbl) for u, lbl in urls}
        total = len(futures)
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            url, lbl = futures[fut]
            r = fut.result()
            r.label = lbl
            results.append(r)
            done += 1
            if done % 25 == 0 or done == total:
                print(f"  [{done}/{total}] {lbl:9s} {r.verdict:8s} {url[:80]}",
                      file=sys.stderr)
    return results


def metrics(results: list[Result]) -> dict:
    by_label: dict[str, list[Result]] = defaultdict(list)
    for r in results:
        by_label[r.label].append(r)

    out: dict = {"timestamp": datetime.now(timezone.utc).isoformat()}
    out["per_label"] = {}
    for label, rs in by_label.items():
        total = len(rs)
        errs = sum(1 for r in rs if r.error)
        ok = total - errs
        if label == "benign":
            fp = [r for r in rs if not r.error and r.verdict in BLOCK_VERDICTS]
            allowed = [r for r in rs if not r.error and r.verdict in ALLOW_VERDICTS]
            out["per_label"][label] = {
                "total": total,
                "errors": errs,
                "fp_count": len(fp),
                "fp_rate": (len(fp) / ok) if ok else 0.0,
                "allowed_count": len(allowed),
                "fp_urls": [
                    {"url": r.url, "verdict": r.verdict, "grade": r.grade,
                     "codes": r.reason_codes, "page_class": r.page_class}
                    for r in fp
                ],
            }
        elif label == "malicious":
            tp = [r for r in rs if not r.error and r.verdict in BLOCK_VERDICTS]
            fn = [r for r in rs if not r.error and r.verdict in ALLOW_VERDICTS]
            out["per_label"][label] = {
                "total": total,
                "errors": errs,
                "tp_count": len(tp),
                "tp_rate": (len(tp) / ok) if ok else 0.0,
                "fn_count": len(fn),
                "fn_urls": [
                    {"url": r.url, "verdict": r.verdict, "grade": r.grade,
                     "codes": r.reason_codes, "page_class": r.page_class}
                    for r in fn
                ][:50],
            }

    # Per-reason-code: which codes fire on benign (= FP drivers)?
    code_benign: Counter = Counter()
    code_malicious: Counter = Counter()
    for r in results:
        if r.error:
            continue
        sink = code_benign if r.label == "benign" else code_malicious
        for c in r.reason_codes:
            sink[c] += 1
    out["per_reason_code"] = {}
    for code in set(code_benign) | set(code_malicious):
        b = code_benign.get(code, 0)
        m = code_malicious.get(code, 0)
        signal = m / (b + m) if (b + m) else 0
        out["per_reason_code"][code] = {
            "benign_hits": b,
            "malicious_hits": m,
            "signal_ratio": round(signal, 3),  # 1.0 = perfect, 0.5 = useless, <0.5 = inverted
        }

    # Latency
    lats = [r.latency_ms for r in results if not r.error]
    if lats:
        lats.sort()
        out["latency_ms"] = {
            "count": len(lats),
            "p50": lats[len(lats) // 2],
            "p95": lats[int(len(lats) * 0.95)],
            "p99": lats[int(len(lats) * 0.99)],
            "max": lats[-1],
        }

    return out


def markdown_report(m: dict) -> str:
    lines = [f"# fp-bench report — {m['timestamp']}\n"]
    pl = m.get("per_label", {})

    if "benign" in pl:
        b = pl["benign"]
        emoji = "✅" if b["fp_rate"] < 0.001 else ("⚠️" if b["fp_rate"] < 0.01 else "🔴")
        lines.append(f"## Benign corpus\n")
        lines.append(f"- Total: {b['total']} | Errors: {b['errors']}")
        lines.append(f"- **FP rate: {b['fp_rate']*100:.3f}%** ({b['fp_count']}/{b['total'] - b['errors']}) {emoji}")
        lines.append(f"- Target: < 0.1%\n")
        if b["fp_urls"]:
            lines.append("### False positives (must investigate):\n")
            lines.append("| URL | Verdict | Grade | Page class | Codes |")
            lines.append("|---|---|---|---|---|")
            for fp in b["fp_urls"][:30]:
                codes = ", ".join(fp["codes"][:5]) or "-"
                lines.append(f"| `{fp['url'][:60]}` | {fp['verdict']} | {fp['grade']} | {fp['page_class']} | {codes} |")
            lines.append("")

    if "malicious" in pl:
        ml = pl["malicious"]
        emoji = "✅" if ml["tp_rate"] > 0.85 else ("⚠️" if ml["tp_rate"] > 0.70 else "🔴")
        lines.append(f"## Malicious corpus\n")
        lines.append(f"- Total: {ml['total']} | Errors: {ml['errors']}")
        lines.append(f"- **TP rate: {ml['tp_rate']*100:.1f}%** ({ml['tp_count']}/{ml['total'] - ml['errors']}) {emoji}")
        lines.append(f"- Target: > 85%\n")
        if ml["fn_urls"]:
            lines.append("### Misses (false negatives — review):\n")
            for fn in ml["fn_urls"][:20]:
                lines.append(f"- `{fn['url'][:90]}` → {fn['verdict']} (grade {fn['grade']})")
            lines.append("")

    rc = m.get("per_reason_code", {})
    if rc:
        lines.append("## Reason-code signal quality\n")
        lines.append("Codes with `signal_ratio` < 0.7 are firing too often on benign URLs.\n")
        lines.append("| Code | Benign hits | Malicious hits | Signal |")
        lines.append("|---|---|---|---|")
        for code, v in sorted(rc.items(), key=lambda x: x[1]["signal_ratio"]):
            sig = v["signal_ratio"]
            flag = "🔴" if sig < 0.7 else ("⚠️" if sig < 0.9 else "✅")
            lines.append(f"| `{code}` | {v['benign_hits']} | {v['malicious_hits']} | {sig:.2f} {flag} |")
        lines.append("")

    lat = m.get("latency_ms", {})
    if lat:
        lines.append("## Latency\n")
        lines.append(f"- p50: {lat['p50']} ms | p95: {lat['p95']} ms | p99: {lat['p99']} ms | max: {lat['max']} ms\n")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:18080")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--limit", type=int, default=0, help="Cap per-label sample size (0 = no cap)")
    ap.add_argument("--only", choices=["benign", "malicious", "all"], default="all")
    args = ap.parse_args()

    urls: list[tuple[str, str]] = []
    if args.only in ("benign", "all"):
        for f in ("benign-curated.txt", "benign-tranco.txt"):
            for u in load_corpus(CORPUS_DIR / f):
                urls.append((u, "benign"))
    if args.only in ("malicious", "all"):
        for f in ("malicious-curated.txt", "malicious-urlhaus.txt", "malicious-openphish.txt"):
            for u in load_corpus(CORPUS_DIR / f):
                urls.append((u, "malicious"))

    if args.limit:
        by_lbl: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for u, l in urls:
            by_lbl[l].append((u, l))
        urls = []
        for lbl in by_lbl:
            urls.extend(by_lbl[lbl][: args.limit])

    if not urls:
        print("No URLs to test. Did you run fetch_corpus.py?", file=sys.stderr)
        return 1

    # de-dup
    seen = set()
    deduped = []
    for u, l in urls:
        if u in seen:
            continue
        seen.add(u)
        deduped.append((u, l))
    urls = deduped

    print(f"Testing {len(urls)} URLs against {args.base} (concurrency={args.concurrency})",
          file=sys.stderr)

    results = run(args.base, urls, args.concurrency, args.timeout)
    m = metrics(results)

    REPORT_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = REPORT_DIR / f"bench-{ts}.json"
    md_path = REPORT_DIR / f"bench-{ts}.md"
    json_path.write_text(json.dumps(m, indent=2))
    md_path.write_text(markdown_report(m))

    latest = REPORT_DIR / "bench-latest.json"
    latest_md = REPORT_DIR / "bench-latest.md"
    for sym, tgt in ((latest, json_path), (latest_md, md_path)):
        if sym.exists() or sym.is_symlink():
            sym.unlink()
        sym.symlink_to(tgt.name)

    print(f"\n=== Summary ===", file=sys.stderr)
    pl = m.get("per_label", {})
    if "benign" in pl:
        b = pl["benign"]
        print(f"  Benign:    FP {b['fp_count']}/{b['total']-b['errors']} = {b['fp_rate']*100:.3f}%",
              file=sys.stderr)
    if "malicious" in pl:
        ml = pl["malicious"]
        print(f"  Malicious: TP {ml['tp_count']}/{ml['total']-ml['errors']} = {ml['tp_rate']*100:.1f}%",
              file=sys.stderr)
    if "latency_ms" in m:
        lat = m["latency_ms"]
        print(f"  Latency:   p50={lat['p50']}ms p95={lat['p95']}ms p99={lat['p99']}ms",
              file=sys.stderr)
    print(f"\n  JSON:  {json_path}\n  MD:    {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
