#!/usr/bin/env python3
"""FP-bench runner.

Reads the corpora under tools/fp-bench/corpus/ and runs each URL through
the verdict-api at $VERDICT_API_URL (default localhost). Reports per-mode
FP rate (benign-* files) and per-category FN rate (malicious-* files)
plus a slow-URL list for performance investigation.

This is the foundation of the maturity-test §15 P2 row "Benign real-world
corpus" — adding ≥500 URLs and an FP threshold of 0.5% in Safe mode.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

VERDICT_API = os.environ.get("VERDICT_API_URL", "http://127.0.0.1:18080")
MODES_TO_TEST = ["safe", "ultra"]
TIMEOUT = 95
HERE = pathlib.Path(__file__).parent

CORPUS_DIR = HERE / "corpus"


def load_corpus(path: pathlib.Path) -> list[str]:
    urls = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        urls.append(s)
    return urls


def call_verdict(url: str, mode: str) -> dict:
    body = json.dumps({"url": url, "mode": mode, "client_id": "fp-bench"}).encode()
    req = urllib.request.Request(
        f"{VERDICT_API}/v1/check",
        data=body,
        headers={"content-type": "application/json"},
    )
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read())
            data["_elapsed_ms"] = int((time.monotonic() - t0) * 1000)
            return data
    except urllib.error.HTTPError as e:
        return {"verdict": f"HTTP-{e.code}", "_elapsed_ms": int((time.monotonic() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"verdict": "ERROR", "error": str(e)[:200], "_elapsed_ms": int((time.monotonic() - t0) * 1000)}


def is_block(v: str) -> bool:
    return v in ("BLOCK", "ISOLATE")


def main() -> int:
    print(f"verdict-api: {VERDICT_API}")
    print(f"corpus dir:  {CORPUS_DIR}")
    print()

    benign_files = sorted(CORPUS_DIR.glob("benign-*.txt"))
    malicious_files = sorted(CORPUS_DIR.glob("malicious-*.txt"))

    overall_fp = {m: {"total": 0, "fp": 0} for m in MODES_TO_TEST}
    overall_fn = {m: {"total": 0, "fn": 0} for m in MODES_TO_TEST}
    slow = []

    for f in benign_files:
        urls = load_corpus(f)
        if not urls:
            continue
        print(f"--- {f.name} ({len(urls)} URLs) ---")
        for mode in MODES_TO_TEST:
            for url in urls:
                r = call_verdict(url, mode)
                v = r.get("verdict", "?")
                ms = r.get("_elapsed_ms", 0)
                # Benign URL: FP if verdict is Block/Isolate
                if is_block(v):
                    overall_fp[mode]["fp"] += 1
                    print(f"  [{mode:5}] FP   {v:7} {url}")
                if v == "WARN":
                    print(f"  [{mode:5}] WARN          {url}")
                overall_fp[mode]["total"] += 1
                if ms >= 10000:
                    slow.append((ms, url, mode, v))
        print()

    for f in malicious_files:
        urls = load_corpus(f)
        if not urls:
            continue
        print(f"--- {f.name} ({len(urls)} URLs) ---")
        for mode in MODES_TO_TEST:
            for url in urls:
                r = call_verdict(url, mode)
                v = r.get("verdict", "?")
                ms = r.get("_elapsed_ms", 0)
                # Malicious URL: FN if verdict is Allow/Clean
                if v in ("ALLOW", "CLEAN"):
                    overall_fn[mode]["fn"] += 1
                    print(f"  [{mode:5}] FN   {v:7} {url}")
                overall_fn[mode]["total"] += 1
                if ms >= 10000:
                    slow.append((ms, url, mode, v))
        print()

    print("============================================================")
    print("SUMMARY")
    print("============================================================")
    for mode in MODES_TO_TEST:
        t = overall_fp[mode]["total"]
        fp = overall_fp[mode]["fp"]
        rate = (fp / t * 100) if t else 0
        print(f"  {mode:10} FP rate: {fp}/{t} ({rate:.2f}%)")
    for mode in MODES_TO_TEST:
        t = overall_fn[mode]["total"]
        fn = overall_fn[mode]["fn"]
        rate = (fn / t * 100) if t else 0
        print(f"  {mode:10} FN rate: {fn}/{t} ({rate:.2f}%)")
    if slow:
        slow.sort(reverse=True)
        print()
        print("Slowest URLs (>10s):")
        for ms, url, mode, v in slow[:10]:
            print(f"  {ms:6}ms [{mode:5}] {v:7} {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
