#!/usr/bin/env python3
"""gate — CI gate against bench-latest.json.

Reads the most recent bench report and exits non-zero if any threshold breached.
Used to block merges when accuracy regresses.

Thresholds (override via env):
  MAX_FP_RATE          default 0.001   (0.1%)
  MIN_TP_RATE          default 0.85
  MAX_BENIGN_HITS_PER_CODE  default 5  (per high-confidence reason code)
  MIN_BENIGN_SAMPLE    default 100     (must run against at least N benign URLs)

Output: human-readable verdict per check + non-zero exit on any failure.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPORT = Path(__file__).parent / "reports" / "bench-latest.json"

# Reason codes treated as "high-confidence" — these must almost never fire on
# benign URLs. If a code outside this list fires on benign that's noted but
# doesn't fail the gate (it might be a soft signal that combines with others).
HIGH_CONFIDENCE_CODES = {
    "FEED_MATCH_URLHAUS",
    "FEED_MATCH_PHISHTANK",
    "FEED_MATCH_OPENPHISH",
    "FEED_MATCH_WEBRISK",
    "VISUAL_REPLICA_HIGH",
    "CREDENTIAL_SINK_HIDDEN_MIRROR",
    "CREDENTIAL_SINK_PRE_SUBMIT_CAPTURE",
    "CREDENTIAL_SINK_MULTI_DESTINATION",
    "IDENTITY_MISMATCH_CERT",
    "MALWARE_BINARY_CONFIRMED",
}


def fail(msg: str) -> None:
    print(f"  ❌ FAIL: {msg}")


def ok(msg: str) -> None:
    print(f"  ✅ OK:   {msg}")


def main() -> int:
    if not REPORT.exists():
        print(f"No report at {REPORT}. Run run_bench.py first.", file=sys.stderr)
        return 2

    m = json.loads(REPORT.read_text())
    print(f"Gate against {REPORT} (ts={m.get('timestamp')})\n")

    failures = 0
    pl = m.get("per_label", {})

    max_fp = float(os.environ.get("MAX_FP_RATE", "0.001"))
    min_tp = float(os.environ.get("MIN_TP_RATE", "0.85"))
    max_hits = int(os.environ.get("MAX_BENIGN_HITS_PER_CODE", "5"))
    min_benign = int(os.environ.get("MIN_BENIGN_SAMPLE", "100"))

    if "benign" not in pl:
        fail("no benign results in report")
        failures += 1
    else:
        b = pl["benign"]
        sample = b["total"] - b["errors"]
        if sample < min_benign:
            fail(f"benign sample too small: {sample} < {min_benign}")
            failures += 1
        else:
            ok(f"benign sample size: {sample}")

        if b["fp_rate"] > max_fp:
            fail(f"FP rate {b['fp_rate']*100:.3f}% > {max_fp*100:.3f}% target")
            failures += 1
            print("    Top FP URLs:")
            for fp in b["fp_urls"][:10]:
                codes = ",".join(fp["codes"][:3])
                print(f"      {fp['url'][:70]} -> {fp['verdict']} [{codes}]")
        else:
            ok(f"FP rate: {b['fp_rate']*100:.3f}% (target <{max_fp*100:.3f}%)")

    if "malicious" not in pl:
        fail("no malicious results in report")
        failures += 1
    else:
        ml = pl["malicious"]
        sample = ml["total"] - ml["errors"]
        if sample == 0:
            fail("malicious sample is zero — feed fetch may have failed")
            failures += 1
        elif ml["tp_rate"] < min_tp:
            fail(f"TP rate {ml['tp_rate']*100:.1f}% < {min_tp*100:.1f}% target")
            failures += 1
        else:
            ok(f"TP rate: {ml['tp_rate']*100:.1f}% on {sample} URLs (target >{min_tp*100:.1f}%)")

    rc = m.get("per_reason_code", {})
    for code in HIGH_CONFIDENCE_CODES:
        v = rc.get(code)
        if not v:
            continue
        if v["benign_hits"] > max_hits:
            fail(f"high-confidence code {code} fired on benign {v['benign_hits']} times (max {max_hits})")
            failures += 1

    print()
    if failures:
        print(f"❌ GATE FAILED: {failures} check(s) failed")
        return 1
    print("✅ GATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
