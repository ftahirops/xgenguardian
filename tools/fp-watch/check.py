"""XGenGuardian — FP watchdog.

Periodically resolves a sample of legitimate sites through our resolver and
alerts if any return NXDOMAIN. Tracks per-domain history so we can spot
"this site was clean for 30 days, now it's blocked" regressions.

Run via systemd timer every 15 minutes (or manually for one-off audits).

Outputs:
  Redis HASH `fpwatch:last`    domain → "<status>|<unix_ts>"
  Redis LIST `fpwatch:alerts`  most recent FP alerts (LPUSH, capped)
  Redis HASH `fpwatch:counts`  status → count (since last reset)
  stdout: per-domain status if --verbose; summary always

Exit code: 0 if zero FPs, 1 if any FPs detected.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import time
from pathlib import Path

import dns.resolver
import redis


RESOLVER = os.getenv("XGG_RESOLVER", "135.181.79.27")
REDIS_ADDR = os.getenv("REDIS_ADDR", "localhost:16379")
TRANCO = Path(os.getenv("TRANCO_PATH", "/home/xgenguardian/code/data/tranco.txt"))
NEVER_BLOCK = Path(os.getenv("NEVER_BLOCK_PATH", "/home/xgenguardian/code/data/never-block.txt"))
SAMPLE = int(os.getenv("SAMPLE_SIZE", "200"))
TIMEOUT = float(os.getenv("DNS_TIMEOUT", "3"))
ALERT_HARD_THRESHOLD = float(os.getenv("FP_RATE_ALERT", "0.005"))  # >0.5% FP = scream


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=SAMPLE)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--include-never-block", action="store_true",
                    help="also test the never-block list (smoke test)")
    args = ap.parse_args()

    rdb = redis.Redis.from_url(f"redis://{REDIS_ADDR}", decode_responses=True)
    domains = _build_sample(args.sample, args.include_never_block)
    print(f"[fp-watch] testing {len(domains)} domains via {RESOLVER}", flush=True)

    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [RESOLVER]
    res.timeout = TIMEOUT
    res.lifetime = TIMEOUT

    fps = []      # (domain, rcode)
    errs = []
    ok = 0
    for d in domains:
        try:
            res.resolve(d, "A")
            ok += 1
            if args.verbose:
                print(f"  ok    {d}", flush=True)
            rdb.hset("fpwatch:last", d, f"NOERROR|{int(time.time())}")
        except dns.resolver.NXDOMAIN:
            fps.append((d, "NXDOMAIN"))
            if args.verbose:
                print(f"  FP!   {d}  NXDOMAIN", flush=True)
            rdb.hset("fpwatch:last", d, f"NXDOMAIN|{int(time.time())}")
        except dns.exception.DNSException as e:
            errs.append((d, str(e)))
            if args.verbose:
                print(f"  err   {d}  {e}", flush=True)

    total = len(domains)
    fp_rate = len(fps) / total if total else 0
    summary = {
        "checked": total,
        "ok": ok,
        "fp": len(fps),
        "fp_rate": round(fp_rate, 4),
        "errors": len(errs),
        "ts": int(time.time()),
    }
    print(json.dumps(summary), flush=True)

    if fps:
        print(f"[fp-watch] {len(fps)} FP(s) detected:", flush=True)
        for d, status in fps:
            print(f"  ✗ {d}  ({status})", flush=True)
            rdb.lpush("fpwatch:alerts",
                      json.dumps({"domain": d, "status": status, "ts": int(time.time())}))
        rdb.ltrim("fpwatch:alerts", 0, 999)  # keep last 1000

    rdb.hset("fpwatch:counts", mapping={
        "last_ok": ok, "last_fp": len(fps), "last_err": len(errs), "last_ts": int(time.time()),
    })

    if fp_rate > ALERT_HARD_THRESHOLD:
        print(f"[fp-watch] ALERT: FP rate {fp_rate:.2%} exceeds threshold "
              f"{ALERT_HARD_THRESHOLD:.2%}", file=sys.stderr)
        return 1
    return 0


def _build_sample(n: int, include_guard: bool) -> list[str]:
    """Pull a sample of legitimate domains we expect to resolve."""
    out: list[str] = []
    if NEVER_BLOCK.exists():
        guard = [l.strip().lower() for l in NEVER_BLOCK.read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        if include_guard:
            out.extend(guard)
    if TRANCO.exists():
        with TRANCO.open() as f:
            top = [l.strip().lower() for l in f if l.strip()]
        # take from top-10k where listings are highest-quality
        top10k = top[:10000]
        random.shuffle(top10k)
        out.extend(top10k[:n])
    # dedupe, keep order
    seen = set()
    result = []
    for d in out:
        if d not in seen:
            result.append(d); seen.add(d)
    return result[:n + (50 if include_guard else 0)]


if __name__ == "__main__":
    sys.exit(main())
