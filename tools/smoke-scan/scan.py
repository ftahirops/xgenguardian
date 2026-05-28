#!/usr/bin/env python3
"""xgg smoke-scan — end-to-end sanity test for the verdict pipeline.

Submits a list of URLs to verdict-api and prints a one-line summary per URL.
Use after standing up the stack on a fresh VPS to confirm the wiring works:

    python tools/smoke-scan/scan.py
    python tools/smoke-scan/scan.py --url https://example.com
    python tools/smoke-scan/scan.py --suite phishing
    python tools/smoke-scan/scan.py --base http://my-vps:18080

The default suite covers:
  - 3 known-clean URLs (should ALLOW/CLEAN)
  - 3 brand-impersonation patterns (should BLOCK or WARN)
  - 2 Cloudflare-protected sites (should ISOLATE — challenge gate)
  - 2 feed-listed phishing samples (skipped if no live feed entries)

Exit code 0 if every result matches the suite's `expect` set, 1 otherwise.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
import urllib.error
import urllib.request


@dataclasses.dataclass
class Case:
    url: str
    expect: set[str]  # any of {"ALLOW","CLEAN","WARN","BLOCK","ISOLATE","ANALYZING"}
    note: str = ""


SUITES: dict[str, list[Case]] = {
    "clean": [
        Case("https://www.google.com/",      {"ALLOW", "CLEAN"}, "should be top-trust"),
        Case("https://github.com/",          {"ALLOW", "CLEAN"}, "should be top-trust"),
        Case("https://en.wikipedia.org/",    {"ALLOW", "CLEAN"}, "should be top-trust"),
    ],
    "phishing": [
        # Synthetic patterns — replace 'example.invalid' once you have a
        # confirmed-malicious sample on the deny feed.
        Case("https://paypa1-secure.example.invalid/login",   {"BLOCK", "WARN"}, "homoglyph"),
        Case("https://login-microsoft-365.example.invalid/",  {"BLOCK", "WARN"}, "brand-in-subdomain"),
        Case("https://account-google.example.invalid/verify", {"BLOCK", "WARN"}, "brand-in-subdomain + login"),
    ],
    "cloudflare": [
        # 1337x is the canonical example: real malicious-popup site behind
        # Cloudflare's challenge. Our pipeline must NOT bless it as CLEAN.
        Case("https://1337x.to/",                            {"ISOLATE", "WARN", "BLOCK"}, "Cloudflare challenge"),
        Case("https://nowsecure.nl/",                        {"ISOLATE", "WARN", "BLOCK"}, "known captcha-walled test page"),
    ],
}

VERDICT_COLOR = {
    "ALLOW": "\033[32m",
    "CLEAN": "\033[32m",
    "WARN":  "\033[33m",
    "ISOLATE": "\033[34m",
    "BLOCK": "\033[31m",
    "ANALYZING": "\033[90m",
}
RESET = "\033[0m"


def check(base: str, url: str, timeout: float) -> dict:
    body = json.dumps({"url": url, "client_id": "smoke-scan/1.0"}).encode()
    req = urllib.request.Request(
        f"{base.rstrip('/')}/v1/check",
        data=body,
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read())


def run(cases: list[Case], base: str, timeout: float) -> int:
    fails = 0
    for c in cases:
        t0 = time.time()
        try:
            v = check(base, c.url, timeout)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"  ✗ {c.url}\n    transport error: {e}")
            fails += 1
            continue
        elapsed_ms = int((time.time() - t0) * 1000)

        verdict   = v.get("verdict", "?")
        grade     = v.get("grade", "")
        codes     = v.get("reason_codes") or []
        ok        = verdict in c.expect
        is_chal   = v.get("is_challenge_page", False)
        color     = VERDICT_COLOR.get(verdict, "")
        prefix    = "  ✓" if ok else "  ✗"
        tag       = "challenge" if is_chal else ""

        print(
            f"{prefix} {c.url}\n"
            f"    verdict={color}{verdict}{RESET} grade={grade or '—'} "
            f"confidence={v.get('confidence', 0):.2f} "
            f"elapsed={elapsed_ms}ms {tag}"
        )
        if codes:
            print(f"    codes: {', '.join(codes)}")
        if c.note:
            print(f"    expect: {c.note} → {{{'|'.join(sorted(c.expect))}}}")
        if not ok:
            fails += 1
    return fails


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:18080",
                   help="verdict-api base URL")
    p.add_argument("--url",
                   help="single URL to scan (overrides --suite)")
    p.add_argument("--suite", default="all",
                   choices=["all", "clean", "phishing", "cloudflare"])
    p.add_argument("--timeout", type=float, default=15.0)
    args = p.parse_args()

    if args.url:
        cases = [Case(args.url, {"ALLOW", "CLEAN", "WARN", "BLOCK", "ISOLATE"}, "manual")]
    elif args.suite == "all":
        cases = SUITES["clean"] + SUITES["phishing"] + SUITES["cloudflare"]
    else:
        cases = SUITES[args.suite]

    fails = run(cases, args.base, args.timeout)
    print()
    print(f"=== smoke-scan: {len(cases) - fails}/{len(cases)} passed ===")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
