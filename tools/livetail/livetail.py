#!/usr/bin/env python3
"""XGenGuardian — live debug tail of every /v1/check.

Streams the verdict-api journal, filters to per-URL `check` events, and
pretty-prints each one as a multi-section block. Reads STRUCTURED JSON
logs when verdict-api is started with XGG_LOG_JSON=1; falls back to
parsing ConsoleWriter output otherwise.

Usage:
  python3 tools/livetail/livetail.py                 # tail forever
  python3 tools/livetail/livetail.py --since 5min    # backfill + tail
  python3 tools/livetail/livetail.py --no-color      # plain text
  python3 tools/livetail/livetail.py --host google.com   # filter
  python3 tools/livetail/livetail.py --verdict BLOCK     # filter

What you see per check:
  ─────────────────────────────────────────────
  19:42:01.234  google.com                                 [ALLOW   B]
    url           https://google.com/
    page_class    generic         confidence  0.50    latency  47 ms
    trust_score   0.86            age (days)  10483   cached   no
    reason_codes  -
    clearance     feed=pass vendor_dns=pass domain_age=pass …
    visual        -
  ─────────────────────────────────────────────

Reason codes, clearance failures, and block reasons highlight in red when
the verdict is non-ALLOW; non-zero overrides (Phase G) summarized as a
trailing line when present.

The script is read-only — it reads journald, never touches verdict-api,
never POSTs anywhere. Safe to leave running.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Optional

# ---------- color ----------

USE_COLOR = sys.stdout.isatty()


def c(s: str, code: str) -> str:
    if not USE_COLOR:
        return s
    return f"\033[{code}m{s}\033[0m"


def red(s: str) -> str: return c(s, "31")
def green(s: str) -> str: return c(s, "32")
def yellow(s: str) -> str: return c(s, "33")
def blue(s: str) -> str: return c(s, "34")
def magenta(s: str) -> str: return c(s, "35")
def cyan(s: str) -> str: return c(s, "36")
def dim(s: str) -> str: return c(s, "2")
def bold(s: str) -> str: return c(s, "1")


VERDICT_COLOR = {
    "ALLOW":   green,
    "WARN":    yellow,
    "BLOCK":   red,
    "ISOLATE": magenta,
}


# ---------- model ----------

@dataclass
class CheckEvent:
    time:               str
    url:                str
    verdict:            str
    confidence:         float
    grade:              str
    page_class:         str
    reason_codes:       list[str]
    trust_score:        float
    domain_age_days:    int
    cached:             bool
    is_challenge_page:  bool
    strictness_applied: bool
    visual_top_brand:   str
    visual_top_score:   float
    vendor_dns_blocked_by: list[str]
    clearance:          dict[str, str]
    block_reason:       str
    latency_ms:         int
    decision_trace:     list[dict[str, Any]]


# ---------- parse ----------

JSON_LINE = re.compile(r'\{.*"message"\s*:\s*"check".*\}\s*$')
URL_RE = re.compile(r"url=(\S+)")
KV_RE = re.compile(r"(\w+)=(\S+)")


def parse_json_message(msg: str) -> Optional[CheckEvent]:
    """Parse a zerolog JSON line with message=='check'."""
    try:
        d = json.loads(msg)
    except json.JSONDecodeError:
        return None
    if d.get("message") != "check":
        return None
    return CheckEvent(
        time=str(d.get("time", "")),
        url=str(d.get("url", "")),
        verdict=str(d.get("verdict", "")),
        confidence=float(d.get("confidence", 0.0) or 0.0),
        grade=str(d.get("grade", "") or ""),
        page_class=str(d.get("page_class", "") or ""),
        reason_codes=list(d.get("reason_codes", []) or []),
        trust_score=float(d.get("trust_score", 0.0) or 0.0),
        domain_age_days=int(d.get("domain_age_days", 0) or 0),
        cached=bool(d.get("cached", False)),
        is_challenge_page=bool(d.get("is_challenge_page", False)),
        strictness_applied=bool(d.get("strictness_applied", False)),
        visual_top_brand=str(d.get("visual_top_brand", "") or ""),
        visual_top_score=float(d.get("visual_top_score", 0.0) or 0.0),
        vendor_dns_blocked_by=list(d.get("vendor_dns_blocked_by", []) or []),
        clearance=dict(d.get("clearance", {}) or {}),
        block_reason=str(d.get("block_reason", "") or ""),
        latency_ms=int(d.get("latency_ms", 0) or 0),
        decision_trace=list(d.get("decision_trace", []) or []),
    )


def parse_console_message(line: str) -> Optional[CheckEvent]:
    """Parse the human/ConsoleWriter `INF check url=... verdict=...` form."""
    if " check " not in line and not line.rstrip().endswith(" check"):
        return None
    # Strip ANSI then tokenize key=value pairs.
    clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
    if "check" not in clean:
        return None
    pairs = dict(KV_RE.findall(clean))
    if "url" not in pairs or "verdict" not in pairs:
        return None
    # ConsoleWriter doesn't include arrays cleanly; we render what we have.
    return CheckEvent(
        time=pairs.get("time", ""),
        url=pairs.get("url", ""),
        verdict=pairs.get("verdict", ""),
        confidence=float(pairs.get("confidence", "0") or 0),
        grade=pairs.get("grade", ""),
        page_class=pairs.get("page_class", ""),
        reason_codes=[],
        trust_score=float(pairs.get("trust_score", "0") or 0),
        domain_age_days=int(pairs.get("domain_age_days", "0") or 0),
        cached=pairs.get("cached", "false") == "true",
        is_challenge_page=pairs.get("is_challenge_page", "false") == "true",
        strictness_applied=pairs.get("strictness_applied", "false") == "true",
        visual_top_brand=pairs.get("visual_top_brand", ""),
        visual_top_score=float(pairs.get("visual_top_score", "0") or 0),
        vendor_dns_blocked_by=[],
        clearance={},
        block_reason="",
        latency_ms=int(pairs.get("latency_ms", "0") or 0),
        decision_trace=[],
    )


def parse_line(raw: str) -> Optional[CheckEvent]:
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("{"):
        ev = parse_json_message(raw)
        if ev is not None:
            return ev
    return parse_console_message(raw)


# ---------- render ----------

def host_of(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/]+)/?", url, re.IGNORECASE)
    return m.group(1).lower() if m else url


def fmt_clearance(checks: dict[str, str]) -> str:
    if not checks:
        return dim("-")
    parts = []
    for k in sorted(checks.keys()):
        v = checks[k]
        s = f"{k}={v}"
        if v == "pass":
            parts.append(green(s))
        elif v == "warn":
            parts.append(yellow(s))
        elif v == "fail":
            parts.append(red(s))
        else:
            parts.append(dim(s))
    return " ".join(parts)


def fmt_reason_codes(codes: list[str], verdict: str) -> str:
    if not codes:
        return dim("-")
    color = red if verdict in ("BLOCK", "ISOLATE") else yellow
    return " ".join(color(code) for code in codes)


def render(ev: CheckEvent) -> str:
    width = shutil.get_terminal_size((100, 24)).columns
    rule = dim("─" * max(60, width))

    color_verdict = VERDICT_COLOR.get(ev.verdict, lambda s: s)
    verdict_tag = f"[{color_verdict(bold(f'{ev.verdict:<7}'))} {ev.grade or '-'}]"

    time_short = ev.time.split("T")[-1][:12] if ev.time else ""

    host = host_of(ev.url)
    header = f"{dim(time_short):<14} {bold(host):<48} {verdict_tag}"

    lines = [rule, header]

    def row(label: str, *cells: str) -> str:
        joined = "    ".join(cells)
        return f"  {dim(label):<14}{joined}"

    lines.append(row("url", ev.url))

    page_class = ev.page_class or dim("-")
    confidence = f"{ev.confidence:.2f}"
    latency = f"{ev.latency_ms} ms"
    lines.append(row(
        "page_class", f"{page_class:<14}",
        f"{dim('confidence')}  {confidence}",
        f"{dim('latency')}  {latency}",
    ))

    trust = f"{ev.trust_score:.2f}"
    age = str(ev.domain_age_days) if ev.domain_age_days else dim("-")
    cached_label = green("yes") if ev.cached else dim("no")
    lines.append(row(
        "trust_score", f"{trust:<14}",
        f"{dim('age (days)')}  {age}",
        f"{dim('cached')}  {cached_label}",
    ))

    lines.append(row("reason_codes", fmt_reason_codes(ev.reason_codes, ev.verdict)))
    lines.append(row("clearance", fmt_clearance(ev.clearance)))

    if ev.visual_top_brand:
        lines.append(row(
            "visual",
            f"{ev.visual_top_brand:<14}",
            f"{dim('score')}  {ev.visual_top_score:.2f}",
        ))

    if ev.vendor_dns_blocked_by:
        lines.append(row("vendor_dns", red(", ".join(ev.vendor_dns_blocked_by))))

    if ev.is_challenge_page:
        lines.append(row("flags", yellow("challenge_page")))
    if ev.strictness_applied:
        lines.append(row("flags", yellow("executive_mode_applied")))

    if ev.block_reason:
        lines.append(row("note", ev.block_reason))

    if ev.decision_trace:
        lines.append("")
        lines.append(f"  {dim('DECISION TRACE')}")
        for step in ev.decision_trace:
            stage = str(step.get("stage", ""))
            code = str(step.get("code", ""))
            outcome = str(step.get("outcome", ""))
            detail = str(step.get("detail", ""))
            weight = step.get("weight", 0) or 0
            outcome_color = {
                "fired":      red,
                "fail":       red,
                "suppressed": yellow,
                "skip":       dim,
                "pass":       green,
                "ALLOW":      green,
                "WARN":       yellow,
                "BLOCK":      red,
                "ISOLATE":    magenta,
            }.get(outcome, lambda s: s)
            tag = outcome_color(f"{outcome:<11}")
            stage_label = cyan(f"{stage:<7}")
            code_label = bold(code) if code else dim("-")
            line = f"    {stage_label} {tag} {code_label:<32}  {dim(detail)}"
            if weight:
                line += f"  {dim(f'(w={weight:.2f})')}"
            lines.append(line)

    return "\n".join(lines) + "\n"


# ---------- main ----------

def stream_journal(since: Optional[str]) -> Iterable[str]:
    cmd = ["journalctl", "-fu", "xgg-verdict-api", "-o", "cat", "--no-pager"]
    if since:
        cmd += ["--since", since]
    env = os.environ.copy()
    env["SYSTEMD_COLORS"] = "0"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, env=env)
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            yield line
    finally:
        proc.terminate()


def main() -> int:
    global USE_COLOR
    p = argparse.ArgumentParser(description="Live tail of XGG /v1/check events.")
    p.add_argument("--since", help="journalctl --since (e.g. '5min ago', 'today')")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--host", help="filter to host substring")
    p.add_argument("--verdict", choices=["ALLOW", "WARN", "BLOCK", "ISOLATE"],
                   help="filter to one verdict")
    args = p.parse_args()

    if args.no_color or not sys.stdout.isatty():
        USE_COLOR = False

    print(dim("livetail: streaming xgg-verdict-api /v1/check events. Ctrl-C to stop."))
    print()

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    try:
        for raw in stream_journal(args.since):
            ev = parse_line(raw)
            if ev is None:
                continue
            host = host_of(ev.url)
            if args.host and args.host not in host:
                continue
            if args.verdict and ev.verdict != args.verdict:
                continue
            print(render(ev), flush=True)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
