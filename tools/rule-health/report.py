"""XGenGuardian — weekly rule-health report.

Phase G data-flywheel report. Reads the policy_events table (populated
by /v1/telemetry/override) and the xgg_rule_fired_total Prometheus
counter, then produces a markdown summary of:

  * top rules by override rate         (users push past it → too aggressive?)
  * top rules by FP-report count       (someone explicitly flagged it wrong)
  * rules that fire often but never see WARN/BLOCK in production
  * rules that never fire              (dead code? threshold too tight?)
  * comparison vs prior week           (when last week's report exists)

Inputs:
  --db DSN                  Postgres DSN (default: env PG_DSN or
                            postgres://xgg:xgg@localhost:15432/xgg)
  --metrics URL             Prometheus scrape endpoint of verdict-api
                            (default: http://127.0.0.1:18080/metrics)
  --days N                  window in days (default: 7)
  --out PATH                output markdown path
                            (default: reports/rule-health-<DATE>.md)
  --prev PATH               prior report path for delta column (optional)

Privacy: the source table contains only host + url_hash + reason_codes,
never raw URLs or raw client_ids. The report aggregates by reason code
and shows top hosts by event count — never specific URLs.

Run weekly via cron:

  0 7 * * 1   cd /home/xgenguardian/code && \\
                  python3 tools/rule-health/report.py
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="XGG rule-health report")
    p.add_argument("--db", default=os.environ.get("PG_DSN", "postgres://xgg:xgg@localhost:15432/xgg"))
    p.add_argument("--metrics", default=os.environ.get("METRICS_URL", "http://127.0.0.1:18080/metrics"))
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--out", default=None)
    p.add_argument("--prev", default=None)
    return p.parse_args()


def fetch_fired_counts(metrics_url: str) -> dict[str, float]:
    """Scrape xgg_rule_fired_total{code=...} from /metrics.

    We do NOT depend on a Prometheus server — this hits the local
    verdict-api scrape endpoint directly. Returns {code: count}.
    """
    import urllib.request

    pattern = re.compile(r'^xgg_rule_fired_total\{code="([^"]+)"\}\s+([0-9.eE+-]+)\s*$')
    out: dict[str, float] = {}
    try:
        with urllib.request.urlopen(metrics_url, timeout=10) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                m = pattern.match(line)
                if m:
                    out[m.group(1)] = float(m.group(2))
    except OSError as e:
        print(f"[warn] could not scrape metrics endpoint {metrics_url}: {e}", file=sys.stderr)
    return out


def fetch_event_aggregates(dsn: str, days: int) -> dict[str, Any]:
    """Pull per-rule override/fp/fn counts and top-hosts from policy_events.

    Returns: {
      "overrides": {code: count},
      "fp_reports": {code: count},
      "fn_reports": {code: count},  # FN reports may have no codes; bucketed under "_unknown"
      "top_hosts":  [(host, count), ...],   # up to 20
      "total_events": int,
      "window_start": datetime,
    }
    """
    import psycopg2  # local import so the script runs without psycopg2 installed if you only want the metrics scrape

    overrides: dict[str, int] = {}
    fp_reports: dict[str, int] = {}
    fn_reports: dict[str, int] = {}
    top_hosts: list[tuple[str, int]] = []
    total = 0
    start = dt.datetime.utcnow() - dt.timedelta(days=days)

    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        # Per-rule x action counts, exploding the JSONB array of codes.
        cur.execute(
            """
            SELECT action, code, COUNT(*)
            FROM policy_events,
                 LATERAL jsonb_array_elements_text(reason_codes) AS code
            WHERE occurred_at >= %s
            GROUP BY action, code
            """,
            (start,),
        )
        for action, code, count in cur.fetchall():
            bucket = {
                "override_warn": overrides,
                "override_block": overrides,
                "report_fp": fp_reports,
                "report_fn": fn_reports,
            }.get(action)
            if bucket is None:
                continue
            bucket[code] = bucket.get(code, 0) + int(count)

        cur.execute(
            "SELECT host, COUNT(*) FROM policy_events WHERE occurred_at >= %s AND host IS NOT NULL "
            "GROUP BY host ORDER BY COUNT(*) DESC LIMIT 20",
            (start,),
        )
        top_hosts = [(row[0], int(row[1])) for row in cur.fetchall()]

        cur.execute("SELECT COUNT(*) FROM policy_events WHERE occurred_at >= %s", (start,))
        total = int(cur.fetchone()[0])

    return {
        "overrides": overrides,
        "fp_reports": fp_reports,
        "fn_reports": fn_reports,
        "top_hosts": top_hosts,
        "total_events": total,
        "window_start": start,
    }


def render_report(
    fired: dict[str, float],
    agg: dict[str, Any],
    days: int,
    prev: Optional[dict[str, float]] = None,
) -> str:
    """Render the markdown report.

    override_rate = overrides[code] / fired[code]   (0 if fired[code] == 0)
    fp_rate       = fp_reports[code] / fired[code]
    """
    overrides = agg["overrides"]
    fp_reports = agg["fp_reports"]
    fn_reports = agg["fn_reports"]
    total_events = agg["total_events"]
    window_start = agg["window_start"]

    all_codes = set(fired) | set(overrides) | set(fp_reports)

    def rate(num: int, denom: float) -> float:
        return (num / denom) if denom > 0 else 0.0

    rows = []
    for code in all_codes:
        f = fired.get(code, 0.0)
        ov = overrides.get(code, 0)
        fp = fp_reports.get(code, 0)
        rows.append({
            "code": code,
            "fired": f,
            "overrides": ov,
            "fp_reports": fp,
            "override_rate": rate(ov, f),
            "fp_rate": rate(fp, f),
        })

    top_override = sorted(rows, key=lambda r: r["override_rate"], reverse=True)[:10]
    top_fp = sorted(rows, key=lambda r: r["fp_reports"], reverse=True)[:10]
    never_fires = sorted([r for r in rows if r["fired"] == 0 and r["overrides"] == 0], key=lambda r: r["code"])

    lines: list[str] = []
    lines.append(f"# Rule health — {days}-day window")
    lines.append("")
    lines.append(f"Window start (UTC): {window_start.isoformat(timespec='seconds')}")
    lines.append(f"Total policy events: **{total_events}**")
    lines.append("")

    lines.append("## Top 10 rules by override rate")
    lines.append("")
    lines.append("Users clicking past the verdict for this code. High rate ⇒ rule is too aggressive OR the warn page is unclear.")
    lines.append("")
    lines.append("| Rule | Fires | Overrides | Override rate |")
    lines.append("| --- | ---: | ---: | ---: |")
    for r in top_override:
        if r["overrides"] == 0:
            continue
        lines.append(f"| `{r['code']}` | {int(r['fired'])} | {r['overrides']} | {r['override_rate']:.1%} |")
    lines.append("")

    lines.append("## Top 10 rules by FP reports")
    lines.append("")
    lines.append("Explicit false-positive flags from operators or users. Each row is a corpus-entry candidate.")
    lines.append("")
    lines.append("| Rule | Fires | FP reports | FP rate |")
    lines.append("| --- | ---: | ---: | ---: |")
    for r in top_fp:
        if r["fp_reports"] == 0:
            continue
        lines.append(f"| `{r['code']}` | {int(r['fired'])} | {r['fp_reports']} | {r['fp_rate']:.1%} |")
    lines.append("")

    lines.append("## Rules that never fired")
    lines.append("")
    if never_fires:
        lines.append("These reason codes are defined but produced no verdicts in the window. Either the path is dead, the threshold is too tight, or the corpus doesn't cover them.")
        lines.append("")
        for r in never_fires:
            lines.append(f"- `{r['code']}`")
    else:
        lines.append("_All known reason codes fired at least once._")
    lines.append("")

    lines.append("## False-negative reports")
    lines.append("")
    if fn_reports:
        lines.append("Operator/user-flagged missed bad sites. Each row should land in `tools/fp-bench/cases.yaml` as a corpus case.")
        lines.append("")
        lines.append("| Rule | FN reports |")
        lines.append("| --- | ---: |")
        for code, count in sorted(fn_reports.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"| `{code}` | {count} |")
    else:
        lines.append("_No false-negative reports in window._")
    lines.append("")

    lines.append("## Top hosts by event volume")
    lines.append("")
    if agg["top_hosts"]:
        lines.append("| Host | Events |")
        lines.append("| --- | ---: |")
        for host, count in agg["top_hosts"]:
            lines.append(f"| `{host}` | {count} |")
    else:
        lines.append("_No host events in window._")
    lines.append("")

    if prev is not None:
        lines.append("## Drift vs prior week")
        lines.append("")
        lines.append("Rules whose fire count moved ≥25 % since last report.")
        lines.append("")
        lines.append("| Rule | Prev | This | Δ |")
        lines.append("| --- | ---: | ---: | ---: |")
        for code in sorted(all_codes | set(prev)):
            now_n = fired.get(code, 0.0)
            prev_n = prev.get(code, 0.0)
            if prev_n == 0 and now_n == 0:
                continue
            if prev_n == 0:
                delta_label = "+∞ (new)"
            else:
                delta = (now_n - prev_n) / prev_n
                if abs(delta) < 0.25:
                    continue
                delta_label = f"{delta:+.0%}"
            lines.append(f"| `{code}` | {int(prev_n)} | {int(now_n)} | {delta_label} |")
        lines.append("")

    return "\n".join(lines) + "\n"


def parse_prev_report(path: str) -> dict[str, float]:
    """Re-extract per-code fire counts from a previous markdown report.

    Cheap parser — pulls `| `CODE` | N | ...` rows from the override-rate
    table. We never depend on having every code; we just want to compute
    week-over-week drift on the codes we DO know about.
    """
    out: dict[str, float] = {}
    row_re = re.compile(r"^\|\s*`([A-Z0-9_]+)`\s*\|\s*([0-9]+)\s*\|")
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            m = row_re.match(line)
            if m:
                out[m.group(1)] = max(out.get(m.group(1), 0.0), float(m.group(2)))
    except OSError as e:
        print(f"[warn] could not read prior report {path}: {e}", file=sys.stderr)
    return out


def main() -> int:
    args = parse_args()
    fired = fetch_fired_counts(args.metrics)
    try:
        agg = fetch_event_aggregates(args.db, args.days)
    except Exception as e:
        print(f"[error] policy_events query failed: {e}", file=sys.stderr)
        return 2

    prev = parse_prev_report(args.prev) if args.prev else None
    md = render_report(fired, agg, args.days, prev)

    if args.out:
        out_path = Path(args.out)
    else:
        date = dt.date.today().isoformat()
        out_path = Path("reports") / f"rule-health-{date}.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
