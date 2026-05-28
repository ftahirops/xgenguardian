# On-Call

**TL;DR:** acknowledge fast, mitigate first, document everything, hand off cleanly.

## Rotation

- 1-week rotations, Mon 09:00 → Mon 09:00 (operator's local TZ).
- Primary + secondary. Secondary covers if primary is unreachable for 15 min.
- Schedule lives in PagerDuty / Linear under team `xgg-oncall`.

## Before Your Shift

- [ ] Read the last 7 days of `#incidents` and `#alerts`.
- [ ] Review `docs/runbooks/` for new entries.
- [ ] Verify your phone has PagerDuty installed + push notifications on.
- [ ] Verify VPN, SSH keys, AWS/DO CLI auth all work end-to-end.
- [ ] Run `scripts/smoke.sh` against staging and prod; both should pass.

## During Your Shift

- Carry the laptop. Always. No "just running to the store".
- Acknowledge any page in ≤5 minutes (mobile is fine for ack; laptop required for fix).
- Use `#incidents` for any S1/S2 — even if you think it'll resolve in a minute.
- For non-urgent tickets that arrive in `#alerts`, batch them; address within the shift.

## Common Alerts → First Move

| Alert | First move |
|---|---|
| `resolver_dns_query_errors > 1%` | Check upstream DNS health (Quad9, Cloudflare); roll back resolver if recent deploy |
| `verdict_api_latency_p99 > 5s` | `kubectl top pods` on verdict-api; check sandbox-render pool saturation |
| `sandbox_render_browser_crashes > 5/min` | Scale up sandbox-render replicas; rotate base image if memory leak suspected |
| `visual_match_pgvector_latency > 500ms` | Check `ivfflat` index; consider `lists` tuning or REINDEX |
| `ct_monitor_websocket_disconnects > 10/h` | Certstream is unreliable; fall back to crt.sh polling |
| `brand_registry_stale_minutes > 30` | Manually run hydrator: `kubectl exec verdict-api -- registry-refresh` |
| `evidence_bucket_4xx > 1%` | Check S3/Spaces credentials; permission drift on the bucket |
| `phishtank_ingest_failures > 3 consecutive` | PhishTank API changed format; check `tools/blocklist-fetcher/fetch.py` |

## Detection Quality Alerts

These are not S1 but pay attention:

- `false_positive_rate_1h > 0.5%` — investigate within 2 hours; we can't ship FPs.
- `phishtank_recall_24h < 0.40` — review fusion thresholds; check brand registry health.
- `block_rate_change_z > 3` — sudden spike or drop in blocks; usually intel feed issue.

## After Your Shift

- Handoff message in `#xgg-oncall` listing:
  - Open incidents (none if you did your job).
  - Anything noisy that didn't quite alert.
  - Any deploy you blocked / pushed.
- Update `docs/runbooks/` with anything you wished was there.

## Cardinal Rules

1. **Mitigate first, diagnose second.** Don't keep users degraded while you read a stack trace.
2. **Roll back is always an option.** If the last deploy was within 1h of the incident, roll it back before doing anything else.
3. **Two-person rule for destructive ops.** DROP TABLE, `terraform destroy`, force-push to main — never alone.
4. **You're not paid to be a hero.** Page the secondary. Page the team. Page me.
