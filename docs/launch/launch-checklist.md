# Launch Checklist

## T-7 days

- [ ] All P0+P1 features in `architecture.md` §27 are at REVIEW or DONE.
- [ ] `make eval` against PhishTank last-24h corpus passes Phase-1 exit gates.
- [ ] `scripts/smoke.sh` passes against staging.
- [ ] Status page (`status.xgenguardian.com`) is live and Operational.
- [ ] Brand registry seeded with ≥50 brands and verified visually.
- [ ] CT-monitor running stable for 7+ days with no disconnects > 1 hr.
- [ ] Demo video recorded.
- [ ] Press release drafted; embargo plan agreed.
- [ ] Customer-support inbox routed to a real human.
- [ ] Postmortem template + incident-response runbook reviewed.

## T-3 days

- [ ] Production stack deployed; canary at 10% traffic for at least 48 hours.
- [ ] No new error types in Sentry; no SLO breaches in Grafana.
- [ ] Email to waitlist drafted, queued (not sent).
- [ ] HN/X/Reddit posts proofread by 2+ people.
- [ ] Founders' personal accounts ready for engagement.
- [ ] Press release sent under embargo to selected journalists.
- [ ] Pricing flow + Stripe end-to-end tested with a real card.

## T-1 day

- [ ] All staging issues triaged; no S2+ open.
- [ ] On-call rotation announced; primary + secondary committed for 12 hr launch window.
- [ ] Mental checklist: "What will I do if traffic 10×s in an hour?" → answer documented in runbook.
- [ ] Sleep.

## T-0 (Launch Day)

| Time (ET) | Action |
|---|---|
| 06:00 | Email waitlist + design partners. |
| 08:30 | Final smoke test on prod. |
| 09:00 | Submit HN post. |
| 09:05 | Update status page with "Launch day — extra traffic expected." |
| 10:00 | Reply to first 5 HN comments personally. |
| 12:00 | Post X thread. |
| 13:00 | Cross-post to Reddit (r/privacy, r/selfhosted, r/sysadmin). |
| 14:00 | Press embargo lifts. |
| 16:00 | First retro: what's breaking? |
| 22:00 | Hand off to next-day support shift. |

## T+1 day

- [ ] Reply to every comment from launch day.
- [ ] Tabulate signups; analyze conversion funnel.
- [ ] Postmortem any outages.
- [ ] Update `docs/progress/PROGRESS.md` with launch-day metrics.

## T+7 days

- [ ] Public transparency report: signups, queries served, FPs caught, FN reports received.
- [ ] First customer interview scheduled (5 interviews in first month).
- [ ] Iterate landing page based on funnel data.
