# Postmortem Template

Copy this file to `docs/runbooks/incidents/YYYY-MM-DD-<slug>.md` after every S1/S2 incident. Due within **5 business days** of resolution.

Blameless. Focus on systems, not people.

---

## `INC-YYYY-MM-DD-<slug>`

- **Authors:** @who, @who
- **Status:** Draft / Final
- **Severity:** S1 / S2
- **Duration:** YYYY-MM-DD HH:MM → HH:MM UTC (h:mm total)
- **Customer impact:** N users affected; Y% of queries; $Z estimated revenue impact
- **Action-item owner:** @who

## Summary

One paragraph. What broke, what users saw, what fixed it. Written so an exec who skips the rest gets the picture.

## Impact

- Users affected: who, how many, when.
- Functional impact: what specifically could users not do?
- Data integrity: any data loss, corruption, exfil?
- Revenue / SLA: ARR at risk, SLA credits owed, contractual impact.
- Reputation: external reports, social mentions, customer complaints.

## Timeline (UTC)

| Time | Event |
|---|---|
| HH:MM | First alert fired (`metric_name > threshold`) |
| HH:MM | On-call paged |
| HH:MM | Incident declared S2 in `#incidents` |
| HH:MM | IC assigned (@who); status page updated |
| HH:MM | Hypothesis 1 (X) ruled out at HH:MM |
| HH:MM | Mitigation applied: <what> |
| HH:MM | Metric returned to baseline |
| HH:MM | Status page set to Operational |
| HH:MM | Incident closed |

## Root Cause

5-whys. Don't stop at the proximate cause.

1. **Why did the user-visible thing break?** (proximate)
2. **Why did that condition arise?**
3. **Why didn't we prevent it?**
4. **Why didn't we detect it sooner?**
5. **Why didn't we recover faster?**

End with one sentence stating the root cause unambiguously.

## Contributing Factors

Things that didn't *cause* it but made it worse:
- Alert latency
- Missing runbook
- Recently shipped change that interacted badly
- Vendor outage
- Knowledge gap on the on-call team
- Tool / tooling deficiency

## What Went Well

Genuinely. Examples:
- On-call ack'd within 90s.
- Rollback worked first time.
- Customer comms went out before customers asked.

## What Went Poorly

Examples:
- Alert fired only after 8 min of user impact.
- IC and on-call were the same person (no scribe).
- Rollback bricked the canary because migration was already applied.
- Internal Slack flooded; no single source of truth.

## Lessons

Three to five lessons. Each one should be defensible if questioned in 6 months. "We should have monitoring" is too vague; "We need a SLO for resolver SERVFAIL rate with a 2-min alert" is right.

## Action Items

Each item has owner + due date + ticket. **Action items without owners and dates are wishes.**

| # | Action | Type | Owner | Due | Ticket |
|---|---|---|---|---|---|
| 1 | Add SLO + alert for X | prevention | @who | YYYY-MM-DD | XGG-NNN |
| 2 | Runbook entry for Y | process    | @who | YYYY-MM-DD | XGG-NNN |
| 3 | Refactor Z to avoid the foot-gun | fix | @who | YYYY-MM-DD | XGG-NNN |
| 4 | Vendor SLA conversation about <thing> | external | @who | YYYY-MM-DD | XGG-NNN |
| 5 | Replay drill: same incident in staging | drill | @who | YYYY-MM-DD | XGG-NNN |

## Customer Comms

- Status-page entry: `<link>`
- Email sent to: <segment>
- Slack/Discord channels notified: <list>
- Apology + credit issued? Yes / No / Pending exec decision.

## Appendix

- Dashboards: `<grafana link>`
- Slack threads: `<archive>`
- Relevant PRs / commits: `<links>`
- Stack traces, log excerpts, queries.

---

### Rules for postmortems

1. **Blameless.** Never name a person as a cause. People work inside systems; broken systems cause incidents.
2. **Public** to the whole company. Customer-facing version optional, but every internal incident is internally public.
3. **Action items make it back to** `docs/tasks/TASKS.md`. The postmortem is worthless if the items vanish.
4. **Re-read 30 days later.** What did we actually fix? Update the postmortem with status.
