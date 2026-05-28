# Incident Response

**TL;DR:** declare → page → mitigate → communicate → resolve → postmortem.

## Severity

| Sev | Meaning | Response time | Page |
|---|---|---|---|
| **S1** | Resolver down OR mass-FP (>1% of queries) OR data breach | 5 min | Yes, immediately |
| **S2** | One service degraded; user-visible but not total | 30 min | Yes, business hours immediate / off-hours next business day |
| **S3** | Degraded internals; users unaffected | 4 h | No, ticket |
| **S4** | Cosmetic / nuisance | next biz day | No |

## Step 1 — Declare

1. Drop a message in `#incidents` Slack channel: `INCIDENT S<N> <one-line>`.
2. Create an incident in your incident-management tool (e.g. incident.io).
3. **Take the IC role** (incident commander) yourself unless you're rolling out → page someone else.

## Step 2 — Page (if S1/S2)

- PagerDuty escalation policy: `xgg-oncall`.
- If the pager doesn't fire within 60s, manually call the on-call person.
- IC stays in the channel as scribe; on-call drives the fix.

## Step 3 — Mitigate Before Diagnose

Bias toward **stopping the bleeding** even if you don't yet know why.

| Symptom | First mitigation |
|---|---|
| Resolver returning SERVFAIL > 1% | Roll back to previous resolver image (`kubectl rollout undo deploy/resolver`) |
| Mass false positives | Globally lower BLOCK threshold to 0.95 via OPA hotfix (`scripts/policy-hotfix.sh`) |
| Verdict-API p99 > 5s | Disable Tier-2 sandbox dispatch (`HTTP_FLAG_TIER2=off`); accept lower accuracy temporarily |
| Postgres CPU 100% | Kill long-running queries; scale up Postgres tier |
| Evidence bucket throttling | Switch to backup bucket region; queue uploads |
| CT-monitor flooding prescan_queue | Pause the service; drain queue; raise keyword threshold |
| Brand registry returning empty | Disable identity-mismatch rule (`FUSION_FLAG_IDMISMATCH=off`); investigate |

## Step 4 — Communicate

- Status page (`status.xgenguardian.com`) updated within 15 min of declaration.
- Internal `#incidents` channel: post the timeline of every action you take.
- Customers paying ≥$1k/mo: email contact within 30 min for S1.
- Twitter/X update only after the dust settles.

## Step 5 — Resolve

- Confirm via dashboards that the metric returned to baseline for **≥15 min sustained**.
- Set status page back to "Operational".
- Mark incident resolved in incident.io.

## Step 6 — Postmortem

Within 5 business days for S1/S2, post-mortem doc in `docs/runbooks/incidents/YYYY-MM-DD-<slug>.md`:

- Summary
- Impact (users affected, duration, revenue impact if any)
- Timeline (UTC timestamps)
- Root cause (5-whys, not just proximate)
- Contributing factors
- What went well
- What didn't
- Action items with owners + dates

Blameless. The goal is system improvement, not punishment.

## Verification

The incident is over when:
- Metric is at baseline for ≥15 min.
- Status page is green.
- On-call confirms no related alerts firing.
- An action-item ticket exists in `docs/tasks/TASKS.md` for every "what didn't".
