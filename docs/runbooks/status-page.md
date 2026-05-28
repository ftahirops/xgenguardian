# Status Page

**TL;DR:** truthful, fast, monitored. Update within 15 min of S1 declaration; resolve within 15 min of recovery.

## Where

`status.xgenguardian.com` — hosted on Instatus (or Atlassian Statuspage / Statushub — see ISS-N for vendor decision).

## Components We Report

These are the user-visible surfaces. Internal services are not listed here.

| Component | What it covers |
|---|---|
| **DoH Endpoint (dns.xgenguardian.com)** | Resolver answering encrypted DNS |
| **Verdict API** | URL checks via portal / extension / partner API |
| **Transparency Portal** | Public "check this URL" + evidence pages |
| **Admin Dashboard** | Tenant admin console |
| **Browser Extension** | Auto-update + verdict fetching |
| **CT Monitor** | Real-time CT log pre-scanning |
| **Email Gateway** (Phase 4+) | Time-of-click email URL rewriting |

## Status Definitions

| Status | Meaning |
|---|---|
| **Operational** | Working as designed |
| **Degraded performance** | Slower than SLO but functional |
| **Partial outage** | Some users / regions affected |
| **Major outage** | Component non-functional for most users |
| **Maintenance** | Scheduled downtime in progress |

## Updating During an Incident

Three updates minimum. Always.

### 1. Acknowledge (within 15 min of declaration)
> We're investigating reports of <symptom>. Some users may experience <impact>. Updates to follow.

Do not speculate on root cause. Do not commit to a fix ETA.

### 2. Mitigation in progress (every 30 min while degraded)
> We have identified the issue and are <doing the thing>. <symptom> is no longer growing / is now affecting <X%> of <Y>.

### 3. Resolved
> The issue has been resolved as of HH:MM UTC. <symptom> is back to normal. A full postmortem will be published within 5 business days.

After resolution, do **not** retroactively rewrite history. Append, don't overwrite.

## Scheduled Maintenance

For any planned downtime ≥5 minutes:

- Announce ≥48h ahead via status page + customer email.
- Use the Maintenance status, not Operational, during the window.
- Publish a post-maintenance "all clear" within 15 min of completion.

## Subscriptions

Encourage customers to subscribe via:
- Email
- SMS (Business+ tier)
- RSS / Atom
- Webhook (for SIEM / Slack integration)

## Automation

- Synthetic monitor (every 60s) for each component → auto-flip status to Degraded if 3 consecutive failures.
- PagerDuty webhook → status-page draft update (human still confirms before publishing).
- On resolve, auto-flip back to Operational only after 15 min sustained green.

## Cardinal Rules

1. **Truth over comfort.** If users are seeing errors, the page says so. We don't downplay.
2. **Update before users ask.** If a customer reports an issue and the page is still green, we failed.
3. **Internal-first comms.** Update `#incidents` Slack before the public page; never blindside customer-facing teams.
4. **Postmortem link from the resolved entry.** When the postmortem ships, edit the resolved status to include it.
