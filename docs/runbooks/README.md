# Runbooks

Operational procedures. Each runbook is a step-by-step recipe for one
specific situation. If you have to think about *what* to do, this
directory has failed.

| Runbook | When to use |
|---|---|
| [`incident-response.md`](incident-response.md) | Production is degraded or down |
| [`on-call.md`](on-call.md) | You're carrying the pager |
| [`deploy.md`](deploy.md) | Shipping new code to staging/prod |
| [`phishing-report-triage.md`](phishing-report-triage.md) | A user reported a missed phishing URL |
| [`false-positive-triage.md`](false-positive-triage.md) | A clean site got blocked |
| [`brand-registry-update.md`](brand-registry-update.md) | Adding/updating a protected brand |
| [`rotate-secrets.md`](rotate-secrets.md) | Rotating API keys, DB creds, signing keys |
| [`status-page.md`](status-page.md) | Updating the public status page during incidents / maintenance |
| [`postmortem-template.md`](postmortem-template.md) | Template for incident postmortems |
| [`incidents/`](incidents/) | Archive of past incident postmortems |
| [`internal-testing.md`](internal-testing.md) | Running the stack locally and hammering it with real malicious URLs |

## Conventions

- Each runbook starts with a **TL;DR** (≤3 lines).
- Numbered steps for the actual procedure.
- A **Rollback** section if any step is reversible.
- A **Verification** section: how do you know it worked?
- Updated every time someone uses it and finds it wrong.
