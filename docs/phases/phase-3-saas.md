# Phase 3 — SaaS Multi-Tenant + Admin Console

**Duration:** 2 calendar months
**Effort:** ~8 engineer-months
**Mission:** unlock SMB and family-plan revenue. Compete head-on with NextDNS Pro.

## Features added
#62, #66, #67, #71, #72, #73, #83, #90, #93.

## Platform deliverables
- Multi-tenant data model (orgs, groups, members, devices).
- Admin Console (members, devices, policies, logs, reports, billing).
- Per-tenant DoH endpoint provisioning.
- SCIM + SAML/OIDC SSO.
- Policy profiles (default, strict, kids, work, gaming).
- Per-device QR-code enrollment for mobile.
- Weekly/monthly PDF reports.
- Slack/email/webhook notifications.
- Stripe billing.

## Sub-milestones
| Week | Deliverable |
|---|---|
| 1 | Multi-tenancy schema + RBAC + auth flows |
| 2 | Admin Console: members + devices |
| 3 | Policy engine (OPA) + per-tenant policy storage |
| 4 | Logs viewer + reports |
| 5 | SSO + SCIM |
| 6 | Stripe billing + tier gating |
| 7 | Per-user risk score + FP/FN analyst workflow |
| 8 | Launch SMB + Family tiers |

## Exit gate
- 50 paying orgs.
- 500 paying families.
- $25k MRR.
- NPS ≥40 on Admin Console.

## Infra cost
~$4,000/mo.
