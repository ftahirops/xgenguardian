# Phase 4 — Production-Grade Detection (Full P1)

**Duration:** 3 calendar months
**Effort:** ~12 engineer-months
**Mission:** close remaining P1 detection gaps; defensibly claim ~99% accuracy. Series A-ready.

## Features added
#23, #24, #26, #27, #29, #31, #34, #35, #36, #40, #53, #75, #86, #91, #92.

## Sub-milestones
| Month | Deliverable |
|---|---|
| 1 | File scanning + CAPE detonation + code-signing verification |
| 2 | DGA + tunneling + rebinding + bitsquat + subdomain takeover + DOM similarity |
| 3 | Email URL rewriting + honeypot ingest + federation + SIEM + 3 anycast PoPs |

## Exit gate
- ≥99% block rate on internal phishing test corpus.
- File detonation pipeline at 100k samples/day.
- Anycast PoPs in NA + EU + APAC.
- 5,000 paying users.
- $100k MRR.

## Infra cost
~$15,000/mo (CAPE farm + anycast + premium TI feeds).
