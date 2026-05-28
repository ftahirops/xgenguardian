# Phase 1 — POC (Public Demo)

**Duration:** 3 calendar months (team of 3)
**Effort:** ~9 engineer-months
**Mission:** prove the brain works publicly. The artifact that gets posted to HN.

## Features in scope (from architecture.md §27)
#1, #2, #3, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14, #15, #16, #22, #37

## Out of scope this phase
Behavioral sandbox (#20), canary creds (#21), LLM reasoner (#33), multi-egress (#18), file scanning (#23, #24), mobile, native client, federation, admin console.

## Sub-milestones
| Week | Deliverable |
|---|---|
| 1 | Resolver up, blocklists ingested, DoH endpoint live |
| 2 | URL Verdict API + Redis cache + Postgres registry |
| 3 | Lexical layer + WHOIS/RDAP/cert/NRD + Tranco allowlist + rule-based verdict |
| 4 | Playwright render service + screenshot/DOM/favicon capture |
| 5 | Brand Registry seeding for 50 brands + CLIP embeddings + pgvector |
| 6 | Visual + favicon fusion + threshold tuning on labeled PhishTank |
| 7 | Transparency Portal + per-verdict evidence pages + CT-log pre-scanner |
| 8 | Hardening, rate-limiting, public health page, launch prep |
| 9–12 | Public launch (HN/PH/X), iterate FPs/FNs |

## Tickets
See `docs/tasks/TASKS.md` epics E1–E6 (XGG-3 through XGG-24).

## Exit gate
- Catches ≥50% of last 100 PhishTank URLs while still <24h old.
- Catches ≥10 phish that GSB+SmartScreen+VT all label clean at scan time.
- Median verdict <5s on unknown, <100ms on cached.
- ≥1,000 daily verdict-page views within 30 days of launch.
- One side-by-side demo video that closes any deal.

## Risks
- CLIP threshold tuning / false-positive rate — mitigate by holding back Tranco top-10k for FP eval.
- Brand Registry quality — manual review pass required.
- Playwright stability under load — pool size + autoscale + graceful timeout.
- Certstream WSS stability — fallback to crt.sh polling.

## Infra cost
~$300/mo (single VPS + Postgres + small GPU box or CPU-only CLIP).
