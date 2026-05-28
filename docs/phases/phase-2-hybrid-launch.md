# Phase 2 — v1 Hybrid Launch

**Duration:** 3 calendar months
**Effort:** ~10 engineer-months
**Mission:** turn POC into a real product with browser extension, user accounts, mobile profile. First revenue.

## Features added (from architecture.md §27)
#17, #18, #19, #20, #21, #25, #28, #30, #32, #33, #38, #39 + tracker subset (#70).

## Client deliverables
- Chrome MV3 extension: URL hash reporting, block interstitial, tracker blocklist.
- Firefox port.
- iOS .mobileconfig DoH profile generator.
- Android Private DNS hostname onboarding flow.
- User account + personal dashboard with visit history & evidence pages.

## Brand Registry expansion
50 → 500 brands via CT-log mining + Tranco top-500 auto-seed.

## Sub-milestones
| Week | Deliverable |
|---|---|
| 1–2 | Multi-egress fetch infrastructure + cloaking diff |
| 3–4 | Behavioral sandbox + canary creds wired into verdict |
| 5 | Redirect chain forensics + JS AST analysis |
| 6 | LLM page-understanding + reasoner (hosted LLM) |
| 7–8 | Chrome + Firefox extension MV3 |
| 9 | User accounts + personal dashboard |
| 10 | Mobile DoH/DoT profiles + onboarding |
| 11 | Brand Registry to 500 brands |
| 12 | v1 launch — free + Plus tiers |

## Exit gate
- 10k active DoH endpoints.
- 1k paid Plus subscribers.
- ≥80% catch rate on PhishTank <24h.
- Chrome Web Store ≥500 stars within 60d.
- LLM reasoner used by ≥50% of block-page visitors.

## Infra cost
~$1,500/mo (more sandbox capacity + LLM API spend).
