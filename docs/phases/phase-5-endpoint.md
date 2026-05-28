# Phase 5 — Endpoint Client + Enterprise Mode

**Duration:** 6 calendar months
**Effort:** ~25 engineer-months
**Mission:** non-browser coverage + enterprise SWG-grade visibility. First AV-equivalent product.

## Endpoint deliverables
- Windows endpoint v1 (no MITM): DoH manager + tray + DNS log viewer.
- Windows endpoint v2: local HTTPS-intercepting proxy + per-install CA + top-50 pinned-app bypass.
- Linux endpoint (eBPF + nftables + fanotify + local proxy).
- macOS desktop v1 (no MITM; full MITM in Phase 6).

## Backend features added
#41, #42, #43, #44, #45, #46, #47, #48, #49, #50, #51, #56, #57, #58, #59, #60, #61, #63, #64, #65, #68, #69, #87.

## Sub-milestones
| Month | Deliverable |
|---|---|
| 1 | Win endpoint (no MITM) GA |
| 2 | Linux endpoint (no MITM) GA |
| 3 | Win endpoint MVP with local MITM + CA + pinned-app bypass |
| 4 | Endpoint behavior monitor + post-click forensics |
| 5 | Backend P2 detection block (41–51) |
| 6 | Enterprise SWG mode + ICAP + email gateway + launch |

## Exit gate
- 10 enterprise contracts ≥$25k ARR each.
- Win + Linux endpoint installed base ≥10k devices.
- $400k MRR.
- SOC 2 Type 1 certified.

## Risks
- WHQL kernel driver signing lead time.
- Pinned-app bypass maintenance — permanent ~1 FTE.
- AV conflicts (Defender ATP partnership needed).

## Infra cost
~$35,000/mo.
