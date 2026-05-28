# XGenGuardian — Open Issues & Decisions

Architectural decisions, vendor selection, open design questions. Not bugs — these are *unresolved choices*.

**Status:** `OPEN` · `DECIDED` · `DEFERRED`

## Open

| ID | Title | Area | Owner | Opened | Status |
|----|-------|------|-------|--------|--------|
| ISS-1 | Pick monorepo tool: Turborepo vs Nx vs none | Tooling | Lead | 2026-05-14 | OPEN |
| ISS-2 | Pick CT-log subscription: Certstream public WSS vs self-run CT-log mirror | Backend | Backend | 2026-05-14 | OPEN |
| ISS-3 | Decide hosted vs self-hosted LLM for reasoner (cost/latency tradeoff) | ML | ML | 2026-05-14 | OPEN |
| ISS-4 | Decide anycast strategy: self-BGP via Equinix vs Vultr/Fly.io anycast vs none for Phase 1 | Infra | Infra | 2026-05-14 | OPEN |
| ISS-5 | Choose object storage: AWS S3 vs Cloudflare R2 vs MinIO (cost/exit-cost) | Infra | Infra | 2026-05-14 | OPEN |
| ISS-6 | Brand registry data licensing: are commercial brand logos OK to store for visual match? | Legal | Lead | 2026-05-14 | OPEN |
| ISS-7 | Active disruption (#74): legal review needed before automated takedowns | Legal | Lead | 2026-05-14 | OPEN |

## Decided

| ID | Title | Decision | Date |
|----|-------|----------|------|
| — | (none yet) | — | — |

## Template

```
### ISS-NNN — <title>
- Area: Backend | ML | Infra | Frontend | Legal | Tooling | Product
- Opened: YYYY-MM-DD
- Status: OPEN
- Context:
- Options:
  A) …
  B) …
  C) …
- Constraints:
- Recommendation:
- Decision (when made):
- Decision date:
```
