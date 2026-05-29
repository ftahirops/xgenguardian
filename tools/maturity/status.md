# Maturity Status Tracker

Single source of truth for "what's actually shipped vs aspirational" against
`docs/maturity-testing-blueprint.md`. Updated on every release; consulted by
`make maturity-test`. Numbers here are the floor — passing the gate means
the system is at least this mature; gaps below this baseline are P0 blockers.

Last updated: v0.3.2 (2026-05-29)

## Release-gate matrix

| Gate | Status | First met at | Notes |
|---|---|---|---|
| Extension holding-page: zero indefinite spinners | ✅ SHIPPED | v0.3.2 | 12s hard deadline + retry + fail-open contract |
| Backend dependency chaos: no crashes, no unbounded waits | ✅ SHIPPED | v0.3.2 | All rdb/Postgres/sandbox calls have explicit ctx timeouts |
| Evidence UI: no broken images, no unreadable pages | ✅ SHIPPED | v0.3.1 | `img.onerror` hides broken refs gracefully |
| Benign corpus FP rate below release threshold (Safe mode ≤0.5%) | ⚠️ PARTIAL | v0.3.1 (soak 19/22) | Curated corpus N≥500 still TODO |
| Malicious corpus recall above release threshold (≥80%) | ⚠️ PARTIAL | v0.3.0 | Per-category corpus + bench TODO |
| Race test: zero Go data races | ✅ SHIPPED | v0.2.5 | `go test -race` clean across all services |
| Raw-IP scenarios | ✅ SHIPPED | v0.3.1 | Public BLOCK, operator/private bypass via TrustedIdentity + private CIDR skip |
| Wrapper URLs (SafeLinks/Proofpoint/Mimecast/Cisco/Symantec) | ✅ SHIPPED (bypass) | v0.3.2 | Decode-and-forward TODO P1 |
| Reason codes: every verdict has stable codes | ✅ SHIPPED | v0.2.0 | reasons.go is the canonical taxonomy |
| Handler invariant (always-respond) | ✅ SHIPPED | v0.3.2 | ESLint rule TODO P0 |

## Priority backlog (mirrors blueprint §15)

| Priority | Work | Owner | Status | Target |
|---|---|---|---|---|
| P0 | ESLint `xgg/always-respond` rule | TBD | TODO | Phase 8 |
| P0 | Extension no-hang E2E suite in CI | TBD | TODO | Phase 8 |
| P0 | MinIO bucket-policy nightly check | TBD | TODO | Phase 8 |
| P1 | Wrapper URL decoder (SafeLinks unwrap-and-scan) | TBD | TODO | Phase 9 |
| P1 | MV3 SW-lifecycle automated suite | TBD | TODO | Phase 9 |
| P1 | Adversarial input matrix (NFC, emoji, mixed-script) | TBD | TODO | Phase 9 |
| P1 | Backward-compat migration tests | TBD | TODO | Phase 9 |
| P1 | Telemetry pipeline (runtime.lastError counting) | TBD | TODO | Phase 9 |
| P1 | Sandbox YARA rule signature verification | TBD | TODO | Phase 9 |
| P1 | Action-scoped trust enforcement (brandgraph.scope) | TBD | TODO | Phase 9 |
| P2 | Benign corpus N≥500 with per-category breakdown | TBD | TODO | Phase 10 |
| P2 | Malicious corpus N≥300 with per-category recall | TBD | TODO | Phase 10 |
| P2 | Scam-page detectors (phone, RAT, gift card) | TBD | TODO | Phase 10 |
| P2 | Accessibility audit (axe-core gate) | TBD | TODO | Phase 10 |
| P2 | Sandbox concurrency stampede test | TBD | TODO | Phase 10 |
| P3 | OCR/QR detection (quishing) | TBD | TODO | Phase 11 |
| P3 | Correlation graph campaign tests | TBD | TODO | Phase 11 |
| P3 | Aggressive-mode implementation | TBD | TODO | Phase 11 |
| P3 | Supply-chain CODEOWNERS + signed releases | TBD | TODO | Phase 11 |

## Currently-shipped capabilities snapshot

Counts as of v0.3.2:

- Services running: 5 (verdict-api, portal-api, resolver, sandbox-render, visual-match)
- Migrations applied: 11
- Brand registry entries: 60+ (Phase 4-7 expansions)
- Feed entries: 870K+
- Reason codes registered: 60+
- Policy stages: 8 (Stage 0 → Stage U → Stage F.0 → F.1 → F.2 → F.3 → F.4 → G)
- User modes: 6 (normal / safe / family / strict / paranoid / **ultra**)
- /metrics endpoints: 3 (verdict-api 53, sandbox 16, visual-match 37)
- systemd timers: 2 (backup daily, cleanup weekly)
- Extension interstitials: 5 (blocked, warn, isolate, holding, dnsfail)
- Soak test pass rate: 19/22 (v0.2.9 baseline; v0.3.2 fixes all 3 prior failures)

## Real-User Soak Tracker

Updated after each RUAT session (see `docs/real-user-acceptance-test-plan.md`).
A row stays here until the underlying issue is fixed AND a regression test added.

| Session date | Tester | Mode | Pages | Hangs | OAuth fails | Broken UI | False blocks | False warns | P0 findings | Session file |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| _no sessions yet — run `make ruat-new-session`_ |

Release-ready targets for Safe mode (per blueprint §19):

```
hangs:               0
OAuth failures:      0
broken evidence:     0
false blocks:        0
false warnings:      <1 per 100 pages
```

## How to update this file

1. When a row moves to SHIPPED, set status + version
2. When a new row is added to the blueprint, add a corresponding line here as TODO
3. Quarterly sweep: verify SHIPPED rows haven't regressed (e.g. run `make maturity-test`)
4. Tie blueprint §15 row IDs to this file's "Priority backlog" rows so they can't drift
5. After every RUAT session, append a row to the Real-User Soak Tracker above
