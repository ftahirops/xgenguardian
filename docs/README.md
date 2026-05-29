# XGenGuardian — Documentation Index

All project documentation, plans, tracking, and runbooks live here. This directory is the single source of truth for what's being built, what's being worked on, and what's broken.

## Structure

```
docs/
├── README.md               ← you are here
├── advanced-detection-cases.md ← hard phishing, scam, OAuth, raw-IP, and edge-case examples
├── blueprint-architecture.md ← GitHub-facing system blueprint and differentiation
├── deeptrust-zero-trust-url-analysis.md ← deep per-URL zero-trust investigation engine design
├── final-engine-architecture-plan.md ← final mature DNS/action/trust/risk engine target
├── maturity-testing-blueprint.md ← exhaustive testing, chaos, FP/FN, and release gates
├── architecture.md         ← full architecture, threat model, features, plan
├── phases/                 ← phase plans (1 file per phase)
│   ├── phase-0-foundations.md
│   ├── phase-1-poc.md
│   ├── phase-2-hybrid-launch.md
│   ├── phase-3-saas.md
│   ├── phase-4-production-p1.md
│   ├── phase-5-endpoint.md
│   └── phase-6-privacy-ai.md
├── tasks/                  ← active task tracking
│   └── TASKS.md            ← master task list with status
├── bugs/                   ← bug reports
│   └── BUGS.md
├── issues/                 ← open issues / decisions / questions
│   └── ISSUES.md
├── progress/               ← weekly progress logs
│   └── PROGRESS.md
├── runbooks/               ← ops procedures (incident response, deploys)
└── api/                    ← API references
```

## Canonical Document Scopes

The architecture docs have different scopes. Do not treat every old planning
file as equally authoritative.

| File | Canonical For | Status |
|---|---|---|
| [architecture.md](architecture.md) | historical full-system threat model and original L0-L6 reference | legacy reference; not the current execution plan |
| [final-engine-architecture-plan.md](final-engine-architecture-plan.md) | current mature verdict-engine roadmap and rollout discipline | current canonical engine roadmap |
| [deeptrust-zero-trust-url-analysis.md](deeptrust-zero-trust-url-analysis.md) | per-URL deep investigation / zero-trust analysis design | current canonical deep-analysis spec |
| [maturity-testing-blueprint.md](maturity-testing-blueprint.md) | release gates, test matrices, chaos, privacy, accessibility | current canonical quality gate |
| [real-user-acceptance-test-plan.md](real-user-acceptance-test-plan.md) | human browser testing / RUAT | current canonical RUAT protocol |
| [UNIFIED-PLAN.md](UNIFIED-PLAN.md) | older stabilization plan and historical decisions | legacy/superseded where it conflicts with current docs |

When documents conflict, use this order:

```text
code + tests
CLAUDE.md engineering policy
final-engine-architecture-plan.md
deeptrust-zero-trust-url-analysis.md
maturity-testing-blueprint.md
architecture.md / UNIFIED-PLAN.md as historical context
```

## Rules

1. **Every commit that changes scope** updates the relevant file in `phases/` or `tasks/`.
2. **No task is "done" until** its row in `tasks/TASKS.md` is marked `DONE` with a date.
3. **Bugs go in `bugs/BUGS.md` immediately** when discovered, even before triage.
4. **Weekly progress** is appended to `progress/PROGRESS.md` every Friday.
5. **Open decisions** that aren't tasks (architecture choices, vendor selection, etc.) live in `issues/ISSUES.md`.
6. **Architecture rationale** must state its scope. Do not introduce a new architecture doc without adding it to the Canonical Document Scopes table above.

## Quick Links

- [Advanced Detection Cases](advanced-detection-cases.md)
- [DeepTrust Zero-Trust URL Analysis](deeptrust-zero-trust-url-analysis.md)
- [Blueprint Architecture](blueprint-architecture.md)
- [Final Engine Architecture Plan](final-engine-architecture-plan.md)
- [Maturity Testing Blueprint](maturity-testing-blueprint.md)
- [Real-User Acceptance Test Plan](real-user-acceptance-test-plan.md)
- [Architecture (full document)](architecture.md)
- [Master Task List](tasks/TASKS.md)
- [Active Bugs](bugs/BUGS.md)
- [Open Issues / Decisions](issues/ISSUES.md)
- [Progress Log](progress/PROGRESS.md)
- [Phase 1 — POC](phases/phase-1-poc.md)
