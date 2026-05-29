# XGenGuardian — Documentation Index

All project documentation, plans, tracking, and runbooks live here. This directory is the single source of truth for what's being built, what's being worked on, and what's broken.

## Structure

```
docs/
├── README.md               ← you are here
├── advanced-detection-cases.md ← hard phishing, scam, OAuth, raw-IP, and edge-case examples
├── blueprint-architecture.md ← GitHub-facing system blueprint and differentiation
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

## Rules

1. **Every commit that changes scope** updates the relevant file in `phases/` or `tasks/`.
2. **No task is "done" until** its row in `tasks/TASKS.md` is marked `DONE` with a date.
3. **Bugs go in `bugs/BUGS.md` immediately** when discovered, even before triage.
4. **Weekly progress** is appended to `progress/PROGRESS.md` every Friday.
5. **Open decisions** that aren't tasks (architecture choices, vendor selection, etc.) live in `issues/ISSUES.md`.
6. **Architecture rationale** stays in `architecture.md`; this file is canonical.

## Quick Links

- [Advanced Detection Cases](advanced-detection-cases.md)
- [Blueprint Architecture](blueprint-architecture.md)
- [Maturity Testing Blueprint](maturity-testing-blueprint.md)
- [Real-User Acceptance Test Plan](real-user-acceptance-test-plan.md)
- [Architecture (full document)](architecture.md)
- [Master Task List](tasks/TASKS.md)
- [Active Bugs](bugs/BUGS.md)
- [Open Issues / Decisions](issues/ISSUES.md)
- [Progress Log](progress/PROGRESS.md)
- [Phase 1 — POC](phases/phase-1-poc.md)
