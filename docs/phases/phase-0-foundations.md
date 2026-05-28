# Phase 0 — Foundations

**Duration:** 2 weeks
**Effort:** 1 engineer-month
**Goal:** repos, infra skeleton, CI/CD, domain registration. "Hello world" deploy pipeline working end-to-end.

## Scope
- Monorepo decision (Turborepo / Nx) — see ISS-1.
- Go workspaces for backend, Python workspaces for ML, TS for frontend & extension.
- GitHub org + branch protection + CI (lint/test/build).
- Cloud account (single region) + Terraform skeleton.
- Postgres + Redis + S3-compatible storage provisioned.
- Observability: Grafana Cloud free tier + Sentry + status page.
- Domains: `xgenguardian.com`, `xgenguardian.io`, `dns.xgenguardian.io`, `report.xgenguardian.io`.

## Tickets
See `docs/tasks/TASKS.md` — Phase 0 section.

## Exit gate
- CI green on `main`.
- Staging deploy works (any service answers a request).
- Observability dashboard shows real logs.

## Risks
- Domain availability — confirm before naming is finalized.
- Cloud-account quota delays — request quota raises early.
