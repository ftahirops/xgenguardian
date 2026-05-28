# Deploy

**TL;DR:** CI green → staging deploy → smoke → canary 10% → wait 30 min → full → smoke again.

## Pre-flight

- [ ] PR merged to `main`.
- [ ] CI green on the merge commit.
- [ ] No active incident.
- [ ] No active deploy freeze (check `#xgg-oncall` topic).

## 1. Staging

```bash
git pull origin main
./scripts/deploy.sh staging        # builds + pushes + applies k8s manifests
./scripts/smoke.sh                 # against staging.xgenguardian.io
```

If `smoke.sh` fails: **stop**. Diagnose. Roll back staging:

```bash
./scripts/deploy.sh staging --rollback
```

## 2. Production canary (10%)

```bash
./scripts/deploy.sh prod --canary 10
```

Monitor for 30 minutes:
- `verdict_api_latency_p99` (target <500ms cached, <6s unknown)
- `false_positive_rate_1h` (target <0.5%)
- `error_rate_5m` (target <0.1%)
- Sentry: no new error types

If any metric regresses: **roll back the canary immediately**:

```bash
./scripts/deploy.sh prod --rollback
```

## 3. Production full

```bash
./scripts/deploy.sh prod --full
./scripts/smoke.sh --target prod
```

## 4. Post-deploy

- Post in `#deploys`: `DEPLOY <git sha> → prod` with link to grafana dashboard.
- Update `docs/progress/PROGRESS.md` weekly entry with what shipped.
- Watch dashboards for at least 2 hours; another 24 hours of casual observation.

## Rollback

Any deploy command supports `--rollback` to revert to the previous image SHA:

```bash
./scripts/deploy.sh prod --rollback     # full rollback
./scripts/deploy.sh prod --rollback --to <sha>   # rollback to specific SHA
```

Database migrations are **forward-only**. Rolling back code with a migration applied requires running a compensating migration first — see `migrations/README.md`.

## Database Migrations

Migrations live in `migrations/NNNN_*.sql`. Apply with:

```bash
migrate -path migrations -database "$DATABASE_URL" up
```

Rules:
- Migrations are **additive** when possible (add columns, don't drop).
- Drops happen in a follow-up migration, ≥1 release after the code that uses the column is removed.
- Never run a destructive migration during a deploy that also ships new code — separate them.

## Deploy Freezes

A deploy freeze is in effect when the topic of `#xgg-oncall` starts with `🚫 FREEZE`. Reasons:
- Active S1 incident
- Major customer trial in flight
- Marketing launch within 24h

During a freeze, only S1 fixes ship. Everything else queues up.
