# XGenGuardian

**Brain-first protective DNS.** Catches zero-day phishing that blocklists miss, with full per-URL transparency.

See [`docs/architecture.md`](docs/architecture.md) for the full architecture, threat model, and implementation plan.

## Quick Start (Local Dev)

```bash
# 1. Bring up Postgres + Redis + MinIO + CoreDNS
docker compose up -d

# 2. Run database migrations
make migrate

# 3. Start backend services
make dev-backend     # runs resolver, verdict-api, sandbox-render, visual-match

# 4. Seed the Brand Registry (50 brands)
make seed-brands

# 5. Start the Transparency Portal
make dev-portal      # http://localhost:3000

# 6. Send a test DoH query
make test-doh URL=https://example.com
```

## Repo Layout

```
code/
├── docs/             ← all docs: architecture, phases, tasks, bugs, issues, progress
├── services/         ← Go + Python backend services
├── apps/             ← Next.js portal + browser extension
├── tools/            ← brand-seeder, blocklist-fetcher, eval harness
├── proto/            ← shared protobuf definitions
├── migrations/       ← Postgres DDL
├── infra/            ← Terraform + Kubernetes
└── docker-compose.yml
```

## Where to Start

**Operator — simplest path (recommended):**
→ [`docs/SIMPLE-SETUP.md`](docs/SIMPLE-SETUP.md) — two public ports (`53` for DNS, `13000` for the dashboard). No certs, no CA install, no browser extension. Set your DNS to the server and open the dashboard.

**Operator — full setup (browser extension + Windows tray + DoH):**
→ [`docs/USAGE.md`](docs/USAGE.md) — all three deployment paths.

**Developer / reviewer:**
1. [`docs/architecture.md`](docs/architecture.md) — the full plan.
2. [`docs/tasks/TASKS.md`](docs/tasks/TASKS.md) — what's open.
3. [`docs/phases/phase-1-poc.md`](docs/phases/phase-1-poc.md) — the current phase.
4. Pick a ticket, branch, code, test, PR.

## Tracking

- **Tasks** → [`docs/tasks/TASKS.md`](docs/tasks/TASKS.md)
- **Bugs** → [`docs/bugs/BUGS.md`](docs/bugs/BUGS.md)
- **Issues / decisions** → [`docs/issues/ISSUES.md`](docs/issues/ISSUES.md)
- **Weekly progress** → [`docs/progress/PROGRESS.md`](docs/progress/PROGRESS.md)

## License
TBD — see `LICENSE`.
