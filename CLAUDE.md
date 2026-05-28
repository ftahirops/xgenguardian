# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**XGenGuardian** — brain-first protective DNS aimed at catching zero-day phishing that blocklists miss, with per-URL transparency. The canonical reference is [`docs/architecture.md`](docs/architecture.md); planning and active work live under `docs/` (`tasks/TASKS.md`, `bugs/BUGS.md`, `issues/ISSUES.md`, `phases/`, `progress/`).

## Common commands

All targets are in the `Makefile` at the repo root. Run from `code/`.

- `docker compose up -d` — start Postgres (pgvector), Redis, MinIO, and (unused) CoreDNS. Postgres is published on `127.0.0.1:15432`, Redis on `16379`, MinIO on `19000/19001`.
- `make migrate` — apply Postgres DDL from `migrations/` using `migrate` against `postgres://xgg:xgg@localhost:15432/xgg` (the port docker-compose publishes Postgres on).
- `make seed-brands` — populate Brand Registry from `tools/brand-seeder/brands.yaml`.
- `make dev-backend` — run resolver, verdict-api, sandbox-render (uvicorn :8002), visual-match (uvicorn :8003) concurrently via `air`/`uvicorn --reload`.
- `make dev-portal` — Next.js portal on :3000 (Procfile.dev runs it on :13000).
- `make dev-up` / `make dev-down` — script-driven full stack (`scripts/dev-up.sh`) using overmind/foreman/tmux to run `Procfile.dev`. `Procfile.dev` is the source of truth for ports and env when running everything together.
- `make test` — `go test ./services/...` plus `pytest -q` in `services/sandbox-render` and `services/visual-match`. Run a single Go test with `go test ./services/<svc>/... -run TestName`; a single Python test with `pytest -q tests/path::test_name` inside the service dir.
- `make lint` — `golangci-lint run ./services/...` and `npm run lint` in `apps/portal`. Python uses `ruff format` / `ruff check` (config in `ruff.toml`).
- `make build` — builds all Go services and the Next.js portal.
- `make proto` — regenerate from `proto/` via `scripts/gen-proto.sh`.
- `make test-doh URL=https://example.com` — send a DoH query to the local resolver.
- `make eval` — run the labeled-example harness (`tools/eval/run.py`). **Required before/after any detection-logic change** (thresholds, fusion weights, classifiers); attach the precision/recall/F1 table to the PR.
- `make smoke`, `make doctor`, `make healthcheck`, `make bulk-scan FILE=...` — operational scripts in `scripts/` and `services/healthcheck`.

## Architecture

The system is a layered DNS + URL security platform. Read `docs/architecture.md` §3–4 for L0–L6 specifics; the highlights:

- **`services/resolver`** (Go) — binds `:53` UDP/TCP, terminates DoH/DoT, performs resolve-time enforcement. Calls verdict-api for unknown names; this is the hot path and the latency budget matters.
- **`services/verdict-api`** (Go) — central decision service. Fuses signals (brand-identity mismatch, infra correlation, render/visual results) into a verdict. Detection thresholds and fusion weights live here and are governed by the `make eval` gate.
- **`services/sandbox-render`** (Python/FastAPI, :8002) — headless render of unknown URLs, produces screenshots/DOM/network traces stored in MinIO.
- **`services/visual-match`** (Python/FastAPI, :8003) — CLIP-based visual similarity against Brand Registry. **First start downloads ~600 MB of model weights**; allow several minutes.
- **`services/registry-svc`** — Brand Registry (logo, domains, known infra per brand). Seeded by `tools/brand-seeder`.
- **`services/ct-monitor`** — Certificate Transparency feed → new-domain / mis-issuance signals.
- **`services/portal-api`** (Go, :18081) — backend for the Transparency Portal; needs `ADMIN_PASSWORD`.
- **`apps/portal`** (Next.js) — user-facing Transparency Portal showing per-URL evidence.
- **`apps/extension`**, **`apps/windows-client`**, **`apps/landing`** — client surfaces.
- **`proto/`** — shared protobuf contracts between services. Regenerate with `make proto` after edits.

Data dependencies: Postgres (pgvector for embeddings), Redis (caching/queues), MinIO (evidence blobs: screenshots, DOM, traces).

## Conventions worth knowing

- **Go 1.22**, modules per service (each service has its own `go.mod` under `services/<name>/`; module path `github.com/xgenguardian/services/<name>`). There is no root go.work; treat services as independent Go modules.
- **golangci-lint** config at `.golangci.yml` enforces revive's `exported`, `var-naming`, `error-return`, `error-naming` rules plus the usual suspects. Tests are excluded from `errcheck`/`unused`.
- **Python** services use `pyproject.toml` + ruff (config in `ruff.toml`).
- **Branches**: `xgg-<id>-<short-slug>`. Commits: imperative, ≤72 char subject, prefix with ticket ID (`XGG-18: …`). See `CONTRIBUTING.md`.
- **Tasks workflow**: pick from `docs/tasks/TASKS.md`, reference with `Closes XGG-NN` in the PR. Design decisions go in `docs/issues/ISSUES.md`, not PR comments.
- **Detection-logic PRs** are a higher merge bar: must include `make eval` output and not regress precision/recall/F1 below current values or break Phase-1 exit-gate criteria.
- **Test fixtures**: never include real phishing URLs unless they are already-classified PhishTank entries. Use `phish-test.example`-style placeholders.
