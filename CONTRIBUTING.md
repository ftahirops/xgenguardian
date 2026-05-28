# Contributing to XGenGuardian

We aim to keep contribution friction low and the bar for what lands high.

## Quick Start

```bash
git clone https://github.com/xgenguardian/xgenguardian
cd xgenguardian
docker compose up -d
make migrate
make seed-brands
make dev-backend &
make dev-portal
```

## Where Things Live

- **All documentation** — `docs/`. Architecture, phases, tasks, bugs, issues, progress.
- **Active tasks** — `docs/tasks/TASKS.md`. Claim a ticket by opening a PR that references it (`Closes XGG-NN`).
- **Bugs** — `docs/bugs/BUGS.md`. Open one even if you don't have a fix yet.
- **Design questions** — `docs/issues/ISSUES.md`. Decisions go here, not in PR comments.
- **Weekly progress** — `docs/progress/PROGRESS.md`. Updated every Friday.

## Branching & Commits

- Branch from `main`. Name your branch `xgg-<id>-<short-slug>` (e.g. `xgg-18-fusion-rule`).
- Commit messages: imperative mood, ≤72 chars subject. First line should reference the ticket.
  - Good: `XGG-18: implement identity-mismatch fusion rule`
  - Bad: `Updated some stuff`
- Squash before merge unless commits tell a useful story.

## Code Standards

- **Go**: `gofmt`, `go vet`, and `golangci-lint run` must all pass. We target Go 1.22.
- **Python**: services use `pyproject.toml`. Format with `ruff format`. Lint with `ruff check`.
- **TypeScript**: `npm run lint` and `npm run build` must pass in `apps/portal`.
- **Tests**: every new package needs at least one test. Detection logic needs tests against labeled examples (see `tools/eval`).

## Pull Requests

A good PR:
- Closes a ticket from `docs/tasks/TASKS.md`. New work? Open the ticket first.
- Updates the ticket's status comment (`IN_PROGRESS` → `REVIEW`).
- Has a "Test plan" section listing exactly what you ran and what you observed.
- Updates docs if architecture or APIs changed.
- Includes a regression test if it fixes a bug.

A bad PR:
- Bundles unrelated changes.
- Skips tests "because it's just a small change."
- Modifies `docs/architecture.md` without updating the table of contents.
- Adds a feature not on the roadmap without a `docs/issues/ISSUES.md` proposal first.

## Detection-Logic Changes

If you change a verdict threshold, fusion weight, or any classifier:

1. Run `make eval` before and after. Attach the table to the PR.
2. Confirm precision/recall/F1 stayed above current values.
3. Confirm Phase-1 exit-gate criteria still pass.

Detection regressions are a higher bar to merge than ordinary code changes.

## Security

See [`SECURITY.md`](SECURITY.md) for responsible disclosure.

Do **not** include real phishing URLs in test fixtures unless they're already-classified PhishTank entries. Use `phish-test.example` style placeholders elsewhere.

## License

Contributions are made under [MIT](LICENSE).
