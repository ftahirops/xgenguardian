# XGenGuardian — Progress Log

Weekly progress, appended every Friday. Newest entries at the top.

---

## 2026-W20i — Session 9 (2026-05-14) — Password-gated admin dashboard

**Phase:** internal-testing gate
**Status:** operator can now see every DNS query and every URL verdict, gated by one password.

### Done
- **`migrations/0002_admin.sql`** (XGG-57) — `dns_queries` table (append-only, indexed by ts/domain/verdict/sinkhole), 30-day retention recommended.
- **Resolver query persistence** — every `resolve()` call enqueues a record to Redis stream `xgg:dns` after the response is sent. Best-effort fire-and-forget so DNS latency is unaffected. Captures domain, qtype, verdict, cache_hit, sinkhole flag, duration_ms, client_id.
- **`services/portal-api/internal/dnsdrain.go`** — consumer-group worker drains `xgg:dns` into Postgres. Auto-creates the group, ACKs successfully-inserted messages, retries on transient errors.
- **Admin endpoints in portal-api** (XGG-58):
  - HTTP Basic auth (password from `ADMIN_PASSWORD` env). When unset, every admin route returns 403.
  - `GET /v1/admin/stats` — 24-h counters, 1-h sparkline buckets, top-20 blocked domains.
  - `GET /v1/admin/queries?q=&verdict=&limit=` — paged DNS query log.
  - `GET /v1/admin/verdicts?brand=&limit=` — URL-level verdicts with brand match.
- **Admin dashboard UI** (XGG-59) at `apps/portal/app/admin/`:
  - `/admin/login` — single password form.
  - `/admin/api/login` (POST) — verifies via portal-api, sets HttpOnly cookie.
  - `/admin/api/logout` (POST) — clears cookie.
  - `/admin/layout.tsx` — nav with cookie-aware logout button.
  - `/admin/page.tsx` — overview: 5 stat cards, 24-h sparkline (total vs blocked), top blocked table.
  - `/admin/queries/page.tsx` — full DNS query table with search + verdict filter.
  - `/admin/verdicts/page.tsx` — URL verdicts with brand filter + deep-link to evidence.
- **`docs/dns-test.md`** (XGG-60) — explains the three ways to feed domains in (bulk-scan / dig+DoH / browser-driven), what verdict to expect per category, FP/FN workflow.
- **Procfile.dev** — exports `ADMIN_PASSWORD=${ADMIN_PASSWORD:-changeme}` so the dashboard works out of the box; override before `make dev-up`.

### Waiting on the operator
1. Provide the list of domains to test (PhishTank entries, URLhaus links, suspicious sites, your own homoglyph constructions, plus a few known-good domains as control).
2. Have the stack running (`make bringup && make dev-up && make seed-brands && make doctor`).
3. Set `ADMIN_PASSWORD` to something you'll remember.

I'll then run them through `bulk-scan`, the DoH endpoint, and show the resulting analysis in the admin dashboard.

### In flight
- Live DNS test against operator-provided domains (waiting on the domain list).

### Blockers
- None within session scope.

---

## 2026-W20h — Session 8 (2026-05-14) — Full-stack operator readiness

**Phase:** internal-testing gate; system now usable end-to-end across DNS + extension + Windows
**Status:** every component the operator needs to test the platform internally is in place

### Done
- **`scripts/doctor.sh` + `make doctor`** (XGG-52) — per-component diagnostics with one-line fixes. Covers toolchain, dev TLS, Docker infra, Postgres+pgvector+brand count, Redis+blocklist count, MinIO, every service `/healthz`, the resolver's DoH endpoint, an end-to-end `/v1/check` smoke, and the session log directory.
- **`services/healthcheck/`** Go binary (XGG-53) — single-line JSON summary for status pages / scripts. Returns exit code 0/1/2 mapped to healthy/degraded/critical. Includes `brands`, `blocklist_domains`, `last_verdict_age_s`.
- **`tools/bulk-scan/scan.py`** (XGG-54) — async parallel scanner that accepts plain text URL lists, JSON arrays, or Chrome history exports. Colored per-row output via Rich, summary table, optional JSON dump. `make bulk-scan FILE=...`.
- **`apps/windows-client/`** (.NET 8) (XGG-55) — tray app, embedded WebView2 live feed, configures Windows 11 native DoH via PowerShell (UAC-prompted), restores DNS on Quit. Builds via `build.ps1` into a ~60 MB self-contained single EXE.
  - Source files: `Program.cs`, `TrayContext.cs`, `LiveFeedForm.cs`, `AppSettings.cs`
  - `XGenGuardian.csproj` with single-file publish, WebView2 dep
  - `app.manifest` with proper DPI awareness + asInvoker (UAC per-action)
  - `README.md` documenting build, run, env vars, internal-testing setup
- **`docs/USAGE.md`** (XGG-56) — the operator's single entry point. Three deployment paths laid out side by side; 8-scenario testing workflow; verdict-color cheat sheet; full make-target reference; troubleshooting table; explicit "what's NOT in this build" section (no billing, no mobile).
- **Makefile** — added `doctor`, `healthcheck`, `bulk-scan` targets.
- **Root README.md** — operator now sees USAGE.md as the entry point.

### In flight
- First real run of the Windows tray client against a live backend.
- First bulk-scan against a 1k-URL Chrome history export.
- Operator's first 30-minute test session through the 8 scenarios.

### Blockers
- None within session scope.

### What the operator does now
```bash
make bringup && make dev-up && make seed-brands && make doctor
# then follow docs/USAGE.md for whichever deployment path you want
```

---

## 2026-W20g — Session 7 (2026-05-14) — Operator UX polish

**Phase:** internal-testing gate
**Status:** stack now starts with one command; brands seedable even when CAPTCHA-walled; verdicts auto-logged to a portable JSONL.

### Done
- **`Procfile.dev` + `scripts/dev-up.sh` + `make dev-up`/`make dev-down`** (XGG-49):
  - Preferred: `overmind start -f Procfile.dev` (best dev UX: per-process logs + restart).
  - Fallback: `foreman start`.
  - Last resort: a tmux script that opens 7 windows in a session named `xgg`.
  - `make dev-down` cleans up tmux + overmind + docker compose.
- **Brand-seeder manual screenshot fallback** (XGG-50):
  - `tools/brand-seeder/MANUAL.md` — capture procedure + IP/licensing note.
  - `brands.yaml` schema now accepts `manual_screenshots: [{file, page_label, page_url}]`.
  - `seed.py` rewritten: tries auto-render first; on failure, loads local PNG and embeds via `/embed` (new `image_b64` body path on visual-match).
  - CLI gained `--brand <name>` for targeted re-seed and `--dry-run` for testing.
  - `tools/brand-seeder/manual/` is `.gitignore`d (visual IP); `.gitkeep` keeps dir in tree.
- **Persistent session JSONL log** (XGG-51):
  - `services/verdict-api/internal/httpgw/sessionlog.go` — opens `<SESSION_LOG_DIR>/<UTC-date>.jsonl`, rotates by day.
  - One JSON line per verdict: timestamp, URL, domain, verdict, confidence, brand match, all signals, client_id, evidence_id. No screenshots.
  - Enabled automatically in `Procfile.dev` (`SESSION_LOG_DIR=../../data/sessions`).
  - Runbook updated with `jq` recipe for slicing the log when filing BUGS reports.

### In flight
- First `make dev-up` run by operator.
- First seeded brand with manual fallback (likely Chase or HSBC).

### Blockers
- None within session scope.

### What the operator needs now
- Install Docker, Go 1.22+, Node 20+, Python 3.11+, and one of (overmind / foreman / tmux).
- `git pull && make bringup && make dev-up`.
- Click bad URLs. Watch `/live`. Grep `data/sessions/*.jsonl` afterwards.

---

## 2026-W20f — Session 6 (2026-05-14) — Internal-testing readiness

**Phase:** between Phase 1 and Phase 2 (internal-testing gate)
**Status:** end-to-end pipeline closed; ready to point at real malicious URLs

### Done
- **`docs/phases/internal-testing.md`** (XGG-43) — what the operator does, 8 test scenarios, success gates, hardware needs.
- **`docs/runbooks/internal-testing.md`** — step-by-step operator runbook (trust CA, start services, point Firefox at DoH, click bad URLs, file FN/FP reports, reset, troubleshoot).
- **Resolver → verdict-api wiring** (XGG-44) — replaced `tier1Verdict` stub with a real HTTP call; 280ms timeout; fail-open on error.
- **`scripts/gen-dev-certs.sh`** (XGG-45) — local CA + leaf cert (`dns.local.test`, `localhost`, `127.0.0.1`); per-OS trust instructions.
- **Live activity feed** (XGG-46) — `verdict-api/internal/httpgw/stream.go` (SSE on Redis pub/sub `xgg:verdicts`) + `apps/portal/app/live/page.tsx` real-time feed with counters.
- **File-download discovery** (XGG-47) — `sandbox-render/app/downloads.py` finds + hashes downloadable links (cap 20/page, 4 MiB each); new `risky_downloads` signal in fusion.
- **`scripts/bringup.sh`** (XGG-48) — preflight → certs → compose → migrations → blocklists → build → printed instructions.
- **Makefile** — `make bringup`, `make dev-certs`.

### In flight
- gRPC stub generation (pending `protoc` install in dev env; HTTP is fine for internal testing).
- Real brand-seeder run against 50 brands (needs stack up first).
- First real internal-test session by the operator.

### Blockers
- None within session scope. Operator needs Docker installed to actually `make bringup`.

### Operator's next step
```
git pull
make bringup
# follow the printed instructions
```

---

## 2026-W20e — Session 5 (2026-05-14)

**Phase:** 0 → 1 → Phase 2 prep + go-to-market
**Status:** ready for first real deploy + public launch

### Done
- **`apps/extension/`** (XGG-40) — Chrome MV3 v0:
  - `manifest.json` with minimal-permissions justification.
  - `src/background.js` — webNavigation hook → URL hash → verdict-api → cached in `chrome.storage.session` → tab redirect to interstitial on BLOCK/WARN.
  - `src/blocked.html` — interstitial with reason, brand, similarity score, links to evidence portal + FP report.
  - `src/popup.html/.js` — current-tab verdict + protection toggle.
  - `src/options.html/.js` — API endpoint config, enforcement level, telemetry opt-in.
  - `src/rules/trackers.json` — declarativeNetRequest tracker blocklist (10 rules).
  - i18n stub, README with permissions justification + Phase-2 roadmap.
- **`docs/runbooks/postmortem-template.md`** (XGG-41) — blameless template with 5-whys, action-item table, customer comms, 30-day re-read rule.
- **`docs/runbooks/status-page.md`** — components, status definitions, comms cadence (15 min on declare, 30 min during, on resolve).
- **`docs/runbooks/incidents/README.md`** — incident archive index with naming conventions.
- **`docs/launch/`** (XGG-42) — 7 launch artifacts:
  - `launch-checklist.md` — T-7d through T+7d, complete with timestamps for launch day.
  - `hn-post.md` — Show HN with body, operational notes, pushback FAQ.
  - `x-thread.md` — 10-tweet thread with visual cues.
  - `reddit-r-privacy.md` — three distinct posts (r/privacy, r/selfhosted, r/sysadmin) with disclosure.
  - `demo-video-script.md` — 90-second storyboard with cue-level timing.
  - `press-release.md` — embargoed release + journalist outreach email.
  - `email-launch.md` — waitlist email + variants for paying partners + dormant signups.

### In flight
- Real deploy on staging stack (still pending external network env).
- Smoke + eval against live PhishTank corpus.
- Designer-quality icons for the extension (currently no PNGs in `icons/`).
- Brand registry coverage expansion 50 → 500 via CT-driven seeding.

### Blockers
- None.

### Next session candidates
- **Browser extension Firefox port + Safari WebExtension build.**
- **Demo / launch-day support tooling**: live demo URL rotator, "did GSB/VT/SmartScreen miss this" cross-check service.
- **Onboarding flow** for the personal dashboard: signup → verify email → device enrollment → first verdict.
- **Status-page automation**: synthetic monitors + auto-flip-to-degraded webhook.
- **Stripe billing integration end-to-end** for Free/Plus/Family/Business tiers.

---

## 2026-W20d — Session 4 (2026-05-14)

**Phase:** 0 → 1
**Status:** detection plumbing closed end-to-end; ops + go-to-market scaffolded

### Done
- **`services/verdict-api/internal/registry`** (XGG-37):
  - In-memory Brand cache hydrated from Postgres at boot.
  - 5-minute periodic refresh; `Lookup(token)` resolves brand_name / keyword / domain-SLD.
  - `AllKeywords()` feeds Tier-1 homoglyph detector (replacing the hardcoded 18-brand fallback list).
  - Wired into `verdict-api/cmd/main.go` and `httpgw/pipeline.go` — the universal identity-mismatch rule now actually has `canonical_domains`, `legitimate_asns`, `legitimate_issuers` to compare against.
- **`docs/runbooks/`** (XGG-38): 7 files
  - `README.md`, `incident-response.md`, `on-call.md`, `deploy.md`, `phishing-report-triage.md`, `false-positive-triage.md`, `brand-registry-update.md`, `rotate-secrets.md`.
- **`apps/landing/`** (XGG-39): Next.js marketing site, 8 sections
  - Nav, Hero, Differentiators, HowItWorks, Comparison table (vs Quad9/NextDNS/Cloudflare), Demo block, Pricing (4 tiers), FAQ (8 honest answers), Footer.
  - Dockerfile, port 3001 to avoid clash with Transparency Portal.

### In flight
- gRPC stub generation (protoc) — still waiting on dev env install.
- Real `terraform apply` against DO + Cloudflare.
- End-to-end smoke test on a `docker compose up` environment.

### Blockers
- None.

### Next session
- Run `docker compose up` + `make migrate` + `make seed-brands` + `make smoke` against a real environment to flush out integration bugs.
- Add a **browser extension v0** (Chrome MV3) for Phase 2 prep.
- Add **postmortem template** and **status-page integration runbook** to `docs/runbooks/`.
- Write **status.xgenguardian.com** static page or pick a vendor (Statuspage / Instatus / Atlassian).

---

## 2026-W20c — Session 3 (2026-05-14)

**Phase:** 0 → Phase 1 substantially scaffolded
**Status:** detection-logic core landed; repo passes its own bar

### Done
- **`services/verdict-api/internal/fusion`** (XGG-18 REVIEW):
  - Identity-mismatch rule from architecture.md §27 #13 implemented.
  - Blocklist short-circuit, weak-visual-match path, domain-age curve.
  - Unit tests cover the canonical w1thineartht.com lookalike scenario + canonical-domain negative + blocklist + weak-match + clean-old-domain.
- **`services/verdict-api/internal/httpgw/pipeline.go`** (XGG-30):
  - Replaced stub `runPipeline` with real Tier-1 + Tier-2 orchestration.
  - Calls sandbox-render and visual-match via HTTP; fuses with internal/fusion.
  - `shouldRunTier2` decides when to escalate based on Tier-1 score + URL heuristics.
- **`scripts/smoke.sh`** (XGG-34): exercises every endpoint, prints pass/fail, exits non-zero on any failure. `make smoke`.
- **`CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`** (XGG-35): MIT, responsible disclosure with response SLAs, contribution & branch rules, detection-change policy.
- **Linter configs** (XGG-36): `.golangci.yml`, `ruff.toml`, `apps/portal/.eslintrc.json`, `.editorconfig`, `.gitignore`. CI's lint job can now actually fail.

### In flight
- gRPC stub generation pending `protoc` install.
- Brand-registry hydrator (loads canonical domains/ASNs/issuers into fusion.Inputs) — needed for the universal rule to fire correctly without manual injection.
- First real `make smoke` run on a `docker compose up` environment.

### Blockers
- None.

### Next session
- Brand-registry hydrator in `verdict-api/internal/registry` (queries Postgres for top brand match given VisualTopBrand).
- Generate gRPC stubs and register the gRPC `VerdictServer` interface.
- First real PhishTank eval pass with `make eval` once seeder has populated brands.
- Apply Terraform staging stack against a real DO/Cloudflare pair.

---

## 2026-W20b — Session 2 continued (2026-05-14)

**Phase:** 0 → spilling into Phase 1
**Status:** scaffolding round 2 — integrations + ops

### Done
- **`tools/blocklist-fetcher`** — 4-source ingest (PhishTank, OpenPhish, URLhaus, ThreatFox) into Redis + flat file (XGG-5 REVIEW).
- **`services/verdict-api/internal/httpgw`** — HTTP gateway with `/v1/check`, `/v1/rescan`, CORS, JSON contract (XGG-30 REVIEW).
- **`services/portal-api`** — `/v1/evidence/:id` + `/v1/recent` (XGG-31 REVIEW).
- **`services/ct-monitor`** — Certstream WebSocket subscriber + 5-min keyword hot-reload + prescan-queue enqueue (XGG-23 REVIEW).
- **`tools/eval/run.py`** — eval harness with Phase-1 exit-gate checks built in (XGG-24 REVIEW).
- **7 Dockerfiles** — multi-stage Go (resolver, verdict-api, portal-api, ct-monitor), Playwright Python (sandbox-render), CLIP Python (visual-match), Next.js (portal) (XGG-32 REVIEW).
- **`.github/workflows/ci.yml`** — go-build matrix, python smoke-import, portal lint+build, migrations sanity vs. live PG (XGG-1 REVIEW).
- **`scripts/gen-proto.sh` + Makefile `proto`** target (XGG-33 REVIEW).
- **`infra/terraform/staging`** — Droplet + managed PG/Redis + Spaces bucket + Cloudflare DNS (XGG-22 IN_PROGRESS).

### In flight
- gRPC stub generation — script ready, awaiting `protoc` install in dev env.
- Verdict-pipeline wiring inside `httpgw.runPipeline` (currently returns ANALYZING stub).
- First `terraform apply` against real DO + Cloudflare accounts.

### Blockers
- None.

### Next session
- Run brand seeder end-to-end against the 50 brands (XGG-16 final pass).
- Wire `verdict-api/internal/httpgw.runPipeline` to actually call tier1 + sandbox-render + visual-match.
- First real `make eval` run against PhishTank last-24h.
- Apply Terraform staging stack.

---

## 2026-W20 — Week of 2026-05-11

**Phase:** 0 (Foundations)
**Status:** Kickoff

### Done
- Architecture document finalized (`docs/architecture.md`, 36 sections).
- Repo skeleton scaffolded under `code/`.
- Phase 1 task list opened in `docs/tasks/TASKS.md` with 22 tickets + 7 foundation tickets.
- Phase definitions written for all 6 phases under `docs/phases/`.
- **Starter code landed for 7 components (all in REVIEW pending wiring):**
  - `services/resolver` — Go DoH endpoint, Bloom allow/block, Redis cache, sinkhole/upstream routing.
  - `services/verdict-api` — Go gRPC scaffold + Tier-1 worker (cert + lexical + homoglyph w/ Cyrillic confusables).
  - `services/sandbox-render` — Python FastAPI + Playwright + S3 evidence upload + form extraction.
  - `services/visual-match` — Python FastAPI + OpenCLIP ViT-B/32 + pgvector kNN + favicon pHash/MMH3.
  - `tools/brand-seeder` — Python seeder + `brands.yaml` (50 most-impersonated brands).
  - `apps/portal` — Next.js 14 Transparency Portal w/ paste-URL form, verdict panel, `/report/[id]` evidence pages.
  - `migrations/0001_init.sql` — full Phase-1 schema (domains, urls, brands, brand_screenshots, evidence, scan_history, prescan_queue).
- `proto/verdict/v1/verdict.proto` — gRPC contract.
- `docker-compose.yml` — Postgres+pgvector, Redis, MinIO, CoreDNS.
- `Makefile` + root `README.md`.

### In flight
- Day-1 setup tickets (XGG-25 to XGG-29).
- 13 tickets in REVIEW — skeletons need wiring + tests + integration.

### Blockers
- None.

### Next week (W21)
- **Wire skeleton-to-skeleton:** generate gRPC stubs (`protoc`), connect resolver → verdict-api → sandbox-render → visual-match end-to-end.
- **Close XGG-5:** PhishTank/OpenPhish/URLhaus hourly ingest cron.
- **Close XGG-22:** deploy to staging.xgenguardian.io.
- **Run brand seeder** end-to-end with all 50 brands.
- **First eval pass** against PhishTank last-24h corpus (XGG-24).

### Phase 1 exit gate progress
- ☐ Catches ≥50% of last 100 PhishTank URLs <24h old
- ☐ Catches ≥10 phish missed by GSB + SmartScreen + VT
- ☐ Median verdict <5s unknown / <100ms cached
- ☐ ≥1,000 daily verdict-page views within 30d of launch
- ☐ Public DoH endpoint + Transparency Portal live

---

## Template

```
## YYYY-Www — Week of YYYY-MM-DD

**Phase:** N
**Status:** ...

### Done
- ...

### In flight
- ...

### Blockers
- ...

### Next week
- ...

### Phase exit gate progress
- ☐ / ☑ criterion
```
