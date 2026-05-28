# XGenGuardian — Master Task List

Single source of truth for active work. Tasks reference architecture features by `#N` from `architecture.md` §27.

**Status legend:** `TODO` · `IN_PROGRESS` · `BLOCKED` · `REVIEW` · `DONE`

---

## Phase 0 — Foundations

| ID | Title | Owner | Status | Feature | Notes |
|----|-------|-------|--------|---------|-------|
| XGG-1 | Stand up Go monorepo + Turborepo + CI | Lead | REVIEW | — | repo skeleton + Makefile + .github/workflows/ci.yml complete |
| XGG-2 | Provision dev Postgres + Redis + MinIO via docker-compose | Backend | REVIEW | — | docker-compose.yml written; verify with `docker compose up` |
| XGG-25 | Register xgenguardian.com / .io domains + ACM certs | Infra | TODO | — | |
| XGG-26 | Set up Sentry, Grafana Cloud, status page | Infra | TODO | — | |
| XGG-27 | Decide observability conventions (OTel span naming) | Lead | TODO | — | |
| XGG-28 | Create Linear/Jira workspace, milestones for Phase 1 weeks | Lead | TODO | — | |
| XGG-29 | Write CONTRIBUTING.md + SECURITY.md | Lead | TODO | — | |

## Phase 1 — POC

### Epic E1 — Resolver MVP
| ID | Title | Owner | Status | Feature | Notes |
|----|-------|-------|--------|---------|-------|
| XGG-3 | Bootstrap resolver service with CoreDNS plugin shell | Backend | REVIEW | #1 | starter Go in services/resolver/cmd/resolver/main.go |
| XGG-4 | Implement DoH endpoint over HTTPS at /dns-query | Backend | REVIEW | #1 | RFC 8484 GET+POST handler implemented |
| XGG-5 | Ingest PhishTank + OpenPhish + URLhaus blocklist | Backend | REVIEW | #3 | tools/blocklist-fetcher complete (4 sources incl. ThreatFox) |
| XGG-6 | Tranco top-1M allowlist Bloom filter | Backend | REVIEW | #9 | scaffolded in resolver; needs data file |

### Epic E2 — Verdict API + Site Registry
| ID | Title | Owner | Status | Feature | Notes |
|----|-------|-------|--------|---------|-------|
| XGG-7 | Define verdict.proto + scaffold gRPC server | Backend | REVIEW | — | proto written; gRPC stubs generation pending |
| XGG-8 | Postgres migrations (domains, urls, brands, brand_screenshots, evidence) | Backend | REVIEW | #14 | migrations/0001_init.sql complete |
| XGG-9 | Redis verdict cache with TTL policy | Backend | IN_PROGRESS | #15 | client wired in resolver; verdict-api side TODO |
| XGG-10 | Tier-1 worker: WHOIS/RDAP + cert age + lexical | Backend | IN_PROGRESS | #5, #6 | cert + lexical + homoglyph implemented; WHOIS/RDAP TODO |
| XGG-11 | Homoglyph + Levenshtein detector vs. brand keywords | Backend | REVIEW | #8 | in services/verdict-api/internal/tier1/tier1.go |

### Epic E3 — Sandbox Render
| ID | Title | Owner | Status | Feature | Notes |
|----|-------|-------|--------|---------|-------|
| XGG-12 | Playwright headless render worker in Docker | ML/Infra | REVIEW | #10 | FastAPI service + /render endpoint complete |
| XGG-13 | Form-action extractor | Backend | REVIEW | #22 | cross-origin detection in sandbox-render |
| XGG-14 | Evidence uploader to MinIO/S3 with signed URLs | Backend | IN_PROGRESS | #37 | direct PUT works; signed URLs TODO |
| XGG-30 | Verdict API HTTP gateway (/v1/check, /v1/rescan) | Backend | REVIEW | — | wired to tier1 + fusion + sandbox + visual-match |
| XGG-31 | portal-api service (/v1/evidence/:id, /v1/recent) | Backend | REVIEW | #37 | services/portal-api complete |
| XGG-32 | Dockerfiles for all services | Infra | REVIEW | — | 7 Dockerfiles (multi-stage Go, Playwright base, CLIP base, Node) |
| XGG-33 | protoc generation script + Make target | Backend | REVIEW | — | scripts/gen-proto.sh wired |
| XGG-34 | Smoke test script (scripts/smoke.sh) | Infra | REVIEW | — | exercises every endpoint; `make smoke` |
| XGG-35 | CONTRIBUTING/SECURITY/LICENSE | Lead | DONE | — | MIT, responsible disclosure, contribution rules |
| XGG-36 | Linter configs (.golangci, ruff, eslint, editorconfig, gitignore) | Lead | DONE | — | repo passes its own CI on first run |
| XGG-37 | Brand-registry hydrator | Backend | REVIEW | #12 | services/verdict-api/internal/registry — 5min refresh, wired into pipeline |
| XGG-38 | Runbooks (incident, on-call, deploy, triage × 2, brand-update, secrets) | Lead | DONE | — | 7 runbooks under docs/runbooks/ |
| XGG-39 | Landing page (xgenguardian.com) | Frontend | REVIEW | — | apps/landing — Next.js, 8 sections, Docker-packaged |
| XGG-40 | Chrome MV3 extension v0 | Frontend | REVIEW | — | apps/extension — background SW, popup, options, block interstitial, tracker DNR rules |
| XGG-41 | Postmortem template + status-page runbook | Lead | DONE | — | docs/runbooks/postmortem-template.md + status-page.md + incidents/ |
| XGG-42 | Launch-day content (HN/X/Reddit/PR/email/video script) | Marketing | REVIEW | — | docs/launch/ — 7 files |
| XGG-43 | Internal-testing plan + runbook | Lead | DONE | — | docs/phases/internal-testing.md + docs/runbooks/internal-testing.md |
| XGG-44 | Wire resolver → verdict-api over HTTP | Backend | REVIEW | — | Real HTTP call; fail-open on error; verdict-mapping to cache TTLs |
| XGG-45 | Dev TLS cert generator | Infra | REVIEW | — | scripts/gen-dev-certs.sh — local CA + SAN cert for dns.local.test |
| XGG-46 | Live activity feed (SSE) | Backend + Frontend | REVIEW | — | verdict-api Redis pub/sub + /v1/stream; portal /live page |
| XGG-47 | File-download discovery + hashing | Backend | REVIEW | — | sandbox-render downloads.py; verdict-api risky_downloads signal in fusion |
| XGG-48 | One-shot bring-up script | Infra | REVIEW | — | scripts/bringup.sh — deps check, certs, compose, migrate, blocklist, build |
| XGG-49 | Procfile.dev + make dev-up | Infra | REVIEW | — | overmind/foreman/tmux fallback; single-command start of all 7 services |
| XGG-50 | Brand-seeder manual screenshot fallback | ML | REVIEW | #12 | brands.yaml `manual_screenshots:`, base64 path via /embed; MANUAL.md guidance |
| XGG-51 | Session JSONL log | Backend | REVIEW | — | verdict-api appends every verdict to data/sessions/YYYY-MM-DD.jsonl when SESSION_LOG_DIR set; auto-enabled in Procfile.dev |
| XGG-52 | make doctor — diagnostic script | Infra | REVIEW | — | scripts/doctor.sh checks toolchain, certs, infra, services, brand count, blocklist count, smoke /v1/check |
| XGG-53 | healthcheck Go binary | Backend | REVIEW | — | services/healthcheck — single-line JSON for status pages + scripts |
| XGG-54 | Bulk-scan tool | Backend | REVIEW | — | tools/bulk-scan/scan.py — plain text / JSON / Chrome history accepted |
| XGG-55 | Windows .NET tray client | Frontend | REVIEW | — | apps/windows-client — .NET 8, tray + WebView2 + native DoH config; build.ps1 |
| XGG-56 | Comprehensive USAGE.md | Lead | DONE | — | docs/USAGE.md — three deployment paths, testing workflow, cheat sheet |
| XGG-57 | DNS query log + admin schema | Backend | REVIEW | — | migrations/0002_admin.sql + resolver emits to Redis stream `xgg:dns` + portal-api drain worker |
| XGG-58 | Password-protected admin endpoints | Backend | REVIEW | — | portal-api /v1/admin/{stats,queries,verdicts} gated by ADMIN_PASSWORD HTTP Basic |
| XGG-59 | Admin dashboard UI | Frontend | REVIEW | — | apps/portal/app/admin: login, overview (counters + hour sparkline + top blocked), queries, verdicts; cookie session |
| XGG-60 | DNS test instructions | Lead | DONE | — | docs/dns-test.md — three test paths + expected verdicts + FP/FN workflow |

### Epic E4 — Visual Brand Match
| ID | Title | Owner | Status | Feature | Notes |
|----|-------|-------|--------|---------|-------|
| XGG-15 | Visual-match service loading OpenCLIP ViT-B/32 | ML | REVIEW | #11 | /embed + /match endpoints written |
| XGG-16 | Brand seeder — 50 brands → screenshots → embeddings → DB | ML | REVIEW | #12 | seed.py + brands.yaml (50 brands) written |
| XGG-17 | Favicon pHash + MMH3 service | ML | REVIEW | #11 | embedded in visual-match |
| XGG-18 | Identity-mismatch fusion rule v1 | Backend | REVIEW | #13 | services/verdict-api/internal/fusion + unit tests; threshold tuning pending real eval |

### Epic E5 — Portal & Demo
| ID | Title | Owner | Status | Feature | Notes |
|----|-------|-------|--------|---------|-------|
| XGG-19 | Transparency Portal Next.js scaffold + paste-URL form | Frontend | REVIEW | #37 | apps/portal with /api/check + verdict panel |
| XGG-20 | Per-verdict evidence page /report/[id] | Frontend | REVIEW | #37 | dynamic route + artifact links |
| XGG-21 | Side-by-side comparison view | Frontend | TODO | #37 | needs UI for phish vs brand canonical |
| XGG-22 | Deploy to single region (staging.xgenguardian.io) | Infra | IN_PROGRESS | — | Terraform staging skeleton landed; needs apply + bootstrap |

### Epic E6 — Eval & CT Monitor
| ID | Title | Owner | Status | Feature | Notes |
|----|-------|-------|--------|---------|-------|
| XGG-23 | CT-log monitor (Certstream + brand-prefix matcher) | Backend | REVIEW | #7 | services/ct-monitor — keyword hot-reload every 5m |
| XGG-24 | Evaluation harness against PhishTank last 24h | ML | REVIEW | — | tools/eval/run.py — gate checks built in |

---

## Phase 2+ (Tracked Later)

To be expanded when Phase 1 hits its exit gate.

---

## Burndown Snapshot

- Phase 0: 5 / 7 DONE (XGG-35/36/38/41/43); XGG-1/2 in REVIEW; XGG-25..29 still TODO
- Phase 1: 2 / 53 done (XGG-56, XGG-60 DONE) — **44 in REVIEW**, 4 in IN_PROGRESS
- Phase 2 prep: XGG-40 (Chrome extension v0) + XGG-55 (Windows tray client) in REVIEW
- Marketing: XGG-42 launch content in REVIEW
- **Operator admin dashboard with password gate landed.** Every DNS query the resolver answers is persisted to `dns_queries` via a Redis stream, surfaced in `/admin/queries` with filters; per-URL verdicts in `/admin/verdicts`; 24-h sparkline + top-blocked-domains in `/admin`. One password (`ADMIN_PASSWORD`), no account system.
- New this session: XGG-57..60 (DNS query log, admin endpoints, admin UI, DNS test doc)
- **Phase 1 exit gate**: catches ≥50% of last 100 PhishTank URLs <24h old; ≥10 phish that GSB+SmartScreen+VT all miss; median verdict <5s unknown / <100ms cached.

Last updated: 2026-05-14
