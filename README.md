# XGenGuardian

**Action-aware web protection beyond DNS filtering.**

XGenGuardian is a self-hostable security system that protects users before risky web actions happen: login, payment, OAuth consent, command copy, file download, popup navigation, and raw-IP browsing. It combines protective DNS, a browser extension, local threat intelligence, sandbox rendering, visual brand matching, credential-sink analysis, command-copy protection, OAuth checks, scam behavior detection, and transparent evidence pages.

Traditional filters ask:

```text
Is this domain known bad?
```

XGenGuardian asks:

```text
Is this page allowed to ask this user for this action?
```

That difference is the product.

## Index

1. [What Makes It Different](#what-makes-it-different)
2. [Current Release Highlights](#current-release-highlights)
3. [Step-By-Step Protection Flow](#step-by-step-protection-flow)
4. [Where It Outperforms Traditional Filters](#where-it-outperforms-traditional-filters)
5. [Architecture](#architecture)
6. [Advanced Catch Examples](#advanced-catch-examples)
7. [Verdict Types](#verdict-types)
8. [Maturity And Testing](#maturity-and-testing)
9. [xhelix Integration](#xhelix-integration)
10. [Quick Start](#quick-start)
11. [Docs](#docs)

## What Makes It Different

| Layer | What Most Products See | What XGenGuardian Adds |
|---|---|---|
| DNS | domain reputation | resolver policy, rebind defense, local feeds, DNS evidence |
| Browser | URL reputation | full URL, opener lineage, copy events, popup/new-tab context |
| Page | limited or none | rendered DOM, forms, scripts, downloads, screenshots, behavior |
| Identity | domain allow/block | claimed brand vs authorized infrastructure |
| Sensitive action | mostly invisible | login sink, OAuth scopes, copied command, payment/download target |
| Evidence | opaque category | reason codes, screenshots, checklist, report page |
| Privacy | third-party SaaS by default | self-hostable, local registries, configurable retention |

**Core rule:**

```text
Reputation can clear normal browsing.
Only proof can clear sensitive action.
```

## Current Release Highlights

The current stabilization line has focused on real-user reliability, false-positive control, and evidence clarity.

| Area | Current Behavior |
|---|---|
| Extension reliability | holding page has a hard watchdog; no indefinite spinner by design |
| Failure handling | if verification stalls, user gets clear choices instead of being trapped |
| DNS failure UX | DNS/network failures show a friendly "not an XGG block" explainer |
| Permanent allowlist | Options page supports trusted hostnames, suffixes, IPs, and CIDRs |
| 24h trust | user can temporarily trust a site and revoke it later |
| Raw IP handling | public raw-IP URLs are aggressively scanned/blocked unless operator-trusted |
| OAuth and email wrappers | known auth hosts and enterprise link wrappers are handled without loops |
| Evidence pages | warn/block/isolate pages show detailed analysis and hide broken images cleanly |
| Testing | `make maturity-test` runs release-gate checks across backend, extension, corpus, and status |

Passing `make maturity-test` means the current known release gate is green. It does **not** mean the internet is solved; every real false positive/false negative still becomes a permanent regression test.

## Step-By-Step Protection Flow

### 1. Normalize

XGenGuardian first normalizes the request:

```text
raw URL -> decoded URL -> host -> path -> redirects -> final URL -> canonical evidence key
```

It handles long URLs, wrappers, punycode, fragments, nested destinations, raw IPs, and browser-internal schemes safely.

### 2. Check Known Bad And Known Safe Signals

Fast checks run first:

- local threat feeds,
- domain/URL cache,
- known blocklists,
- trusted identity registry,
- user/operator allowlist,
- external reputation evidence when configured,
- raw IP and direct-download shape.

High-confidence bad can block immediately. Clean reputation lowers risk, but it does not bypass sensitive-action checks.

### 3. Classify The Page Action

The engine decides what kind of page this is:

| Page Class | Why It Matters |
|---|---|
| login | credentials require trusted identity and trusted sink |
| payment/billing | payment processor trust must be action-scoped |
| OAuth | client ID, scopes, redirect URI, publisher matter |
| developer install/docs | copied commands can be the payload |
| download | file type, source, hash, and sandbox behavior matter |
| support/refund/tax | phone, remote-tool, gift-card, crypto phrases matter |
| generic browsing | lower friction, reputation often enough |

### 4. Run Tier-1 Fast Checks

These are low-latency checks:

- homoglyph and typosquat detection,
- DGA/random hostname detection,
- suspicious domain keywords,
- certificate age,
- raw-IP shape,
- shared-hosting tenant handling.

### 5. Decide Whether To Deep Scan

Deep scan is forced for high-risk cases:

- login, payment, OAuth, MFA, recovery,
- unknown billing/checkout pages,
- developer install pages,
- public raw-IP URLs,
- unknown downloads,
- brand name in URL,
- shared-hosting tenants,
- suspicious opener/popup lineage,
- strict, child, paranoid, or ultra mode.

### 6. Sandbox Render

The sandbox opens the page in Chromium and extracts:

- screenshot,
- DOM,
- forms and credential sinks,
- downloads,
- scripts,
- YARA matches,
- popup/alert/fullscreen behavior,
- hidden fields,
- code blocks,
- shell commands,
- final URL and redirects.

### 7. Visual And Identity Binding

Visual match asks:

```text
What brand does this page look like?
```

Identity binding asks:

```text
Is this host allowed to represent that brand for this action?
```

Example:

```text
looks like Microsoft + not Microsoft infrastructure + asks for password = block
```

### 8. Sink And Action Verification

XGenGuardian checks where the action goes:

| Action | Verified By |
|---|---|
| password | form action, fetch/XHR/beacon/WebSocket sink |
| payment | known payment processor scoped to payment action |
| OAuth | client ID, scopes, redirect URI, provider |
| command copy | command structure, official install registry, clipboard mediation |
| download | file type, hash, YARA, direct-download pattern |
| support/refund | phone, remote-support tool, gift-card/wire/crypto phrases |

### 9. Final Policy

The staged policy combines evidence into:

```text
ALLOW / WARN / ISOLATE / BLOCK / REQUIRE_APPROVAL / DETONATE
```

Policy mode changes the risk tolerance:

| Mode | Intended Use |
|---|---|
| Normal | low friction |
| Safe | default daily browsing |
| Family | child/content safety |
| Strict | stronger unknown-site scrutiny |
| Paranoid | sensitive pages isolate when not proven |
| Ultra | maximum proof requirement, intentionally noisy |

## Where It Outperforms Traditional Filters

XGenGuardian is strongest when the attack is not yet known to global reputation systems.

| Attack Class | Why DNS/Reputation Misses | XGenGuardian Catch Point |
|---|---|---|
| fresh phishing | domain has no history | visual replica + identity mismatch + sink analysis |
| fake developer docs | no malicious download, just copied text | command-copy mediation + shell IOC scanner |
| JavaScript clipboard swap | visible text looks safe | copy event and clipboard comparison path |
| OAuth consent abuse | real provider domain looks clean | unknown client + sensitive scopes + redirect risk |
| compromised legitimate site | parent domain is reputable | path-level verdict + rendered sink behavior |
| support scam | may be a new clean domain | phone/remote-tool/popup/brand correlation |
| raw-IP malware link | DNS never sees it | browser/API raw-IP policy + binary path detection |
| HTML smuggling | payload assembled after render | sandbox render + YARA + download behavior |
| popup scareware | reputation may lag | popup storm, alert loop, fullscreen, beforeunload signals |
| shared-hosting abuse | parent platform is legitimate | tenant-aware checks, not apex-domain blocking |

## Architecture

```text
User / Browser / Device
  DNS lookup, navigation, copy, OAuth, form, download, popup
          |
          +-------------------------+
          |                         |
          v                         v
  Protective DNS              Browser Extension
  fast domain policy          URL, DOM, copy, popup
          |                         |
          +-----------+-------------+
                      |
                      v
                Verdict API
          normalize, classify, policy
                      |
        +-------------+-------------+
        |             |             |
        v             v             v
   Fast Checks   Sandbox Render   Registries
   feeds/DNS     DOM/YARA/OCR     brand/OAuth/install
        |             |             |
        +-------------+-------------+
                      |
                      v
             Staged Policy Engine
                      |
        ALLOW / WARN / ISOLATE / BLOCK
```

## Advanced Catch Examples

The detailed casebook is in [`docs/advanced-detection-cases.md`](docs/advanced-detection-cases.md).

| Case | What Makes It Hard | Rule Combination That Catches It |
|---|---|---|
| fake Claude/OpenAI docs with malicious command | page looks like docs, no file download | developer-install page class + command scanner + official install registry |
| Microsoft support scam with phone in screenshot | phone may not be in DOM | OCR/visual brand + unknown support phone + scareware language |
| SafeLinks wrapped phishing URL | wrapper domain is Microsoft | unwrap destination + scan final URL + OAuth/page-class policy |
| public IP malware path | DNS reputation sees nothing | raw-IP host + binary/architecture path + direct download logic |
| compromised WordPress page | root domain may be clean | path-level reputation + form sink + behavior |
| OAuth app on real Google/Microsoft page | provider domain is legitimate | unknown client + sensitive scopes + redirect URI analysis |
| checkout false positive | payment sink is cross-origin by design | action-scoped payment processor trust |
| shared-hosting phishing tenant | platform domain is legitimate | tenant-level policy, never apex-level punishment |
| popup storm scareware | page may not steal credentials | popup/alert/fullscreen/beforeunload behavior composite |
| image-only QR phishing | URL hidden from DOM | screenshot OCR/QR extraction + recursive URL scan |

## Verdict Types

| Verdict | Meaning |
|---|---|
| ALLOW | enough evidence to proceed |
| WARN | suspicious, but not confirmed malicious |
| ISOLATE | risky/unknown; open with extra safety |
| BLOCK | high-confidence malicious or disallowed |
| REQUIRE_APPROVAL | parent/admin/operator approval needed |
| DETONATE | file/script requires sandbox analysis first |
| ALLOW_TEMP | temporary user approval with expiry |

## Maturity And Testing

The system has a dedicated maturity strategy:

- [`docs/maturity-testing-blueprint.md`](docs/maturity-testing-blueprint.md) defines release gates, chaos tests, FP/FN corpus rules, raw-IP policy, extension no-hang tests, privacy/retention, and accessibility requirements.
- [`docs/real-user-acceptance-test-plan.md`](docs/real-user-acceptance-test-plan.md) defines practical browser testing for real users.
- `make maturity-test` runs the release-gate suite.

Current testing stance:

```text
Automated tests prove known cases still work.
Real-user acceptance testing proves the product is usable daily.
Every false result becomes a permanent corpus entry.
```

## xhelix Integration

XGenGuardian and xhelix are complementary.

| Layer | XGenGuardian | xhelix |
|---|---|---|
| web trust | owns URL, DOM, visual, OAuth, command-copy, download pre-check |
| host enforcement | sends provenance context | owns process, file, secret, cgroup, outbound behavior |
| prevention point | before risky web action | after execution starts |
| combined story | prevent web-originated risk | contain host impact if prevention fails |

```text
XGenGuardian evidence
  source_url
  page_class
  copied_command_hash
  downloaded_file_hash
  verdict
  reason_codes
        |
        v
xhelix runtime context
  process lineage
  command executed
  secrets touched
  outbound destination
  containment decision
```

## Quick Start

```bash
# 1. Bring up Postgres + Redis + MinIO + CoreDNS
docker compose up -d

# 2. Run database migrations
make migrate

# 3. Start backend services
make dev-backend

# 4. Seed the Brand Registry
make seed-brands

# 5. Start the Transparency Portal
make dev-portal

# 6. Run the maturity release gate
make maturity-test
```

## Repo Layout

```text
code/
├── apps/             browser extension, portal, landing page, Windows client
├── services/         resolver, verdict API, sandbox render, visual match, scheduler
├── tools/            brand seeder, blocklist fetcher, bulk scan, eval, fp-bench, maturity
├── docs/             architecture, blueprint, maturity, real-user testing, runbooks
├── proto/            shared protobuf definitions
├── migrations/       Postgres schema
├── infra/            deployment infrastructure
└── docker-compose.yml
```

## Docs

Start here:

- [`docs/advanced-detection-cases.md`](docs/advanced-detection-cases.md) - advanced phishing, scam, raw-IP, OAuth, and impossible-case detection examples.
- [`docs/blueprint-architecture.md`](docs/blueprint-architecture.md) - system architecture and differentiation.
- [`docs/maturity-testing-blueprint.md`](docs/maturity-testing-blueprint.md) - exhaustive release-gate and stability test plan.
- [`docs/real-user-acceptance-test-plan.md`](docs/real-user-acceptance-test-plan.md) - real browser testing strategy.
- [`docs/architecture.md`](docs/architecture.md) - full technical architecture and threat model.
- [`docs/SIMPLE-SETUP.md`](docs/SIMPLE-SETUP.md) - simplest operator setup.
- [`docs/USAGE.md`](docs/USAGE.md) - full operator setup.
- [`docs/tasks/TASKS.md`](docs/tasks/TASKS.md) - active task tracking.

## License

TBD - see [`LICENSE`](LICENSE).
