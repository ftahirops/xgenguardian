# XGenGuardian

**Action-aware web protection for DNS, browsers, copied commands, OAuth consent, downloads, and child/paranoid policy modes.**

XGenGuardian is not another DNS blocklist wrapper. It is a web trust engine that asks a stronger question before a user takes a risky action:

> Is this page authorized to ask this user for this action, and where will the action actually go?

Most products classify a domain or URL as safe or unsafe. XGenGuardian classifies the **action**: reading a page, entering a password, approving OAuth scopes, copying a terminal command, downloading a file, opening a popup, or visiting unknown content under child/strict/paranoid mode.

For the full technical blueprint, see [`docs/blueprint-architecture.md`](docs/blueprint-architecture.md).

## Eye-Catching Feature Summary

| Feature | Why It Matters |
|---|---|
| Action-aware verdicts | A site can be safe to read but unsafe to log into, copy from, authorize, or download from. |
| Protective DNS + browser extension | DNS blocks fast at domain level; the browser sees URL path, DOM, forms, clipboard, popups, and downloads. |
| Copy-command defense | Catches fake developer documentation, ClickFix, `curl-to-shell`, PowerShell `iex`, encoded payloads, and visible-vs-clipboard command swaps. |
| Identity/sink binding | Blocks pages that look like a brand but send credentials, OAuth, forms, or scripts to untrusted infrastructure. |
| Sandbox render + visual match | Uses rendered DOM, screenshots, OCR, YARA, forms, downloads, and behavior instead of relying only on reputation. |
| OAuth and install registries | Positive trust for official apps, official docs, known command templates, and known publisher patterns. |
| Transparent evidence | Verdicts include reason codes, screenshots, signals, and report pages instead of opaque "blocked by policy" messages. |
| Child, strict, paranoid modes | Unknown sensitive actions can warn, isolate, block, detonate, or require approval depending on policy. |
| Self-hostable security stack | Operators can run the system without handing all DNS and browsing metadata to a third-party SaaS resolver. |
| xhelix bridge-ready | XGenGuardian stops risky web actions; xhelix can consume provenance if the action reaches host execution. |

## What This System Is

XGenGuardian is a layered security platform with five main enforcement surfaces:

1. **Protective DNS resolver** for fast domain-level policy, blocklists, never-block lists, RPZ-style enforcement, rebind defense, and device/network coverage.
2. **Verdict API** for URL checks, staged scoring, reason codes, registries, feed lookups, policy modes, and evidence persistence.
3. **Browser extension** for navigation checks, warning/block pages, copy-command mediation, popup lineage, and browser-context enforcement.
4. **Sandbox render and visual analysis** for dynamic pages, screenshots, DOM, forms, downloads, OCR, YARA, and phishing-kit behavior.
5. **Transparency portal** for manual scans, reports, admin views, live events, and explainable evidence.

It is built for attacks that reputation-first products often miss:

- newly created phishing pages,
- compromised legitimate sites,
- fake developer documentation,
- JavaScript-swapped clipboard commands,
- OAuth consent abuse on real provider domains,
- image/QR-based lures,
- first-seen login/payment pages,
- child-safety decisions where "unknown" should not mean "allowed",
- high-risk downloads that should be detonated before release.

## System Architecture

```text
                            User / Device
                    navigation, DNS, copy, OAuth,
                    forms, download, popup, scan
                                  |
          +-----------------------+-----------------------+
          |                                               |
          v                                               v
+--------------------+                         +--------------------+
| Protective DNS     |                         | Browser Extension  |
| - domain policy    |                         | - full URL checks  |
| - RPZ/blocklists   |                         | - DOM/form context |
| - rebind defense   |                         | - copy mediation   |
| - category rules   |                         | - warning UI       |
+---------+----------+                         +----------+---------+
          |                                               |
          +-----------------------+-----------------------+
                                  |
                                  v
                         +--------+---------+
                         | Verdict API      |
                         | staged policy    |
                         +--------+---------+
                                  |
       +--------------------------+--------------------------+
       |                          |                          |
       v                          v                          v
+------+-------+          +-------+-------+          +-------+-------+
| Fast Path    |          | Deep Render   |          | Registries    |
| cache, feeds,|          | Playwright,   |          | brand, OAuth, |
| lexical, DNS |          | DOM, YARA, OCR|          | install, trust|
+------+-------+          +-------+-------+          +-------+-------+
       |                          |                          |
       +--------------------------+--------------------------+
                                  |
                                  v
                        +---------+----------+
                        | Fusion + Mode      |
                        | Policy Engine      |
                        +---------+----------+
                                  |
            +---------------------+---------------------+
            |                     |                     |
            v                     v                     v
          ALLOW                  WARN                  BLOCK
                                                        |
                                      +-----------------+----------------+
                                      |                                  |
                                      v                                  v
                                    ISOLATE                         DETONATE /
                                                                    REQUIRE_APPROVAL
```

## Why It Is Not the Same as NextDNS, Quad9, Umbrella, or Browser Safe Browsing

DNS products are excellent at fast, broad, low-latency blocking. Browser vendors are excellent at huge-scale reputation. Enterprise secure web gateways are strong at managed fleet policy. XGenGuardian is different because its core model is **proof-first for sensitive actions**.

```text
Typical DNS/security product:
  domain or URL -> reputation/category lookup -> allow/block

XGenGuardian:
  page -> claimed identity -> requested action -> sink/target -> policy mode -> verdict + evidence
```

| Capability | DNS-only products | Browser built-ins | Enterprise SWG | XGenGuardian |
|---|---:|---:|---:|---:|
| Domain reputation | Strong | Strong | Strong | Strong via feeds/resolver |
| URL/path context | Weak | Medium | Strong | Strong |
| DOM/form analysis | None | Limited | Medium | Strong |
| Rendered screenshot/OCR evidence | None | Limited | Mixed | Core design |
| Copy-command mediation | None | None | Rare | Core feature |
| Visible text vs clipboard mismatch | None | None | Rare | Core feature |
| OAuth consent risk analysis | None | Weak | Mixed | Core feature |
| Developer install-lure detection | None | Weak | Rare | First-class page class |
| Per-action policy | Category-based | Mostly reputation | Mixed | Core model |
| Child/paranoid handling for unknown sensitive actions | Category-based | Limited | Mixed | First-class modes |
| Transparent evidence bundle | Weak | Weak | Mixed | Core design |
| Self-hostable privacy | Mixed | No | Usually no | Yes |
| Massive global telemetry | Provider advantage | Browser advantage | Vendor advantage | Not the goal |

XGenGuardian does not try to out-index Google or out-telemetry enterprise security clouds. It shines where those systems are structurally weaker: **fresh sensitive pages, command-copy malware, brand impersonation with untrusted sinks, OAuth consent abuse, strict child/paranoid decisions, and evidence-driven self-hosted protection.**

## How Verdicts Work

XGenGuardian avoids one flat score. It stages decisions so unrelated signals do not get mixed too early.

| Stage | Question | Example Output |
|---|---|---|
| Normalize | What URL is really being requested after redirects, shorteners, encoding, and punycode? | canonical URL graph |
| Reputation | Is the domain or URL already known? | known bad, known safe, unknown |
| Page class | What kind of action does this page request? | login, payment, OAuth, developer install, download, chat, adult, generic |
| Replica | Does the page visually or semantically claim a known brand? | claimed brand + similarity |
| Identity | Is the host, tenant, cert, ASN, script, form, or OAuth target authorized for that brand? | authorized, mismatch, unknown |
| Sink | Where will credentials, OAuth, clipboard, downloads, or forms go? | trusted sink, untrusted sink, unknown |
| Policy mode | What should this user/profile allow under uncertainty? | allow, warn, block, isolate, detonate, require approval |

Core rule:

```text
high brand similarity + identity mismatch + sensitive action = block
```

Stronger rule:

```text
sensitive action + untrusted sink = block
```

## Where XGenGuardian Shines

| Attack | Why Common Defenses Miss | XGenGuardian Response |
|---|---|---|
| Fake docs with malicious terminal command | No file download, fresh domain, trusted hosting platform | Browser copy guard + command analyzer + install registry |
| JavaScript command swap | User sees safe text but clipboard receives payload | Visible-vs-clipboard and copy-event mediation |
| OAuth consent phishing | Real OAuth provider domain may look legitimate | OAuth scope/client/redirect/publisher analysis |
| New login clone | Domain has no reputation yet | Visual/semantic replica + identity mismatch |
| Compromised legitimate site | Domain reputation may be clean | Path-level URL verdicts, forms, sinks, DOM behavior |
| QR/image lure | URL hidden in image or rendered content | OCR/QR recursion through render pipeline |
| HTML smuggling | Payload assembled inside browser | Sandbox render + YARA + download behavior |
| Child visits unknown chat/community | Category lists lag or miss niche sites | Child mode treats unknown sensitive categories as approval/block |

## Security Posture

XGenGuardian is designed as a high-security, evidence-first system:

- **Self-hostable by default** so operators can keep DNS, URL, and evidence data under their own control.
- **Layered enforcement** so DNS, browser, API, sandbox, registries, and portal each cover different blind spots.
- **Reason-coded verdicts** so every decision can be audited, tuned, and appealed.
- **Policy modes** so uncertainty is handled differently for normal users, children, executives, developers, and paranoid profiles.
- **Positive trust registries** so official install commands and known vendors can be allowed without weakening detection for clones.
- **Sandboxed dynamic analysis** so JavaScript-mutated pages, downloads, YARA hits, and behavior are captured after render.

No security product is "perfect" against every attack. XGenGuardian's security advantage is narrower and more defensible: it raises the bar for risky web actions that happen before endpoint tools usually get a chance to respond.

## xhelix Integration

XGenGuardian and xhelix are complementary.

| Layer | XGenGuardian | xhelix |
|---|---|---|
| Web page classification | Owns | Consumes selected context |
| DNS/URL action verdicts | Owns | Consumes selected context |
| Copy-command prevention | Owns | Consumes provenance if command executes |
| Download pre-scan | Owns | Observes file/process behavior |
| Process execution | No | Owns |
| Secret/API-key reads | No | Owns |
| Outbound C2 from process | Enriches with domain intel | Owns enforcement |
| Containment | Browser/DNS/isolation | Host/process/cgroup |

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
xhelix host enforcement
  process lineage
  command executed
  files/secrets touched
  outbound destination
  containment decision
```

This proves the combined story: XGenGuardian prevents risky web-originated actions; xhelix contains the host if prevention fails or a user bypasses a warning.

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

# 6. Send a test DoH query
make test-doh URL=https://example.com
```

## Repo Layout

```text
code/
├── apps/             browser extension, portal, landing page, Windows client
├── services/         resolver, verdict API, sandbox render, visual match, scheduler
├── tools/            brand seeder, blocklist fetcher, bulk scan, eval, fp-bench
├── docs/             architecture, blueprint, phases, runbooks, tasks, progress
├── proto/            shared protobuf definitions
├── migrations/       Postgres schema
├── infra/            deployment infrastructure
└── docker-compose.yml
```

## Where to Start

- [`docs/blueprint-architecture.md`](docs/blueprint-architecture.md) - public-facing system blueprint and differentiation.
- [`docs/architecture.md`](docs/architecture.md) - full architecture, threat model, and implementation plan.
- [`docs/SIMPLE-SETUP.md`](docs/SIMPLE-SETUP.md) - simplest operator setup.
- [`docs/USAGE.md`](docs/USAGE.md) - full operator setup.
- [`docs/tasks/TASKS.md`](docs/tasks/TASKS.md) - active task tracking.

## License

TBD - see [`LICENSE`](LICENSE).
