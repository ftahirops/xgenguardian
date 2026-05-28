# Internal Testing Phase (between Phase 1 and Phase 2)

**Goal:** the operator runs the whole stack on their own machine, points one browser at the local DoH endpoint, and clicks the worst of the open web — phishing pages, malware-laden ads, fake software updates, drive-by exploit lures, virus-infected freeware sites — to validate the system catches what it should and lets through what's safe.

This is the "does it actually work" gate before any public launch.

## What "ready" looks like

The operator opens a browser configured for our DoH, visits any URL, and within 3 seconds either:

1. The page loads normally **and** the verdict shows `CLEAN` in the live activity feed, OR
2. The page is intercepted by a sinkhole **and** the block interstitial shows the screenshot + evidence + LLM explanation, OR
3. They land on the "Analyzing this site for your safety…" interstitial that auto-redirects when the verdict resolves.

Each verdict appears in the operator's Live Activity Feed within ~1s of being decided.

## Test scenarios

The operator clicks through each of these categories. Expected verdicts in parentheses.

### 1. Known-safe baseline
- google.com / wikipedia.org / github.com / your bank's real domain.
- **Expected:** `CLEAN` cache hit, <50ms. No interstitial. No badge.
- **Validates:** Tranco allowlist, no false positives on top-1M.

### 2. Phishing — known to PhishTank / OpenPhish
Pull 10 fresh entries from `https://data.phishtank.com/data/online-valid.json`.
- **Expected:** `BLOCK` from the aggregated blocklist within 50ms.
- **Validates:** blocklist ingest, Bloom filter, sinkhole.

### 3. Phishing — never-seen lookalikes
The operator constructs typo/homoglyph URLs against the seeded 50 brands and visits them. (Many will be parked / NXDOMAIN; that's fine.) Try:
- `paypa1.com`, `paypaI.com` (capital I), `pаypal.com` (Cyrillic а)
- `g00gle-secure-login.tk`
- `microsoft-account-verify.<some-NRD-TLD>`
- `coinbase-wallet-recover.xyz`
- **Expected:** `BLOCK` from identity-mismatch rule even when no blocklist has seen them.
- **Validates:** homoglyph detection + visual brand match + fusion universal rule.

### 4. Malware-hosting / drive-by lures
Use URLhaus's recent list (`https://urlhaus.abuse.ch/downloads/csv_recent/`). Several entries are direct binary downloads.
- **Expected:** `BLOCK` on the URL; if it slips through, the file-download scanner downloads the binary in the sandbox and flags it.
- **Validates:** URLhaus ingestion + file-download scanning.

### 5. Clickbait / scam / tech-support / fake-update lures
These often don't impersonate a brand but try to scare/induce action.
- "Your computer is infected! Call 1-800-..."
- Fake CAPTCHA → ClickFix paste-to-run
- Fake Chrome update pages
- **Expected:** `WARN` based on behavioral signals (push-notification abuse, weird domains, suspicious lexical features). Some may slip through; document which.
- **Validates:** lexical scoring, behavior heuristics. Documents detection gaps.

### 6. Compromised legitimate sites
Use anything from a Magecart or wp-skimmer feed (e.g. Sucuri's recent reports).
- **Expected:** `WARN` based on JS AST analysis detecting skimmer patterns; if it's a known-good site that suddenly went bad, the DOM-drift check (Phase-4) catches it. Phase-1 misses some; document them.
- **Validates:** JS deobfuscation, drift detection.

### 7. Tracker-heavy sites
Pick any news site (nytimes.com, cnn.com).
- **Expected:** Page loads normally (`CLEAN` for the domain) but the extension blocks ~10–50 tracker requests via declarativeNetRequest.
- **Validates:** extension tracker blocklist.

### 8. False-positive sentinel
Visit five obscure but legitimate sites:
- A personal blog (>3 years old, niche topic)
- A regional bank's actual domain
- A small SaaS company's signup page
- A government site (.gov, .gc.ca, etc.)
- An indie game's official site
- **Expected:** all `CLEAN`. Any `BLOCK` here is an FP and must be fixed before public launch.
- **Validates:** false-positive rate ≤ 0.5%.

## Success gates (operator runs through all 8 in one session)

- [ ] Tier-1 verdict latency p50 < 300ms, p95 < 800ms.
- [ ] Tier-2 verdict latency p50 < 5s, p95 < 8s.
- [ ] Known-phishing block rate ≥ 95% on PhishTank fresh entries.
- [ ] Zero-day lookalike block rate ≥ 70% on operator-constructed homoglyphs.
- [ ] FP rate 0% on the false-positive sentinel set.
- [ ] Tracker-block count > 10 on a typical news site visit.
- [ ] Live activity feed shows every verdict within 1 second.
- [ ] Block interstitial renders correctly with screenshot + reason + evidence link.
- [ ] No service crash during a 30-minute browsing session.
- [ ] Resolver continues serving DNS even if verdict-api crashes (fail-open on uncertain).

## Operator setup checklist (one-time)

See [`docs/runbooks/internal-testing.md`](../runbooks/internal-testing.md) for the actual commands. High-level:

1. Install Docker.
2. Clone repo. Run `scripts/bringup.sh`.
3. Install dev TLS cert into OS trust store (script handles this).
4. Configure Firefox (recommended) for DoH against `https://dns.local.test:8543/dns-query`.
5. Open `http://localhost:3000/live` for the activity feed.
6. Start clicking dangerous things.

## What to log per session

Save the activity feed + any verdict you disagree with. For every disagreement, create a `docs/bugs/BUGS.md` entry tagged `internal-test`. After three test sessions, triage the bug list into actual fixes before considering public launch.

## What NOT to test in this phase

- Mobile (Phase 6).
- Non-browser apps (endpoint client, Phase 5).
- Multi-tenant SaaS flows (Phase 3).
- Stripe billing (explicitly skipped — operator decision).
- Email/SMS phishing (Phase 4).

## Hardware

Internal testing fits comfortably on a developer laptop with:
- 16 GB RAM (Docker uses ~6 GB at peak: Postgres + Playwright + CLIP + Go services).
- ~20 GB free disk.
- No GPU required; CPU CLIP is fine for one user's traffic.

Network: requires outbound HTTPS to: PhishTank, OpenPhish, URLhaus, Certstream, Tranco, the upstream resolver (Quad9 9.9.9.9 by default).
