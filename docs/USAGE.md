# XGenGuardian — How to Use It

This is the operator's guide. Pick the deployment path that matches what you
want to test, follow the steps, and use the testing workflow at the end.

## Three deployment paths

| Path | Scope | Setup time | Trust required |
|---|---|---|---|
| **A. DNS only (DoH)** | One device, browser + system traffic | 2 min | Lowest |
| **B. + Browser extension** | One browser, full URL visibility | 4 min | Low |
| **C. + Windows tray client** | Whole machine, friendly UX | 6 min | Low–Medium |

All three connect to the same backend (the same Phase-1 POC stack). You can
mix them on different devices.

---

## 0. Prerequisites

On the machine running the backend (your dev workstation or a small VM):
- **Docker** + Docker Compose plugin
- **Go 1.22+**, **Node 20+**, **Python 3.11+**
- **openssl**
- One of: **overmind** (recommended) / **foreman** / **tmux**
- 16 GB RAM, ~20 GB disk

On the test client machine (can be the same machine):
- A fresh browser profile (Firefox recommended for granular DoH control)
- For Path C: Windows 10/11, .NET 8 SDK to *build*, no runtime needed to *run*

---

## 1. One-time backend setup

```bash
git clone https://github.com/xgenguardian/xgenguardian
cd xgenguardian/code
make bringup     # generates dev TLS certs, brings up Postgres/Redis/MinIO,
                 # runs migrations, ingests blocklists, builds Go services
make dev-up      # starts every service (overmind / foreman / tmux fallback)
make seed-brands # populates the 50-brand visual fingerprint registry
                 # (takes ~15 min first run; CLIP downloads + Playwright renders)
make doctor      # confirms everything is healthy
```

`make doctor` is your first stop whenever something feels wrong. It prints a
green OK for each component or a one-line fix command.

The Transparency Portal is now at <http://localhost:3000>.
The live activity feed is at <http://localhost:3000/live>.

---

## Path A — DNS only

You change one DNS setting; the system protects every app on that device.

### Firefox (recommended for testing)

1. Trust the dev CA in Firefox:
   Settings → Privacy & Security → View Certificates → Authorities → Import
   → select `tls/ca.pem` → tick "Trust this CA to identify websites"
2. Settings → Network Settings → enable DNS over HTTPS → Custom
3. Set URL: `https://dns.local.test:8543/dns-query`
   (or `https://localhost:8543/dns-query` if you skipped `/etc/hosts`)
4. Open <https://1.1.1.1/help> — should say "Using DNS over HTTPS: Yes".

### Chrome / Edge

Chrome doesn't allow custom DoH endpoints in the UI. Use a flag:

```
chrome.exe --enable-features="DnsOverHttps<study" --force-fieldtrials="study/yes" --force-fieldtrial-params="study.yes:server/https%3A%2F%2Fdns.local.test%3A8543%2Fdns-query/method/POST"
```

In practice, use Firefox for testing and reserve Chrome/Edge for the
browser-extension path.

### Whole-OS (every app uses it)

| OS | Command |
|---|---|
| **Windows 11** | `Add-DnsClientDohServerAddress -ServerAddress 127.0.0.1 -DohTemplate 'https://dns.local.test:8543/dns-query' -AllowFallbackToUdp $false -AutoUpgrade $true; Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter \| Where-Object Status -eq Up).ifIndex -ServerAddresses 127.0.0.1` (as Admin) |
| **macOS 14+** | System Settings → Network → your interface → Details → DNS → DNS Servers → add `127.0.0.1` and set DoH template manually via `networksetup` or a configuration profile |
| **Linux (systemd-resolved)** | `[Resolve] DNS=127.0.0.1#dns.local.test DNSOverTLS=yes` in `/etc/systemd/resolved.conf`, then `systemctl restart systemd-resolved` |
| **Router** | If your router supports DoH (OpenWRT, OPNsense), point upstream at `https://dns.local.test:8543/dns-query`. Otherwise, run XGG on a Pi inside the LAN and set the Pi as DHCP DNS. |

### Verify

Open a phishing URL from PhishTank's latest list. The browser should land on
the XGenGuardian block interstitial.

---

## Path B — Browser extension

Layer on top of Path A. Extension adds **URL-path visibility, tracker
blocking, and in-page evidence**. Doesn't require a CA install, doesn't see
your HTTPS content (only the URL it asks the API about).

### Chrome / Edge

1. `chrome://extensions` → enable Developer mode → Load unpacked
2. Select `apps/extension/`
3. Click the puzzle-piece icon → pin XGenGuardian
4. Options → set API endpoint to `http://localhost:8080`

### Firefox

Use `about:debugging#/runtime/this-firefox` → Load Temporary Add-on → pick
`apps/extension/manifest.json`. Permanent install requires signing for the
public store.

### What you'll see

- A small badge appears on the toolbar icon: green/yellow/red per verdict.
- Click the icon to see the current tab's verdict + protection toggle.
- On BLOCK, you land on a full-screen interstitial with screenshot + reason +
  evidence link.

---

## Path C — Windows tray client

A 60 MB single-EXE app that does Path A's DNS configuration for you and
gives you a tray menu + WebView2 activity window. No CA install needed for
the production endpoint (CA is publicly trusted); for internal testing the
dev CA still needs trusting.

### Build

On the test Windows machine:

```powershell
cd apps\windows-client
.\build.ps1
```

Output: `bin\Release\net8.0-windows\win-x64\publish\XGenGuardian.exe`

### Run

```powershell
$env:XGG_DOH = "https://dns.local.test:8543/dns-query"
$env:XGG_RESOLVER_IP = "127.0.0.1"
$env:XGG_VERDICT_API = "http://YOUR-BACKEND-HOST:8080"
$env:XGG_PORTAL_URL = "http://YOUR-BACKEND-HOST:3000"
.\bin\Release\net8.0-windows\win-x64\publish\XGenGuardian.exe
```

UAC prompts for DNS configuration on first run. Tray menu:

- **Open live activity** — shows the /live feed in an embedded window
- **Check a URL…** — opens the public Transparency Portal
- **Configure DNS** / **Restore DNS** — manual toggle if needed
- **Quit** — exits and restores DNS automatically

For the dev CA, import `tls\ca.pem` into Windows Trusted Root via
`certmgr.msc` → Certificates - Local Computer → Trusted Root → Import.

---

## Testing workflow

Each session: about 30 minutes for a full pass.

### 1. Pre-flight

```bash
make doctor
```

All green? Continue. Any red? Fix as instructed and re-run.

### 2. Start the live feed

Open <http://localhost:3000/live> in a tab outside your test browser, on a
second monitor if possible. Keep it visible.

### 3. Eight scenarios

Visit each set of URLs in your test browser. Expected verdicts in parens.

| # | What | Expected |
|---|---|---|
| 1 | google.com, wikipedia.org, github.com | CLEAN, cache hit <10ms |
| 2 | 10 fresh PhishTank URLs (<https://data.phishtank.com/data/online-valid.json>) | BLOCK from blocklist within 50ms |
| 3 | Operator-built lookalikes vs seeded brands: `paypa1.com`, `g00gle-secure.tk`, `pаypal.com` (Cyrillic) | BLOCK from identity-mismatch rule |
| 4 | URLhaus recent malware links | BLOCK on URL; if it slips, downloads scanned in sandbox |
| 5 | Tech-support / fake-update lures / ClickFix paste-to-run | WARN at minimum |
| 6 | Compromised legit sites (Sucuri reports) | WARN; some misses are expected in Phase 1 |
| 7 | Tracker-heavy news sites | Page loads, extension blocks 10–50 tracker requests |
| 8 | False-positive sentinel: personal blog, regional bank, small SaaS, .gov, indie game | All CLEAN; any BLOCK is an FP |

### 4. Bulk-scan your existing data

To run a list of URLs through the system in one shot:

```bash
# plain text — one URL per line
make bulk-scan FILE=urls.txt

# or with options
python tools/bulk-scan/scan.py --concurrency 16 --out report.json urls.txt
```

Accepts plain text, JSON arrays, or Chrome history JSON exports.

### 5. File reports

Whenever a verdict surprises you:

- **Missed phishing** — open `docs/bugs/BUGS.md`, add an entry tagged
  `false-negative`. Include the URL, what should have caught it, and a slice
  of the session log:
  ```bash
  jq 'select(.url=="https://that-bad-url.tk")' data/sessions/$(date -u +%F).jsonl
  ```
- **False positive** — same as above, tagged `false-positive`. Then run:
  ```bash
  docker compose exec -T redis redis-cli SADD blocklist:allowlist that-clean-domain.com
  ```

### 6. Reset between sessions

```bash
# wipe Redis caches but keep brand registry and verdicts in Postgres
docker compose exec -T redis redis-cli FLUSHDB

# nuke everything and start fresh
docker compose down -v && make bringup && make dev-up
```

---

## Verdict colors — what they mean

| Color | Verdict | What you see |
|---|---|---|
| 🟢 Green | CLEAN | Page loads normally. Cache TTL 24h. |
| 🟡 Yellow | WARN | Page loads with a yellow banner (if extension installed). Cache TTL 6h. |
| 🔴 Red | BLOCK | Sinkhole → block interstitial with screenshot + reason. Cache TTL 30d. |
| ⚪ Gray | ANALYZING | First-time unknown URL. Sinkhole → "Analyzing this site for your safety…" page. Auto-redirects within ~5s. Cache TTL 30s. |

---

## Cheat sheet

```bash
make bringup           # one-time backend setup
make dev-up            # start every backend service
make dev-down          # stop everything
make doctor            # diagnose what's broken
make healthcheck       # JSON status (use in scripts)
make seed-brands       # populate brand visual fingerprints
make bulk-scan FILE=…  # scan a list of URLs
make smoke             # end-to-end test
make eval              # PhishTank gate check (precision/recall)
make fetch-blocklists  # refresh threat-intel feeds
make dev-certs         # regenerate dev TLS certs
make clean             # remove build artifacts
```

Key URLs:

- <http://localhost:3000>          — Transparency Portal landing
- <http://localhost:3000/live>     — Real-time activity feed
- <http://localhost:8080/healthz>  — Verdict API health
- <http://localhost:8080/v1/check> — POST {url} → verdict (curl-able)
- <https://dns.local.test:8543/dns-query> — DoH endpoint
- <http://localhost:9001>          — MinIO console (evidence bucket)

Key files:

- `data/sessions/YYYY-MM-DD.jsonl` — every verdict, one per line
- `tls/ca.pem`                     — the dev CA to trust
- `docs/bugs/BUGS.md`              — where you log surprises
- `tools/eval/corpus/*.txt`        — your regression corpus

---

## Troubleshooting

| Symptom | First thing to try |
|---|---|
| `make bringup` fails on Docker | Start Docker Desktop / `systemctl start docker` |
| Firefox shows `MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT` | Trust `tls/ca.pem` (see Path A step 1) |
| Every URL returns CLEAN with `pipeline_stub` signal | Not all backends running. `make doctor` will tell you which |
| `/live` shows "disconnected" | verdict-api not running OR CORS issue. Check `:8080/healthz` |
| `make seed-brands` hangs on PayPal/Chase | They CAPTCHA-wall headless browsers. Add a manual screenshot — see `tools/brand-seeder/MANUAL.md` |
| Sandbox-render times out on dangerous URLs | Expected for some malware sites; budget is 5s |
| Windows tray client says "backend unreachable" | Set `XGG_VERDICT_API` to your backend host:port |

Full operator runbook: [`docs/runbooks/internal-testing.md`](runbooks/internal-testing.md).

---

## What's NOT in this build

Per your decision, **no Stripe / no billing / no SaaS account flows**. The
free, single-user, internal-testing path is fully functional. Multi-tenant
admin console, SSO, and pricing flows are Phase-3 work and remain unbuilt.

Also intentionally absent for now: mobile native apps (DoH config profile
works), Linux endpoint binary (DNS-layer protection works), and macOS endpoint
binary. Add as needed.
