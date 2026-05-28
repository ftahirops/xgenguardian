# DNS Test — How to Provide Domains and Read Results

## What to give me

A plain list of domains or URLs. Any of these formats work:

- One per line in a text file
- Comma-separated
- Pasted in chat as a code block

Examples:

```
paypa1-secure-login.com
microsoft-account-verify.tk
g00gle-drive-share.xyz
update.your-system.click
fake-irs-refund.zip
```

You can mix:
- Live phishing (PhishTank / OpenPhish entries)
- URLhaus malware-hosting links
- Clickbait / scam pages
- Tech-support scams
- Sites you suspect (anything you've been emailed)
- A handful of known-safe domains as control (`google.com`, your bank's real domain) — useful to confirm we're not over-blocking

If you're not sure where to pull live ones from, here's a fresh-feed shortcut:

```bash
# Latest verified PhishTank URLs (sample 20)
curl -s https://data.phishtank.com/data/online-valid.json | jq -r '.[0:20] | .[].url'

# Latest URLhaus entries (malware hosts)
curl -s 'https://urlhaus.abuse.ch/downloads/csv_recent/' \
  | awk -F'","' 'NR>9 && $1!~/^#/ {print $3}' | head -20
```

## How I'll run them

If your backend is up (`make dev-up`), I can:

### Option 1 — bulk-scan in one shot

```bash
# from anywhere with curl / Python
python tools/bulk-scan/scan.py --concurrency 8 --out report.json urls.txt
```

Prints a colored verdict per row + summary table + writes full JSON. Each
URL is checked through the entire pipeline (Tier-1 lexical/cert/homoglyph
→ Tier-2 sandbox render + visual brand match → fusion).

### Option 2 — DNS-level test (simulates a real user)

```bash
# Force the resolver to actually answer queries for each domain
for d in $(cat domains.txt); do
  dig @127.0.0.1 -p 5300 +short "$d" || true
done
```

Or via DoH directly:

```bash
for d in $(cat domains.txt); do
  curl -fksS -H 'accept: application/dns-message' \
    "https://dns.local.test:8543/dns-query?dns=$(echo -n "$d" | base64 -w0)" \
    >/dev/null && echo "✓ $d"
done
```

This exercises the **resolver's actual code path**: blocklist Bloom check,
Redis cache, fall through to verdict-api, and write a row into the
`dns_queries` table.

### Option 3 — Browser-driven (the operator's real-world test)

1. Configure your browser/OS DoH at `https://dns.local.test:8543/dns-query`
2. Trust the dev CA (`tls/ca.pem`)
3. Open each URL manually in a fresh profile
4. Watch the verdict on the block interstitial (if blocked) or in the
   admin dashboard

## Where to see the results

### Admin dashboard

```bash
ADMIN_PASSWORD=changeme cd services/portal-api && go run ./cmd/portal-api
# in another tab
cd apps/portal && PORTAL_API_URL=http://localhost:8081 npm run dev
```

Then visit:

| URL | What you see |
|---|---|
| `http://localhost:3000/admin/login`    | Password gate (one password, no accounts) |
| `http://localhost:3000/admin`          | 24-hour overview, sparkline, top blocked |
| `http://localhost:3000/admin/queries`  | Every DNS query the resolver answered, with verdict, cache hit, sinkhole flag, latency. Filter by domain / verdict. |
| `http://localhost:3000/admin/verdicts` | URL-level analysis results with screenshot link |
| `http://localhost:3000/live`           | Real-time SSE feed |

### Session JSONL log

```bash
# everything that came through verdict-api today
cat data/sessions/$(date -u +%F).jsonl | jq .

# only blocks
jq 'select(.verdict=="BLOCK")' data/sessions/$(date -u +%F).jsonl

# only impersonating a specific brand
jq 'select(.visual_top_brand=="paypal")' data/sessions/$(date -u +%F).jsonl
```

## What I expect to see per category

| Category | Expected verdict | Detection layer |
|---|---|---|
| Known phishing on PhishTank | `BLOCK` <50ms | blocklist Bloom |
| Recently submitted phish (<24h, not on list yet) | `BLOCK` 3–6s | sandbox + visual brand match |
| Homoglyph / typo lookalike vs seeded brand | `BLOCK` 3–6s | tier-1 homoglyph + visual fusion |
| Newly registered domain (<24h) | `BLOCK` <300ms | NRD filter |
| Malware-hosting URL | `BLOCK` from URLhaus blocklist; or `WARN` + risky-download finding from sandbox |
| Clickbait / scam without brand impersonation | `WARN` from lexical/anti-analysis heuristics; may pass — log it |
| Known-good big site | `CLEAN` <10ms | Tranco allowlist |
| Unseeded brand impersonation | `WARN` or `CLEAN` (limitation — extend brand registry) |

## What to do if a verdict is wrong

### False negative (clean verdict on a phishing URL)

1. Click the URL row in `/admin/queries` → opens the verdict's evidence page.
2. If there's no evidence (resolver short-circuited), force a re-scan:
   ```bash
   curl -X POST http://localhost:8080/v1/rescan \
     -H 'content-type: application/json' \
     -d '{"url":"https://that-url.tk/"}'
   ```
3. Open `docs/bugs/BUGS.md`, paste the URL + observed verdict + expected verdict.
4. Add to `tools/eval/corpus/missed-phish.txt`.

### False positive (block on a clean site)

```bash
# immediate unblock for this session
docker compose exec -T redis redis-cli DEL "verdict:that-clean-domain.com"
docker compose exec -T redis redis-cli SADD blocklist:allowlist that-clean-domain.com

# permanent fix
echo "that-clean-domain.com" >> tools/eval/corpus/should-be-clean.txt
```

Then open a `docs/bugs/BUGS.md` entry tagged `false-positive` + attach the
JSONL slice for that domain.

## Quick-start

```bash
# 1. backend running
make bringup && make dev-up && make seed-brands

# 2. set admin password
export ADMIN_PASSWORD="$(openssl rand -base64 18)"
echo "admin password: $ADMIN_PASSWORD"

# 3. restart portal-api with the password (and portal pointing at it)
# in services/verdict-api terminal, kill it and start with env above
# in apps/portal terminal, same

# 4. give me a list of domains. paste here as a code block.

# 5. run them
python tools/bulk-scan/scan.py --out report.json domains.txt

# 6. open the admin dashboard
open http://localhost:3000/admin/login
```
