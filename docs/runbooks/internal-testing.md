# Internal Testing

**TL;DR:** `make bringup` → trust dev CA → point Firefox at our DoH → open `/live` → start clicking malicious URLs and watch what happens.

This runbook walks one operator through running the whole stack locally and exercising it with real-world threats. Don't do this on your daily-driver machine — use a VM, a fresh user account, or at minimum a fresh browser profile.

## 0. Safety

- Use a **dedicated browser profile** (Firefox is recommended; better DoH controls and a separate CA store).
- Disable autofill for passwords / cards in that profile.
- Don't be logged into anything personal.
- Use a VPN or VM if you're worried about your real IP appearing in any payload.
- Never test from production credentials or a corporate machine without explicit IT sign-off.
- Some lures will try to deliver downloads — sandbox-render will fetch and hash them; you don't need to.

## 1. One-time setup (~5 min)

```bash
# 1. clone
git clone https://github.com/xgenguardian/xgenguardian
cd xgenguardian

# 2. bring everything up
make bringup
```

`bringup.sh` checks dependencies, generates dev TLS certs, brings up Postgres + Redis + MinIO + CoreDNS via Docker, runs migrations, and fetches the blocklists.

## 2. Trust the dev CA

The DoH endpoint serves HTTPS with a cert signed by a local CA. Trust the CA so your browser doesn't refuse to talk to it:

| OS | Command |
|---|---|
| **Firefox** (any OS) | Settings → Privacy & Security → View Certificates → Authorities → Import → `tls/ca.pem` → check "trust this CA for websites" |
| **macOS** | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain tls/ca.pem` |
| **Linux (Debian/Ubuntu)** | `sudo cp tls/ca.pem /usr/local/share/ca-certificates/xgg-dev-ca.crt && sudo update-ca-certificates` |
| **Windows** | `certutil -addstore -f "ROOT" tls\ca.pem` (as admin) |

Optionally add a friendly hostname:

```bash
echo '127.0.0.1   dns.local.test' | sudo tee -a /etc/hosts
```

## 3. Start the services

`bringup.sh` only started infrastructure. Start each service in its own terminal (or use `make dev-backend` to background them all):

```bash
# terminal 1
cd services/visual-match && uvicorn app.main:app --port 8003

# terminal 2
cd services/sandbox-render && uvicorn app.main:app --port 8002

# terminal 3
cd services/verdict-api && go run ./cmd/verdict-api

# terminal 4
cd services/portal-api && go run ./cmd/portal-api

# terminal 5  -- the DoH server
cd services/resolver && go run ./cmd/resolver

# terminal 6  -- pre-victim scanner
cd services/ct-monitor && go run ./cmd/ct-monitor
```

## 4. Seed the brand registry

```bash
make seed-brands
```

This populates 50 brands' visual fingerprints. Allow ~15 minutes the first time — each brand renders 1–2 pages in Playwright and computes a CLIP embedding.

## 5. Start the portal + open Live

```bash
cd apps/portal
npm install
npm run dev
```

Open <http://localhost:3000/live> in a normal browser tab. Keep it visible during testing.

## 6. Configure Firefox for our DoH

Settings → Network Settings → Enable DNS over HTTPS → Custom →
`https://dns.local.test:8543/dns-query`

Or via `about:config`:
- `network.trr.mode = 3` (strict DoH)
- `network.trr.uri = https://dns.local.test:8543/dns-query`

Confirm with <https://1.1.1.1/help> — "Using DNS over HTTPS" should say Yes.

## 7. Test

Visit URLs from each of the 8 scenarios in [`docs/phases/internal-testing.md`](../phases/internal-testing.md). Watch `/live` for each verdict to appear in <2 seconds.

### Quick-start phishing samples
- Open <https://data.phishtank.com/data/online-valid.json> in another browser (not the DoH-protected one) and copy 5 URLs into the protected browser.
- Open <https://urlhaus.abuse.ch/browse/> and try recent malware URLs.
- Construct your own homoglyphs against the seeded brands.

## 8. Reading the activity feed

| Badge | What you should see |
|---|---|
| **CLEAN** (green)  | Page loaded normally; verdict in <250ms |
| **WARN** (yellow)  | Page loaded but yellow banner from extension; verdict came back medium-risk |
| **BLOCK** (red)    | Browser landed on the block interstitial; never saw the malicious page |
| **ANALYZING** (gray) | First-time unknown URL; resolver returned a sinkhole pointing to the holding page; will auto-redirect within ~5s |

Click any row in `/live` to open the full evidence report at `/report/<evidence_id>`.

## 9. Filing detection-gap reports

When a verdict is wrong, file it immediately so it lands in the test corpus.

**Missed phishing (false negative):**
1. Click the URL in `/live` to open its evidence page.
2. Click "Report missed phishing".
3. Add the URL to `tools/eval/corpus/missed-phish.txt` (one per line) with a brief note.
4. Open a `docs/bugs/BUGS.md` entry tagged `internal-test` / `false-negative`.

**Clean site blocked (false positive):**
1. Click the BLOCK row.
2. Click "I think this is wrong".
3. Add the URL to `tools/eval/corpus/should-be-clean.txt`.
4. Open a `docs/bugs/BUGS.md` entry tagged `internal-test` / `false-positive`.
5. Optionally allowlist the domain immediately:
   ```
   docker compose exec -T redis redis-cli SADD blocklist:allowlist <domain>
   ```

## 10. Session JSONL log

If you set `SESSION_LOG_DIR=$PWD/data/sessions` in verdict-api's env (the
`make dev-up` path does this automatically via `bringup.sh` creating the dir
and the service reading the env var), every verdict is appended to
`data/sessions/<UTC-date>.jsonl`. One JSON object per line.

When filing a BUGS.md report:

```bash
# attach the relevant slice
jq 'select(.verdict == "BLOCK" and .visual_top_brand == "paypal")' \
  data/sessions/2026-05-14.jsonl > my-bug.jsonl
```

Includes timestamp, URL, domain, verdict, confidence, visual brand match,
all signals, and evidence_id. No screenshots — those stay in MinIO.

## 11. Resetting between sessions

```bash
# wipe Redis caches but keep Postgres data
docker compose exec -T redis redis-cli FLUSHDB

# wipe Postgres state entirely (forgets every verdict ever seen)
docker compose down -v
make bringup
```

## 12. Common issues

| Symptom | Fix |
|---|---|
| Firefox shows `MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT` on DoH | CA not trusted yet; see step 2 |
| Browser hangs on first navigation | resolver crashed or verdict-api unreachable; check service logs |
| `/live` shows "disconnected" | verdict-api isn't running or CORS blocked; check `:8080/healthz` |
| Every URL returns CLEAN with `pipeline_stub` signal | verdict-api gateway is up but pipeline isn't wired; verify all 5 backend services running |
| Sandbox-render times out on dangerous URLs | expected — many malware URLs are slow. Default budget is 5s; that's intentional |
| `/v1/check` returns 504 | check sandbox-render health; Playwright workers may need a restart |
| Live feed never updates | Redis pub/sub down; `docker compose restart redis` |

## 13. Success criteria

You're done with a session when:

- [ ] You browsed for at least 30 minutes through varied content.
- [ ] Each of the 8 scenarios in `internal-testing.md` was exercised.
- [ ] No service crashed.
- [ ] Live feed kept up (no >5s gaps between visit and verdict).
- [ ] Every false negative is in `tools/eval/corpus/missed-phish.txt` with a `BUGS.md` entry.
- [ ] Every false positive is in `tools/eval/corpus/should-be-clean.txt` with a `BUGS.md` entry.

Three clean sessions in a row → the system is ready for the public POC launch.
