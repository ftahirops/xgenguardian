# XGenGuardian — Unified Plan (Final)

Single source of truth that supersedes the R&D specs at `/home/xgendns-phish-scam-protector/` and slots them into the current code. Where the spec and code disagreed, this document picks one answer.

Date: 2026-05-26
Status: authoritative — open issues in `docs/issues/ISSUES.md` if you disagree before implementing.

---

## 1. Product shape (locked)

XGenGuardian is **protective DNS plus pre-navigation verdicting plus selective deep scan plus isolation for the unknown.** Four verdict states, one trust registry, three enforcement surfaces.

**Verdicts** (replaces the current `CLEAN | WARN | BLOCK | ANALYZING`):

| Verdict | Meaning | Enforcement |
|---|---|---|
| `ALLOW` | Known-good or fresh-cached safe | Resolve real IP; no interstitial |
| `WARN` | Suspicious but low confidence | Interstitial with "proceed at your own risk" |
| `BLOCK` | High-confidence malicious | Sinkhole IP / `blocked.html` |
| `ISOLATE` | Risky but not provably bad, or first-seen sensitive class | Open in remote sandbox stream; never on endpoint |

`ANALYZING` is **internal only** — a transient state while a deep scan runs. Never returned to the client; the resolver/extension holds on the interstitial until it resolves to one of the four above (with a 2s hard cap, then falls through to `ISOLATE` for unknown).

**Trust grades** (spec wins — adopt verbatim): `A+, A, B, C, D, F, F+`.
- `A+/A` map to `ALLOW`
- `B/C` map to `ALLOW` or `WARN` based on page class
- `D` maps to `WARN` or `ISOLATE`
- `F` maps to `BLOCK`
- `F+` maps to `BLOCK` with extended cache TTL

---

## 2. Enforcement surfaces (locked)

Three independent entry points; each can produce a verdict request:

1. **Protective DNS resolver** (`services/resolver`) — `:53` UDP/TCP plus DoH. Cheapest, broadest. Cannot see paths.
2. **Browser extension** (`apps/extension`) — pre-navigation hook, sees full URL, sees popups/new tabs. Ship Chrome MV3 first, Firefox second (Firefox blocking is stronger), Edge from the Chrome build.
3. **Endpoint agent / SWG** — Phase 3, out of scope here.

The verdict API is the single decision point all three call.

---

## 3. Popup and new-tab handling (the headline rule)

> **Every popup, every `window.open`, every new tab, every middle-click — is treated as a brand-new top-level navigation and gets its own verdict request. No exceptions.**

This is the differentiator vs. NextDNS/Quad9, and it must be implemented carefully because the rules differ by the *opener's* trust state.

### 3.1 Decision matrix

Let `opener` = the page that triggered the popup. Let `target` = the URL the popup wants to open.

| Opener verdict | Target known? | Action |
|---|---|---|
| `BLOCK` / `F` / `F+` | any | **Do not open the popup at all.** Opener is already sinkholed/blocked; if the user somehow got a tab, treat any spawned popup as `BLOCK` immediately, no scan, no interstitial. Log the popup attempt as evidence on the opener's case. |
| `WARN` / `D` | known `ALLOW` | Open normally. (A bad page linking to a good page is fine.) |
| `WARN` / `D` | known `BLOCK` | Block hard. |
| `WARN` / `D` | unknown | **Force `ISOLATE`** — open the popup in remote sandbox stream, not on endpoint. Don't even offer ALLOW. |
| `ALLOW` / `A`/`A+`/`B`/`C` | known `ALLOW` (fresh, in-TTL) | Open normally. Fast path. |
| `ALLOW` / `A`/`A+`/`B`/`C` | known `BLOCK` | Block hard. |
| `ALLOW` / `A`/`A+`/`B`/`C` | **unknown** | **Always intercept. Hold on `holding.html`, fire a verdict request, decide.** This is the case the user is asking about — popups from a trusted page going to a never-seen URL. We **always** scan first. |

### 3.2 Sensitive-class override

If the popup target URL matches a sensitive class — `login`, `verify`, `mfa`, `update`, `secure`, `payment`, `checkout`, `oauth`, `consent`, `download`, `recover` in path or domain — the cached "fresh ALLOW" path **does not apply**; treat it as if unknown and revalidate. Reason: trusted hosts get compromised, and login/payment paths are the high-value targets.

### 3.3 Extension implementation

In `apps/extension/src/background.js`:

- Hook `chrome.tabs.onCreated` and `chrome.webNavigation.onCreatedNavigationTarget`.
- For every new tab where `openerTabId` is set:
  1. Immediately swap the new tab's URL to `holding.html?target=<encoded>&opener=<id>`.
  2. Look up the opener's last verdict from the extension's local cache.
  3. POST `/verdict` with `{url: target, opener_verdict, opener_url}`.
  4. Apply the decision matrix above. Replace the holding tab with `blocked.html`, `warn.html`, `isolate.html`, or release to the real URL.
- For middle-click / Ctrl-click new tabs, same path — `webNavigation.onCreatedNavigationTarget` fires on these.
- For `window.open` from script, MV3's declarativeNetRequest can't block synchronously, so the swap-to-interstitial pattern is mandatory. Firefox build can use `webRequest.onBeforeRequest` for true blocking.
- Default-deny rule: if the extension cannot reach the verdict API within 1.5s, the popup target stays on `holding.html` with a "still checking" UI and a manual "open anyway" override that requires explicit click (not auto-progress).

### 3.4 Backend implementation

Add to `services/verdict-api`:
- New request field `opener_url` (optional). When present, the API:
  - Looks up the opener's current grade.
  - If opener is `F` or `F+`, returns `BLOCK` for the target with reason code `BLOCKED_OPENER_LINEAGE`, even if the target itself is unknown.
  - If opener is `D`/`WARN` and target is unknown, forces verdict to `ISOLATE` (not `WARN`) with reason `UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER`.
- Persist opener→target edges to a new table `popup_edges (opener_url_hash, target_url_hash, ts, action)` — feeds graph-based detection later (popup storm clusters, redirect chains).

---

## 4. Trust registry (the missing layer)

The schema in `migrations/0001_init.sql` is most of the way there. Add what's missing.

### 4.1 Schema changes

```sql
ALTER TABLE urls ADD COLUMN grade        TEXT;          -- A+|A|B|C|D|F|F+
ALTER TABLE urls ADD COLUMN page_class   TEXT;          -- login|payment|oauth|admin|download|generic
ALTER TABLE urls ADD COLUMN ttl_seconds  INTEGER;
ALTER TABLE urls ADD COLUMN next_rescan_at TIMESTAMPTZ;
ALTER TABLE urls ADD COLUMN page_fingerprint        TEXT; -- title+favicon hash
ALTER TABLE urls ADD COLUMN redirect_fingerprint    TEXT;
ALTER TABLE urls ADD COLUMN form_fingerprint        TEXT;
ALTER TABLE urls ADD COLUMN script_origin_fingerprint TEXT;
CREATE INDEX idx_urls_next_rescan ON urls (next_rescan_at) WHERE next_rescan_at IS NOT NULL;
CREATE INDEX idx_urls_grade ON urls (grade);

CREATE TABLE popup_edges (
  id BIGSERIAL PRIMARY KEY,
  opener_url_hash BYTEA NOT NULL,
  target_url_hash BYTEA NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  action TEXT NOT NULL  -- 'allowed' | 'blocked' | 'isolated' | 'warned'
);
CREATE INDEX idx_popup_edges_opener ON popup_edges (opener_url_hash);
```

### 4.2 TTL matrix (locked, from spec §12.2)

| Grade | Page TTL | Notes |
|---|---|---|
| `A+` | 30–45 d | Lowest re-scan, never permanent |
| `A` | 30 d | |
| `B` | 24 h | |
| `C` | 6 h | |
| `D` | 30 min | |
| `F` | 12 h | Block cache; re-check on next request |
| `F+` | 7–30 d | Confirmed; takedown-churn dependent |

**Sensitive-page-class TTL caps** (hard, overrides grade):
- `login` / `payment` / `oauth` / `admin` → **7 days max**
- `download` → **6 hours max**

### 4.3 Drift-triggered early revalidation

Re-scan immediately (before TTL expiry) when *any* of these change vs. the stored fingerprints:

- final landing URL
- redirect-chain hash
- certificate SHA256 (already in `domains.current_cert_sha256`)
- title+favicon hash
- form action target
- script-origin set
- hosting ASN
- a brand claim appears where none existed
- the page starts offering downloads where it didn't before
- new negative TI feed entry for the domain

Wire this in a new `services/scheduler` service (see §6).

### 4.4 Paranoid Mode (a.k.a. "Executive Mode")

A per-tenant / per-user strictness toggle. **Not a new detector** — a different grade→verdict mapping. Lands in Phase 2.

**Mapping comparison:**

| Grade | Normal | **Paranoid** |
|---|---|---|
| `A+` / `A` | ALLOW | ALLOW |
| `B` | ALLOW | **ISOLATE** |
| `C` | WARN | **ISOLATE** |
| `D` | ISOLATE | ISOLATE |
| `F` / `F+` | BLOCK | BLOCK |
| Unknown (first-seen) | WARN or ISOLATE per fusion | **ISOLATE always** |

Paranoid mode also tightens TTL decay: `A+` → `A` after 30 d (vs. 45 d); `A` → `B` after 14 d (vs. 30 d). Keeps trust fresh.

**Protection rate impact** (see §19.6 for full table):
- Phase 2 weighted overall: 84% → **91%** (+7 pp).
- Concentrated on attack classes where the gap was "unknown / fresh page slipped through": cloaking, drive-by containment, HTML smuggling, time-bomb, long-tail-brand zero-day phishing.
- **Zero improvement** on attacks that target already-A-graded pages (Magecart on real checkout, OAuth phishing on real provider). Paranoid users must understand this.

**Cost:** day-1 friction ~30–50% of distinct domains hit an interstitial; settles to ~5–8% in steady state with mature telemetry. Above ~8% friction users disable products; do not ship as consumer default.

**Mandatory design rules:**

1. **Opt-in only**, default off. Surface as "Executive Mode" in UI; "paranoid" only in technical docs.
2. **24-hour warmup** when first enabled — treat B as ALLOW for 24 h to populate personal cache, then switch to ISOLATE. Otherwise users uninstall in week 1.
3. **All manual overrides expire in 7 days.** Renewal requires re-justification. Without this, overrides accumulate and the mode becomes performative.
4. **Per-user, not per-device.** Shared devices (households, kiosks) need extension-side enforcement keyed to profile, not DNS-side sinkholing — DNS cannot tell users apart.
5. **Extension-side enforcement only.** DNS continues to return real IPs; the strict mapping is applied by the extension before navigation. Allows mixed-mode households without resolver awareness.
6. **Honest disclosure** in the warmup banner: "Paranoid mode reduces unknown-site risk by ~7 percentage points. It does NOT make trusted sites safer if they're compromised."

**Reason code:** `BLOCKED_BY_STRICTNESS_POLICY` (distinguishes paranoid-mode blocks from detection-driven blocks in analytics — important so we don't mistake friction for true positives).

**Schema additions:**

```sql
ALTER TABLE tenants ADD COLUMN paranoid_mode BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users   ADD COLUMN paranoid_mode BOOLEAN;  -- nullable; null = inherit tenant
ALTER TABLE overrides ADD COLUMN expires_at TIMESTAMPTZ NOT NULL;
```

**Who it's for:** executives, board members, public figures, journalists, sysadmins, IR analysts during incidents, managed family devices with parental allowlist. **Not for** developers, sales/marketing, general consumers as default.

### 4.5 Three revalidation tiers

Don't always run the full sandbox.

| Tier | Cost | What it does | When |
|---|---|---|---|
| `light` | ms | URL/DNS/cert/header/fingerprint diff against stored values | TTL-expiry revalidation of `A`/`A+` |
| `medium` | ~200 ms | HTML fetch, DOM-lite parse, form/script/iframe re-extract | Drift detected; or `B`/`C` revalidation |
| `deep` | 2–10 s | Full Playwright sandbox + behavioral + downloads | First-seen suspicious; opener `WARN`+unknown target; ISOLATE candidates |

---

## 5. Detection — what to keep, what to add

### 5.1 Keep (these are the current crown jewels)

- **Identity-mismatch fusion rule** in `services/verdict-api/internal/fusion/fusion.go:104`. This is the universal phishing tell and stays exactly as specified.
- **CLIP ViT-B/32 visual match** via pgvector ivfflat. Keep.
- **CT-monitor → prescan_queue** for proactive scanning of newly-issued certs with brand keywords. Keep.
- **Shared-hosting eTLD list** in `resolver/cmd/resolver/main.go:70`. Keep, expand quarterly.
- **Brand registry hydrator** with 5-min refresh. Keep.

### 5.2 Add — behavioral abuse signals (sandbox-render)

In `services/sandbox-render/app/main.py`, instrument Playwright to collect during the render:

- `window.open` invocation count, distinct targets
- `alert` / `confirm` / `prompt` call counts (sandbox auto-dismisses)
- fullscreen requests
- `beforeunload` handler registration
- Notification permission prompts
- Clipboard write attempts
- Service worker registrations
- Auto-download triggers (Content-Disposition without user click)
- `document.title` mutation rate (scam tab-flicker)
- right-click disable / devtools detection

Emit a `behavior` block in the render response, scored by `fusion.go`. Reason codes:

- `POPUP_STORM_DETECTED` (≥3 `window.open` calls without user gesture)
- `ALERT_LOOP_DETECTED` (≥2 modal calls)
- `FULLSCREEN_TRAP_DETECTED`
- `BEFOREUNLOAD_ABUSE`
- `CLIPBOARD_HIJACK_ATTEMPT`
- `AUTO_DOWNLOAD_TRIGGER`
- `FAKE_SUPPORT_SCAREWARE` (popup_storm + alert_loop + fullscreen on same page)

### 5.3 Add — RDAP for domain age

The fusion rule's age clause is dead code without this. New package `services/verdict-api/internal/rdap`:

- On first-see of a domain (resolver passes through), enqueue an RDAP lookup.
- Populate `domains.registrar`, `domains.registered_at`, `domains.expires_at`.
- Cache for 7 days. Re-fetch on `WARN`/`BLOCK` verdicts to capture takedown signal.

### 5.4 Add — reason-code taxonomy

Replace ad-hoc Signal names with an enum. New file `services/verdict-api/internal/reasons/reasons.go`:

```
KNOWN_PHISH_URL_MATCH
KNOWN_MALWARE_DOMAIN_MATCH
BRAND_CLAIM_DOMAIN_MISMATCH        // the universal rule
FAVICON_BRAND_MISMATCH
LOGIN_FORM_ON_UNAPPROVED_DOMAIN
FORM_POSTS_TO_UNRELATED_DOMAIN
SUSPICIOUS_REDIRECT_CHAIN
HOMOGLYPH_OF_PROTECTED_BRAND
DOMAIN_AGE_UNDER_THRESHOLD
CERT_DRIFT_ON_TRUSTED_PAGE
MALICIOUS_DOWNLOAD_TRIGGER
POPUP_STORM_DETECTED
ALERT_LOOP_DETECTED
FULLSCREEN_TRAP_DETECTED
FAKE_SUPPORT_SCAREWARE
TITLE_FAVICON_BRAND_IMPERSONATION
BLOCKED_OPENER_LINEAGE
UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER
EXTERNAL_FEED_HIT
```

Every block stores one or more codes in `evidence.signals.codes[]`. Portal renders them with human-readable templates.

### 5.5 Add — at least one external corroborator

`fusion.go` already accepts `GSBClean`, `VTPositives`, `BlocklistHit`. Pick one to wire first: **Google Web Risk** (commercial, JSON API, fits Phase-1 budget). Add `services/verdict-api/internal/feeds/webrisk.go`. Cache per-URL for 6h.

### 5.6 Add — download analysis pipeline

Promote `services/sandbox-render/app/downloads.py` to its own service `services/file-detonator`:

- Hash check vs. internal + commercial reputation
- Code-signing verification (Authenticode for PE, codesign for Mach-O, jarsigner for APK)
- Signer reputation lookup
- AV multi-engine (one engine in Phase 1, multi later)
- Optional cuckoo-style detonation for unknown executables (Phase 2)

Verdict: `ALLOW` / `WARN` / `BLOCK` / `ISOLATE` (same enum). Result attached to the page's evidence record.

---

## 6. New service: `services/scheduler`

The code today has no component that drives revalidation. Add one.

Responsibilities:

- Poll `urls WHERE next_rescan_at <= NOW()` and enqueue light/medium/deep scans based on grade.
- Compare incoming scan fingerprints against stored ones; if any drift trigger fires, force tier-up (light→medium, medium→deep).
- TTL expiry: demote stale grades, evict from `popup_edges` after 90 days, expire `evidence` past `retention_until`.
- Backpressure: per-domain rate limit (max 1 scan / 30 s / domain).
- Re-scan `F+` confirmed-bad domains at lower priority just often enough to detect takedown.

Implementation: Go service, talks to Postgres + Redis (queue) + sandbox-render + visual-match.

---

## 7. Extension — what to build (Phase 1 finish)

The current `apps/extension` is a stub. Finish it:

### 7.1 New pages (HTML + minimal JS)

- `holding.html` — "Checking site safety…" with a 200ms→2s progressive UX. Polls `/verdict` with `?url=&opener_url=`. Hard cap 2s, then escalates to `ISOLATE` automatically.
- `warn.html` — yellow interstitial, lists reason codes, "I understand the risk, continue" button (requires 2-click).
- `isolate.html` — opens the target in an embedded iframe pointing at the isolation gateway (see §8). No direct navigation to the real URL.
- `blocked.html` — exists today. Wire to render reason codes from `/verdict` evidence.

### 7.2 Background service worker logic

Three hooks, all routed through one verdict-resolver function:

1. `chrome.webNavigation.onBeforeNavigate` — top-level frame, fresh URL → swap to `holding.html`, request verdict.
2. `chrome.webNavigation.onCreatedNavigationTarget` — new tab/popup → §3.3 logic.
3. `chrome.tabs.onUpdated` — catch URL changes (SPA navigations) → light re-check.

Local LRU cache: 1000 entries, 5-min TTL for ALLOW, 1-h for BLOCK. Cache by full URL, not domain. Sensitive-class URLs bypass cache.

### 7.3 Firefox build

Same source, swap MV3 service worker for MV2 background script, use `webRequest.onBeforeRequest` with `blocking` for true synchronous gating. This is the strongest enforcement we can ship without a desktop agent.

---

## 8. Isolation (the new tier)

`ISOLATE` needs a real backend. Two acceptable Phase-1 implementations:

- **Option A (recommended, fastest):** Reuse `sandbox-render`'s Playwright pool. New endpoint `POST /isolate/session` returns a streaming URL backed by Chromium DevTools Protocol + a thin WebRTC/WebSocket bridge. User interacts with the remote browser; no JS executes locally. Downloads gated by file-detonator.
- **Option B:** Integrate a third-party RBI (Cloudflare Browser Isolation, Browserling). Lower build cost, higher per-session cost, vendor lock-in.

Decision: **Option A** for Phase 1. Cap concurrent isolation sessions at 10 per node; ISOLATE verdict gracefully degrades to `WARN` with a banner if cap exceeded.

---

## 9. Portal (transparency + admin)

Current `apps/portal` is read-only. Add:

- **Per-URL evidence page** (mostly exists) — render reason codes via the §5.4 enum.
- **Admin override workflow** — authenticated admin can mark a URL/domain `ALLOW` for the tenant (or globally for Phase 1 single-tenant). Stored in a new `overrides` table; verdict-api checks overrides before fusion.
- **Popup-edge graph view** — for any URL, show its inbound/outbound `popup_edges`. Catches storm patterns visually.
- **Re-scan trigger button** — admin can force `next_rescan_at = NOW()` on a row.

---

## 10. Multi-tenancy (do it now, not later)

Add `tenant_id UUID` to `domains`, `urls`, `evidence`, `scan_history`, `overrides`, `popup_edges`. Default tenant `00000000-0000-0000-0000-000000000000` for current single-tenant deploy. Every API call carries a tenant header (extracted from auth token in Phase 2). Retrofitting tenancy later is 10× the work.

---

## 11. Phase plan (locked)

Each phase interleaves in-house work with OSS integrations in the priority order from §18.7. Do not reorder — the order is calibrated for fastest detection-per-week-of-work.

### Phase 1 — Finish what's started + first OSS wave (next 6 weeks)

Status legend: ✅ landed · 🟡 partial (schema only / wiring pending) · ⬜ not started

In-house:
1. ✅ RDAP integration (§5.3) — `services/verdict-api/internal/rdap`, 10 tests green. Fixes the dead branch in fusion.
2. ✅ Reason-code taxonomy (§5.4) — `services/verdict-api/internal/reasons`, 4 tests, 40+ codes, policy-vs-detection split.
3. ✅ Trust-registry schema + TTL matrix — migrations `0003_phase1_foundations.sql` + `services/scheduler/internal/ttl` package, 4 tests.
4. ✅ Scheduler service (§6) — new module under `services/scheduler/` with poller, drift, ttl, expiry, feeds sub-packages. Dispatch currently logs; HTTP wire-up lands with verdict-api scan endpoint.
5. ✅ Extension finish (§7) — `holding.html` + `warn.html` + `isolate.html` + rewritten `background.js` with popup interception and full §3 decision matrix. Manifest v0.2.0.
6. 🟡 Multi-tenancy plumbing (§10) — schema landed in migration 0003 (tenants, users, tenant_id on domains/urls/evidence/scan_history, default tenant seeded). Server-side wiring (auth header → tenant resolution → row-level filter) **not yet done**.
7. ✅ DNS rebinding hard check — `services/resolver/internal/rebind`, 6 tests, wired into `upstreamAnswer`. Strips RFC1918/loopback/link-local/CGNAT/TEST-NET answers; rewrites to NXDOMAIN when every A/AAAA was filtered.

Plus (Executive Mode foundation, originally Phase 2 but landed early):
- ✅ Migration `0004_executive_mode.sql` — `paranoid_mode` flags, warmup tracker, override `expires_at`.
- ✅ `services/verdict-api/internal/strictness` package — full §4.4 mapping with sensitive-class passthrough, warmup, override bypass. 9 tests green.

OSS wave (interleaved with the above):
8. ✅ **YARA integration** in sandbox-render (§18.2) — `app/yara_scan.py` + 5 starter rule files in `rules/` (clickfix, html_smuggling, cryptojacker, magecart_skimmer, phishing_kit). Wired into pipeline: each match becomes a fusion signal with weight-by-severity; rule-declared `reason_code` overrides the generic `YARA_SIGNATURE_MATCH`. 11 Python tests green plus 5 Go tests for codes/weight mapping. Optional import — sandbox keeps working if libyara isn't installed.
9. ✅ **abuse.ch URLhaus + PhishTank + OpenPhish** daily ingest — `services/scheduler/internal/feeds`, 5 tests, plus migration `0005_feed_entries.sql`. Runs once daily via `feeds.Schedule()` in scheduler main.
10. ✅ **dnstwist nightly** — `tools/dnstwist-cron/run.py` reads canonical brands from Postgres, runs `dnstwist --registered`, inserts findings into `feed_entries` (source='dnstwist'). Wired into scheduler via `services/scheduler/internal/dnstwist.Schedule()` — first run 5 min after startup, then every 24 h. `make dnstwist-cron ARGS="--domain paypal.com --dry-run"` for manual runs.
11. ✅ **Google Web Risk** corroborator (§5.5) — `services/verdict-api/internal/feeds.WebRiskClient`. Caches 6 h per URL, returns `*bool` so fusion can distinguish "not consulted" from "clean". 5 tests green.
12. ✅ **playwright-stealth** + Playwright-native HAR recording inside sandbox-render — `record_har_path` per render uploads `network.har` to MinIO alongside screenshot/DOM, surfaces via `evidence.har_url` on the deep-evidence response. (mitmproxy itself stays on the Phase 2 roadmap — needed only for decrypted bodies of service-worker fetches.)
13. ✅ **ImageHash (pHash/dHash) under CLIP** in visual-match — `/match` always computes pHash + dHash on the input, returns them on the response, and consults `brand_screenshots.phash`/`dhash` (new in migration 0006) for a Hamming-distance pre-filter. Conservative threshold (≤ 8 of 64 bits).
14. ✅ **CertStream** primary + **crt.sh** fallback in ct-monitor — `crtshPollLoop` runs every 15 min, queries crt.sh for each brand keyword in round-robin batches (10 per cycle), filters to certs issued in the last 24 h, enqueues matches with `reason='crtsh_brand_match'` so analytics can split CertStream-driven enqueues from crt.sh-driven ones. Runs always; logs "fallback active" when CertStream is down.

Exit gate: `make eval` precision ≥ 0.95, recall ≥ 0.80, popup-interception integration test green, weighted overall (per §20) ≥ 69%.

### Phase 2 — Isolation + behavior + Firefox + file detonation (6–10 weeks)

Status legend: ✅ landed · 🟡 partial · ⬜ not started

In-house:
1. ✅ **Behavioral abuse detection** in sandbox-render — page-injected `window.__xgg_behavior` counters (popup_open, alert/confirm/prompt, fullscreen_req, beforeunload, clipboard_write, notification_perm, service_worker, auto_download). verdict-api maps to PopupStormDetected / AlertLoopDetected / FullscreenTrapDetected / BeforeUnloadAbuse / ClipboardHijackAttempt / AutoDownloadTrigger. Composite `FAKE_SUPPORT_SCAREWARE` fires when ≥3 abuse classes hit on one page. 7 Go tests green.
2. 🟡 **ISOLATE verdict + sandbox-render isolation endpoint** — Cloudflare gate forces ISOLATE for unknown captcha-walled URLs. Real RBI/streaming endpoint still Phase 2.5.
3. ⬜ **Firefox extension build (§7.3)** — MV2 with `webRequest.onBeforeRequest` blocking. Code structure ready; not yet ported.
4. ⬜ **Portal admin overrides + popup-edge graph (§9)** — overrides table exists + expiry; UI not yet built.
5. ⬜ **Multi-egress sandbox + cloaking diff (§16.1)** — biggest remaining gap. Needs 3 cloud-region Playwright instances + diff pipeline.
6. ✅ **Iframe verdict gating (§16.2)** — extension hooks `webNavigation.onCommitted` on sub-frames; when parent verdict ≥ WARN, sub-frame URL fires a verdict request so popup_edges + analytics see the parent→iframe lineage.
7. ⬜ **Interaction simulation (§16.3)** — Browsertrix behavior profiles. Tractable; deferred.
8. ✅ **OAuth `client_id` reputation registry (§16.4)** — migration 0007 + `internal/oauthreg` recognises Microsoft/Google/GitHub/Slack consent URLs, identifies sensitive scopes (Mail.ReadWrite, gmail.modify, Files.ReadWrite.All, etc.), forces BLOCK for unknown clients with sensitive scopes. 8 tests green. **Closes the §15 "OAuth consent phishing" WEAK row.**
9. ✅ **Tabnabbing re-check (§16.5)** — extension tracks `lastSeenByTab`; `onActivated` re-verdicts when the URL changed since last activation.
10. ⬜ **SRI / script-content hashing for supply-chain** — needs sandbox-side per-script SHA256 capture.
11. ⬜ **Blob/`URL.createObjectURL` instrumentation in Playwright via CDP** — partially covered by behavioural `auto_download` counter; full CDP integration deferred.
12. ⬜ **BITB visual classifier** — small CNN. Needs training data.
13. ✅ **DGA classifier** — `internal/tier1/dga.go` character-bigram log-likelihood + Shannon entropy + vowel-ratio composite. Conservative threshold (0.6) keeps legit short brands (google, paypal, chase) below cutoff. Emits `DGA_CLASSIFIER_HIT`. 5 tests green.
14. ✅ **postMessage observation in sandbox** — `__xgg_behavior.postmessage_cross_origin` counter + `post_message_count` on render response.
15. ✅ **Executive Mode (§4.4)** — strictness toggle, 24h warmup, 7-day override expiry, `BLOCKED_BY_STRICTNESS_POLICY` reason code. Implementation plan in §11.3.

OSS wave:
- ⬜ CAPEv2 file-detonator (§5.6) — separate service; Phase 2.5.
- ⬜ ClamAV + YARA layered file scanning — depends on file-detonator.
- ⬜ box-js / malware-jail post-analyzer — depends on file-detonator.
- ⬜ synchrony JS deobfuscator — same pipeline.
- ⬜ oletools / pdfid / WABT / DIE — file-type-specific triage.
- ✅ **Subjack weekly** — `internal/subjack` walks ct-monitor-discovered subdomains (60-day window), resolves CNAMEs, runs 11 curated provider fingerprints (GitHub Pages, Heroku, AWS S3, Shopify, Unbounce, Tumblr, surge.sh, Webflow, Vercel, Netlify), CNAME-pattern + body-marker dual gate keeps false positives near zero. Findings land in `feed_entries` with source='subjack', category='subdomain_takeover'.
- ⬜ Miner-pool domain feeds — small ingest, deferred.

OSS wave:
15. **CAPEv2** as the file-detonator (§5.6) — replaces in-house detonation entirely.
16. **ClamAV** + **YARA** layered file scanning before CAPE.
17. **box-js / malware-jail** post-analyzer for suspicious scripts.
18. **synchrony** JS deobfuscator pipeline.
19. **oletools / pdfid / WABT / DIE** for file-type-specific triage.
20. **Subjack** weekly subdomain-takeover scan against canonical brands.
21. **Miner-pool domain feeds** (NoCoin, MinerBlock) into deny cache for cryptojacking.

Exit gate: ISOLATE round-trip < 1.5s to first paint; 0 endpoint JS execution for any non-ALLOW page; behavioral signals contribute ≥ 5 pp to recall; weighted overall (§20) ≥ 84%.

### Phase 3 — Endpoint agent / SWG (later)

Out of scope for this document. Tracked in `docs/phases/phase-5-endpoint.md`. Closes the residual gaps: DoH-bypass malware, mobile/QR phishing, process-level drive-by detection.

Optional Phase-2.5 evaluation:
- **Drakvuf Sandbox** if eval shows evasion-aware malware bypassing CAPE.
- **Thug** low-interaction honeyclient as a cheap drive-by exploit-kit detector.
- **MISP** if we exceed 3 TI feeds and dedupe becomes painful.

### 11.3 Executive Mode — implementation plan

Feature spec in §4.4. Protection impact in §19.6. Implementation is small (≈400 LOC + schema) because the mode is a verdict *mapping*, not a new detector. Self-contained except for two upstream dependencies.

**Hard prerequisites** (Phase-1 work that must land first):
- `tenants` table exists (currently doesn't — multi-tenancy plumbing per §10).
- `users` table exists (Phase 1 multi-tenancy).
- `urls.grade` column exists (§4.1 schema migration).
- `overrides` table exists (§9 admin workflow).
- Extension finish (§7) — `holding.html`, `warn.html`, `isolate.html` so the strictness mapping has UI to route to.

**Task breakdown (ordered):**

| # | Task | Files | LOC | Depends on |
|---|---|---|---|---|
| 1 | Migration: Phase-1 foundations — tenants, users, overrides, urls.grade/page_class/fingerprints, popup_edges | `migrations/0003_phase1_foundations.sql` | ~120 | — |
| 2 | Migration: Executive Mode columns — paranoid flags, overrides.expires_at | `migrations/0004_executive_mode.sql` | ~30 | #1 |
| 3 | Strictness mapping package — pure function `Apply(grade, paranoid, raw_verdict) → final_verdict` + tests | `services/verdict-api/internal/strictness/strictness.go` + `_test.go` | ~150 | — (standalone) |
| 4 | Reason code: add `BLOCKED_BY_STRICTNESS_POLICY` to taxonomy | `services/verdict-api/internal/reasons/reasons.go` | +1 | §5.4 reasons package |
| 5 | Verdict-api integration — call `strictness.Apply()` after fusion, before response; load tenant/user paranoid flag from DB; cache 60s | `services/verdict-api/internal/service.go`, new `internal/strictness/loader.go` | ~80 | #1, #3, #4 |
| 6 | Warmup tracker — `users.paranoid_enabled_at` + 24 h grace window where B is treated as A | `migrations/0004_executive_mode.sql`, `internal/strictness/strictness.go` | +20 | #2 |
| 7 | Override expiry job — scheduler sweep `overrides WHERE expires_at < now()` → soft-delete | `services/scheduler/cmd/...` | ~30 | §6 scheduler service |
| 8 | Extension settings UI — toggle in `options.html`, "Executive Mode" copy, warmup banner | `apps/extension/src/options.html`, `options.js` | ~80 | §7 extension finish |
| 9 | Portal — admin toggles tenant-default `paranoid_mode`; per-user override; "executive role" auto-prompt | `apps/portal/app/admin/...` | ~120 | §9 portal admin |
| 10 | Analytics split — dashboard separates `BLOCKED_BY_STRICTNESS_POLICY` from detection-driven BLOCKs (must not inflate true-positive metrics) | `apps/portal/app/admin/analytics` | ~40 | #4 |
| 11 | Eval harness extension — `make eval-paranoid` runs corpus through paranoid mapping; expected delta documented in §19.6 | `tools/eval/run.py` | ~30 | #3 |

**Total scope:** ~700 LOC across migrations + Go + extension + portal.

**Order to execute:**
1. Land #1 and #3 first — they have no dependencies and form the foundation. #3 is testable in isolation.
2. Land #2, #4, #6 once #1 is merged.
3. #5 integrates after #1–#4 — that's when the feature flips on for tenants flagged paranoid.
4. #7 in parallel with scheduler service work (§6).
5. #8, #9, #10 follow the broader Phase-1 extension and portal finishes.
6. #11 last — locks the eval gate.

**Exit gate for Executive Mode specifically:**
- `make eval-paranoid` shows ≥ +7 pp weighted recall vs. normal mode on the labeled corpus.
- Friction-rate metric (ratio of `BLOCKED_BY_STRICTNESS_POLICY` to total navigations) under 10% on a 7-day soak test with internal users.
- Override-expiry job evicts test rows within 1 minute of expiry.
- Warmup window verified end-to-end: new paranoid user navigates to a B-graded site within 24 h → ALLOW; after 24 h → ISOLATE.

**Out of scope for Phase 2** (defer to Phase 3):
- Per-page-class strictness (e.g. "paranoid only on login pages"). Build only if a customer asks.
- Strictness presets ("Light Executive" / "Standard Executive" / "Hard Executive"). One mapping is enough until product data says otherwise.

---

## 12. Engineering rules (non-negotiable)

1. **Every block must be explainable.** No verdict ships without ≥1 reason code in `evidence.signals.codes[]`.
2. **Default-hold for unknown popups from any opener.** No silent "allow because we haven't seen it." The matrix in §3.1 is exhaustive.
3. **Sensitive page classes (login/payment/oauth/admin/download) get short TTL caps regardless of grade.** Compromised trusted sites are the worst false-negative class.
4. **Detection-logic PRs run `make eval` before and after.** Precision and recall cannot regress.
5. **No new entry point bypasses the verdict API.** Resolver, extension, and (future) agent all call the same `/verdict`. No service-internal "shortcuts."
6. **No deep scan on every visit.** Trust registry reuse is mandatory — measured by the `cache_hit_ratio` metric on `/verdict`, target ≥ 0.85 in steady state.
7. **Honest UX.** The product is "maximum practical protection," not "perfect safety." Interstitials say "Checking site safety," not "Guaranteed safe."

---

## 13. What this plan deliberately drops from the spec

- **Full enterprise TLS inspection.** High-friction (root CA install), out of scope for the consumer/SMB push. Revisit in Phase 4.
- **Multi-browser sandbox pool (Chromium *and* Firefox in sandbox-render).** Single Chromium for Phase 1 + 2; add Firefox only if eval shows cloaking targeted at Chromium UA.
- **Full antivirus detonation farm.** One AV engine + signature checks in Phase 2; multi-engine later.
- **Permanent product split into "DNS / Web / Scan / Isolate" SKUs.** One product, one verdict API, one portal. Don't fragment until there's a customer asking for it.

---

## 14. Open questions to settle in `docs/issues/ISSUES.md`

- Q1: Confidence threshold for the universal phishing rule — keep `0.92` or tighten?
- Q2: Should `WARN`-verdict opener with `ALLOW`-cached target downgrade the target to `WARN` (taint propagation)?
- Q3: Isolation session length cap — 5 min, 15 min, no cap?
- Q4: Should `holding.html` show the page favicon (good UX) or hide it (avoid leaking that we're fetching the target before user consent)?

---

## 15. Coverage matrix — honest assessment

**Read this before claiming the product catches anything.** No detection system is rock-solid; this matrix says where this one is strong, where it's weak, and what's missing entirely. Each row includes a concrete bypass scenario where the rating is anything below S, and the OSS tool that would close the gap if one exists. Updates here are mandatory whenever a new detector lands.

Legend: **S** strong / **M** medium / **W** weak / **G** gap (no logic).

### Phishing
| Attack | Rating | Defense / concrete bypass / OSS that helps |
|---|---|---|
| Lookalike-domain credential phishing | **S** | Identity-mismatch rule fires on visual + non-canonical + age/ASN/issuer mismatch. |
| Phishing on compromised legit subdomain | **S** | Canonical-domain list excludes the host; cert/script drift catches the compromise transition. |
| MFA-relay (Evilginx, Modlishka, EvilProxy) | **S** | Visual = 1.0 to real brand; domain not in canonical → BLOCK. Even if the relay uses Let's Encrypt and an aged proxy domain, age<90d + form-action analysis trip the rule. |
| Homograph / Punycode / typosquat / combosquat | **S** | Tier-1 homoglyph + Levenshtein + substring. **OSS that strengthens it: `dnstwist`** — generates 30+ permutation classes per brand, much more thorough than our current handful. Run it nightly to pre-populate the deny cache. |
| **Browser-in-the-browser (BITB)** | M | Fake "browser window" is an HTML `<div>` styled to look like a Chrome popup — no `window.open` fires, popup interception is blind. Bypass: kit renders a fake `accounts.google.com` URL bar inside the page, real form posts to attacker. Caught only if CLIP visual matches the fake frame to a brand AND `cred_form_cross_origin` fires. **No mature OSS solution**; would need a small custom classifier trained on BITB screenshots. |
| **OAuth consent phishing** | W | Bypass: real `login.microsoftonline.com/oauth2/authorize?client_id=<malicious>&scope=Mail.ReadWrite+files.readwrite.all` — domain IS canonical, visual IS real, no impersonation. Our rule does not fire. Requires OAuth-aware logic. **OSS that helps: none directly.** Microsoft publishes verified-publisher lists; Google publishes OAuth app catalogue; aggregate manually. |
| Open-redirect on trusted domain | M | Bypass: `bank.com/out?url=https://evil.com` — initial URL is canonical, final URL is malicious. Solid only if `final_url` (not requested URL) is routed through fusion. Sandbox-render already captures `final_url`; the wiring just needs to make verdict-api decide on it. |
| Subdomain takeover | W | Bypass: attacker claims dangling `marketing.bigco.com` CNAME pointing at deleted Heroku app. Our canonical list contains `bigco.com` so subdomain is "in canonical" → rule treats as legit. **OSS that helps: `Subjack`, `subzy`, `tko-subs`, `can-i-take-over-xyz` dataset** — feed CNAME targets through these; flag dangling. |
| QR phishing (quishing) | W | Email-delivered QR scanned on phone; user's phone bypasses our extension and (usually) our DNS. DNS-only mitigation if user configured XGG DNS on the phone. Phase-3 endpoint agent on mobile is the only real fix. |
| Tab-history / history-spoof phishing | M | Page uses `history.replaceState` to make the URL bar show a benign path after navigation. Caught via `final_url` capture; URL-bar spoof doesn't deceive the verdict API. |

### Malware delivery
| Attack | Rating | Defense / concrete bypass / OSS that helps |
|---|---|---|
| Drive-by browser zero-day | W detection / **S containment** | We cannot detect novel exploits from render-side. Mitigation = `ISOLATE` verdict: the exploit fires in the remote sandbox, not the endpoint. Risk = a page mis-classified as ALLOW exposes the user. **OSS that helps containment: `Drakvuf Sandbox`** (VMI-based, hypervisor-level monitoring) sees exploit attempts that evade in-OS hooks; ops-heavy. |
| **HTML smuggling** (Blob → `URL.createObjectURL` → programmatic anchor-click) | M | Bypass: page reassembles a ZIP-in-JS-string into a Blob, creates an object URL, programmatically clicks an anchor with `download` attr. Our current download discovery looks at `<a href>` and `Content-Disposition`; it misses Blob-built downloads unless we instrument the APIs. **OSS that helps: `box-js`, `malware-jail`** — Node-based JS sandboxes that hook these exact APIs and dump the reconstructed payload. Wire them as a post-render analyzer on suspicious scripts. |
| **Magecart / form-skimming JS** (e.g. checkout-page skimmer on legit e-commerce) | M | Bypass: legitimate Shopify/WooCommerce store gets a skimmer injected; it reads keystrokes from card-number field and POSTs to attacker. Caught by `cred_form_cross_origin` *only* if the skimmer uses a visible form-submit; many skimmers use silent `fetch()` from keystroke listeners. **OSS that helps: `YARA`** with rules from Sansec, RiskIQ, ESET — pattern-match the known skimmer families against captured JS. Plus SRI hash tracking. |
| ClickFix / paste-to-run | W | Bypass: page just says "press Win+R, type powershell, paste this command" with no API touch. Pure social engineering — no clipboard write to hook. Some variants do auto-copy via Clipboard API → caught. **OSS that helps: `YARA` rules** for the visible page text patterns ("verify you are human", "press Windows + R", etc.). |
| Compromised JS supply chain (CDN content swap, e.g. **Polyfill.io 2024**) | M | Bypass: same script URL, same SRI-less `<script src>`, but the file content changed. Our script-origin drift catches a *new* origin; it doesn't catch modified content from an existing origin. **OSS that helps: `Retire.js`** (known-vuln JS lib database) + SRI hash tracking implemented by us. |
| Malicious WASM | W | Bypass: ransomware/miner ships as WASM module loaded via `WebAssembly.instantiate`. **OSS that helps: `WABT` (wabt2wat)** for disassembly; pattern-match against known malicious WASM hashes (small ecosystem). Detection of *novel* malicious WASM is unsolved. |
| Service-worker persistence | M | Bypass: page registers SW with broad scope; SW intercepts future fetches even after tab closed and serves malicious content offline. We detect SW registration as a behavioral signal but don't block on it alone. Sensitive-class TTL revisit at next visit catches drift. |
| **Cryptojacking (in-browser miner)** | M | Bypass: page loads Monero/CoinIMP miner WASM; high CPU, no UI signal. Caught via behavioral CPU-spike signal + WASM-load + connection to known miner pool. **OSS that helps: `MinerBlock`, `NoCoin` lists** — public domain/script blocklists for miners; ingest as a feed. |
| LNK / OneNote / ISO / archive nested droppers | S (after file-detonator) | Spec'd in §5.6. **OSS: `CAPEv2`, `Cuckoo3`** for detonation; `YARA` for static signatures. |

### Popup / interaction abuse
| Attack | Rating | Defense / bypass |
|---|---|---|
| Single popup to unknown URL | **S** | §3.1 forces verdict, default-hold on `holding.html`. |
| Nested popup chains (popup → popup → popup) | **S** | Every node verdicts independently; `popup_edges` records lineage; `BLOCKED_OPENER_LINEAGE` propagates downstream. |
| `window.open` flood / popup storm | **S** (after §5.2) | `POPUP_STORM_DETECTED` signal once behavioral instrumentation lands. |
| Popup that triggers download | **S** | Popup itself goes through verdict; if released, the download goes through file-detonator. |
| **Tabnabbing** (opener silently rewrites itself to phishing while you're on popup) | M | Bypass: malicious page opens a popup, then `window.opener.location = 'evil.com/login'` while you're distracted. Caught only with `chrome.tabs.onActivated` re-verdict on focus return. Spec'd in §16.5 but not implemented. |
| **Reverse tabnabbing** (popup rewrites its own opener via `window.opener`) | M | Same fix as above; mitigated for `target=_blank` links with `rel=noopener` but we can't enforce that on third-party HTML. |
| Alert/confirm/fullscreen/`beforeunload` traps | **S** (after §5.2) | `FAKE_SUPPORT_SCAREWARE` composite reason. |

### Server-side evasion (largest weak area)
| Attack | Rating | Defense / bypass / OSS |
|---|---|---|
| **Server-side cloaking by IP/UA/geo** | W | **Single biggest detection gap.** Bypass: kit serves benign HTML to AWS/GCP sandbox IPs (which urlscan/our sandbox use), serves real phishing to residential IPs. Our render = clean. **OSS that helps: nothing turn-key**, but residential-proxy services (Bright Data, Smartproxy — not OSS but commercial) used responsibly + multi-cloud egress diversification (DigitalOcean + Hetzner + OVH + Linode) gives diff'able outputs. Open Tor exit is detectable by attackers and they whitelist or block it, so not a substitute. |
| Time-bomb / delayed payload | W | Bypass: malicious JS sleeps 60s before injecting iframe; sandbox snapshots at `networkidle` (~5s) and exits. Extend wait, sample at multiple checkpoints (5s, 30s, 2min for high-risk). |
| User-interaction-gated payload | W | Bypass: kit only injects credential form after first click on the page. Spec mentions interaction simulation, not built. **OSS that helps: `Browsertrix-Crawler`** (Webrecorder) — Playwright-based, supports behavioral scripts that click/scroll/dismiss; can adopt their interaction profile. |
| Captcha-walled malicious page | W | Bypass: page shows Cloudflare/hCaptcha to scanners, malicious form to real users post-solve. Hard to bypass without a real captcha solver; treat captcha-walled unknowns as `ISOLATE` by default. |
| Referrer-dependent malicious behavior | M | Sandbox does not vary Referer. Easy fix: render with empty / google.com / suspicious-typical referrers and diff. |

### Iframe / embedded content
| Attack | Rating | Defense / bypass / OSS |
|---|---|---|
| **Malvertising iframe on clean publisher** (e.g. ad-network compromise serving exploit kit) | G | §3 verdict matrix covers top-level + popups only — third-party iframes aren't gated. A clean news site loading an ad-network iframe that pivots to an exploit kit slips through. **Open gap.** Fix in §16.2. |
| Hidden iframe to unrelated domain | M | Flagged as signal, contributes to fusion score; not auto-block. |
| postMessage abuse (iframe ↔ parent) | W | We don't currently observe postMessage traffic. Add as a sandbox-render signal. |

### DNS / network layer
| Attack | Rating | Defense / bypass / OSS |
|---|---|---|
| DGA / fast-flux | M | Bypass: malware uses domain like `xkvjqweru.com` rotated daily. Tier-1 lexical helps but is not a real DGA classifier. **OSS that helps: `dgad`, `pyDGA`, `Endgame DGA classifier`** (open-sourced character-bigram models) — train on DGArchive and run as a Tier-1 signal. |
| DoH bypass by malware (uses `1.1.1.1` / `8.8.8.8` directly) | W | Bypass: Emotet/Qakbot speak DoH directly, never hit our resolver. Requires endpoint agent (Phase 3) to block outbound to public DoH. |
| DNS rebinding | M | Resolver should drop RFC1918/loopback answers for public names. **OSS that helps: `dnsrebinder`-style filter logic; existing `dnsmasq --stop-dns-rebind` is reference.** Verify our resolver does this. |
| Sinkhole evasion via hard-coded IPs | W | If malware hard-codes IPs, no DNS query → we don't see it. Endpoint agent only. |

### Identity / form abuse
| Attack | Rating | Defense |
|---|---|---|
| Form posts credentials cross-origin | **S** | `cred_form_cross_origin` signal. |
| Hidden / off-screen credential fields | M | Bypass: skimmer reads from `position: absolute; left: -9999px` input. Need DOM-traversal that ignores visibility for credential-field detection. |
| Keystroke listener exfil (no form-submit) | M | See Magecart row above. |
| Notification-permission spam → drive-by | **S** | Composite: prompt + popup-storm. |

---

## 16. The five additions required before claiming "rock-solid"

Until these ship, the product is "very good, with known holes" — not rock-solid.

1. **Multi-egress sandbox + cloaking diff.** 2–3 ASNs minimum (cheapest: one DigitalOcean region + one Hetzner + one residential-proxy session), UA rotation, referrer rotation. Render the same URL from each; diff DOM/screenshot/network. Any divergence is a hard signal. Closes server-side cloaking.
2. **Iframe verdict gating.** Top-level third-party iframes get their own verdict request with parent as opener (same matrix as §3.1). Closes the malvertising gap.
3. **Interaction simulation.** Sandbox clicks visible buttons, dismisses banners, scrolls. Adopt Browsertrix-Crawler's behavior profiles. Triggers user-gated payloads.
4. **OAuth `client_id` reputation registry.** New table populated from Microsoft verified-publisher catalogue and Google OAuth app catalogue. Verdict-api intercepts OAuth consent screens (URL pattern match on real provider domains) and blocks unknown apps requesting sensitive scopes.
5. **Tabnabbing re-check.** Extension hooks `chrome.tabs.onActivated`; if the focused tab's URL changed since last verdict, re-verdict.

### Second wave — high-leverage smaller additions
- **YARA integration** in sandbox-render and file-detonator — phishing-kit and skimmer signatures from Sansec, RiskIQ, Awakening, abuse.ch. Single highest-bang-for-buck OSS adoption.
- **box-js / malware-jail** as a JS post-analyzer for suspicious scripts — catches HTML smuggling and obfuscated droppers.
- **SRI / per-script-content hashing** for supply-chain compromise (Polyfill.io class).
- **Blob/`URL.createObjectURL` instrumentation** in Playwright via CDP — same goal.
- **BITB visual classifier** — small CNN trained on BITB screenshots.
- **DGA classifier** — character-bigram entropy model on the SLD.
- **DNS rebinding hard check** in resolver — drop RFC1918/loopback answers for public names.
- **Referrer-spoof variance** in sandbox renders.
- **Subdomain-takeover scanner** — `Subjack` against canonical-domain CNAME targets, weekly.
- **postMessage observation** in sandbox.
- **CPU/timing-based cryptojacking detection** in sandbox + miner-pool domain feeds.

### Phase-3 additions (need endpoint agent)
- Detect malware bypassing our resolver via direct DoH to 1.1.1.1/8.8.8.8.
- Mobile coverage for QR phishing.
- Process-level behavior signals for drive-by zero-day detection beyond ISOLATE containment.

---

## 17. Honest claims we can and cannot make

**Can claim:**
- Catches phishing impersonation of high-value brands at high precision (eval ≥ 0.95).
- Stops every popup before it opens, scans every unknown one, blocks lineage from already-bad openers.
- Contains drive-by exploits via ISOLATE without needing to detect them.
- Explains every block with reason codes and per-URL evidence.
- Detects compromise of previously-trusted pages via fingerprint drift on cert / scripts / forms / favicon.

**Cannot claim (until §16 lands):**
- "Catches all malware." Cloaking and user-gated payloads will slip.
- "Stops drive-by downloads on any page." Compromised legitimate publishers with malvertising iframes will slip (until §16.2).
- "Protects against OAuth phishing." (Until §16.4.)
- "Works on mobile." (Phase 3.)
- "Cannot be bypassed." Any attacker who knows we use a single-ASN sandbox can serve clean to us, dirty to victims.

**Will never be true:**
- Zero false negatives. Compromised legit sites and zero-day kits always exist.
- Zero false positives. New legitimate brand campaigns will hit homoglyph/age signals.
- Coverage of every endpoint. Without an agent, non-browser malware traffic is invisible.

---

## 18. Open-source tooling — build vs. integrate

We are not the first people to scan a malicious web page. Most of our planned "build" items have mature OSS that we should integrate rather than rebuild. This section is the build-vs-buy register; it is authoritative — overriding individual section text — for any decision about adding a new detection capability.

### 18.1 Already in our stack
| Tool | Where | Notes |
|---|---|---|
| **Playwright** | `services/sandbox-render` | Chromium driver. License Apache-2.0. Keep. |
| **CLIP ViT-B/32** | `services/visual-match` | Visual embeddings. MIT. Keep — this is custom-trained against our brand registry. |
| **pgvector** | Postgres | Embedding search. Keep. |
| **CoreDNS** | dev only | Vestigial in compose; remove or document. |

### 18.2 Integrate now — high leverage, low cost (Phase-1 wave)

These are well-maintained, integration is a few hundred lines each, and they close real gaps in the matrix.

| Tool | License | What it gives us | Wiring |
|---|---|---|---|
| **YARA** | BSD-3 | Signature engine for HTML/JS/file patterns. Single highest-bang OSS adoption. Use rules from Sansec (Magecart), RiskIQ, abuse.ch, Yara-Rules community repo. | Add `services/yara-scan` (Go binding `go-yara`); call from sandbox-render after capture and from file-detonator. Emit matches as reason codes. |
| **dnstwist** | Apache-2.0 | Comprehensive domain-permutation generator — 30+ classes (typo, omission, addition, bitsquat, homoglyph, TLD swap, hyphenation, vowel-swap, …). Far better than our hand-rolled Tier-1 generator. | Nightly job in `services/scheduler`: for each brand keyword, generate permutations, check current resolution, pre-populate deny cache for confirmed-bad. |
| **playwright-stealth** | MIT | Anti-fingerprint plugin — strips `navigator.webdriver`, fixes WebGL/Canvas fingerprints, fixes timezone leaks. Keeps cloaking-aware kits from detecting our sandbox. | Drop into `services/sandbox-render` Playwright init. |
| **mitmproxy** | MIT | TLS-terminating proxy inside the sandbox container. Captures full request/response bodies (including encrypted), HAR-quality. | Run inside each sandbox container; route the headless Chromium through it. Sandbox sees a self-signed cert it trusts. Emit HARs into evidence. |
| **ImageHash / pHash** | BSD | Cheap perceptual hashes (pHash, dHash, aHash) for favicons and full screenshots. Layers under CLIP — pHash hits are deterministic and faster; CLIP is the deeper net. | Compute in visual-match alongside CLIP embedding; index in Postgres as `bytea`. |
| **Subjack / subzy / can-i-take-over-xyz** | MIT | Subdomain-takeover detectors. | Weekly job: for each canonical-brand domain, enumerate subdomains (CT logs already give them via `ct-monitor`), resolve CNAMEs, flag dangling. Emit `SUBDOMAIN_TAKEOVER_RISK` reason. |
| **CertStream + crt.sh** | MIT | Real-time CT log stream + REST query. | `ct-monitor` likely already uses CertStream; verify, fall back to crt.sh JSON API for historical lookups. |
| **MISP** *(optional)* | AGPL-3.0 | Threat intel platform — ingest STIX/TAXII feeds, dedupe, share. | Heavy-ish. If we have >3 TI feeds, MISP earns its weight; otherwise just call feeds directly. **Default: skip in Phase 1.** |
| **abuse.ch feeds** (URLhaus, ThreatFox, MalwareBazaar) | Free | Free, high-quality, well-curated URL + file + IOC feeds. | Ingest URLhaus daily into deny cache; ThreatFox into IP/domain reputation; MalwareBazaar for hash lookups in file-detonator. |
| **PhishTank + OpenPhish** | Free (PhishTank API), Free tier | Confirmed phishing URLs. | Daily ingest into deny cache. |

### 18.3 Integrate for files (Phase 2 file-detonator)

| Tool | License | Use |
|---|---|---|
| **CAPEv2** | GPL-3 | Modern, actively maintained malware sandbox (fork of Cuckoo). Detonates PE/ELF/Mach-O/JS/HTML/Office/PDF. Returns behavior reports, network artifacts, dropped files. **This is the file-detonator** — don't rebuild. |
| **ClamAV** | GPL-2 | Baseline AV signature engine. Free, decent, has phishing/clicker signatures. |
| **YARA** (again) | BSD | Static signature engine on dropped files. |
| **box-js / malware-jail** | MIT / GPL | Node-based instrumented JS sandbox. Catches obfuscated droppers and HTML-smuggling reconstructions. |
| **synchrony** | MIT | JS deobfuscator (specifically for obfuscator.io output). Run before YARA on suspicious scripts. |
| **WABT (wabt2wat)** | Apache-2.0 | WASM disassembler for static analysis of WebAssembly modules. |
| **DIE (Detect It Easy)** | MIT | Packer / compiler / signature detection for binaries. |
| **oletools** | BSD | Office document macro + payload extraction. Critical for emotet/qakbot-style maldocs. |
| **pdfid / pdf-parser** | Public domain (Didier Stevens) | PDF triage. |

### 18.4 Free-tier external corroborators (not OSS but free at our volume)

Wire as inputs to `fusion.Inputs.GSBClean / VTPositives / BlocklistHit / *new corroborator fields*`. Cache results 6h–24h per URL/hash to stay under quotas.

| Service | Free tier | What we get |
|---|---|---|
| **Google Web Risk** | Trial credit, then paid | Authoritative URL reputation. Plan §5.5 already calls for this. |
| **VirusTotal v3** | 500 req/day free | URL + file hash multi-engine; community votes; relationship graph. |
| **urlscan.io** | Free anonymous + free signed-in | Pre-scan history — if they've already scanned this URL, we get a result for free. |
| **Hybrid Analysis (Falcon)** | Free with registration | Full file detonation as a service. Useful before we stand up our own CAPE. |
| **Triage (tria.ge)** | Free for researchers | Alternative file detonation. |
| **AbuseIPDB** | 1000 req/day free | IP reputation. |
| **Shodan** | Free tier with API key | Hosting context — open ports, banner. |

### 18.5 Evaluate — heavier ops, real upside

| Tool | License | Why it might be worth it |
|---|---|---|
| **Drakvuf Sandbox** | LGPL-3 | Hypervisor-VMI based detonation; sees evasion-aware malware that defeats hooked sandboxes (CAPE/Cuckoo). Ops cost: Xen + kernel-debug VMs. Use if eval shows we're losing to evasion-aware families. |
| **Cuckoo3** | GPL-3 | Cuckoo's official next-gen rewrite; alternative to CAPE. CAPE is the safer bet today. |
| **Thug** | GPL-2 | Low-interaction honeyclient (emulates browser, no real rendering). Designed specifically for drive-by exploit kit detection. Niche but real signal. |
| **Browsertrix Crawler** | AGPL-3 | Playwright-based archival crawler with **behavior scripts** for clicking/scrolling/dismissing — exactly what we need for §16.3 interaction simulation. Either embed or copy their behavior profiles. |

### 18.6 Decision register — what stays in-house

| Capability | Decision | Why |
|---|---|---|
| Visual brand match (CLIP) | **Keep in-house** | Custom against our brand registry; no OSS alternative. |
| Identity-mismatch fusion rule | **Keep in-house** | Our core IP. |
| Brand registry curation | **Keep in-house** | Curation is the moat. |
| Sandbox driver | **OSS (Playwright)** | Already chosen. |
| File detonation | **OSS (CAPEv2)** | Mature, no reason to rebuild. |
| Signature matching | **OSS (YARA + ClamAV)** | Industry standard. |
| JS sandbox / deob | **OSS (box-js + synchrony)** | Specialized, hard problem. |
| TI feeds | **Direct feeds (abuse.ch, PhishTank, OpenPhish, Web Risk)** | MISP only if we exceed 3 feeds. |
| Cert/CT monitoring | **OSS (CertStream + crt.sh)** | Standard. |
| Typosquat permutation | **OSS (`dnstwist`)** | Replaces our Tier-1 hand-roll with broader coverage; keep Tier-1 for runtime classification. |
| Subdomain takeover | **OSS (`Subjack`)** | Trivial integration. |
| Anti-fingerprinting | **OSS (`playwright-stealth`)** | Free win. |
| Sandbox traffic capture | **OSS (mitmproxy)** | Standard. |
| Multi-egress / cloaking diff | **In-house** | Just run Playwright instances on 3 cloud regions and diff — no library needed. |
| OAuth `client_id` reputation | **In-house** | No OSS catalogue exists; assemble from MS/Google verified-publisher lists. |
| BITB classifier | **In-house** | No OSS model exists; small custom CNN. |
| DGA classifier | **OSS (Endgame model) + in-house tuning** | Open models exist; we fine-tune. |
| ISOLATE / remote browser | **In-house (Playwright pool + CDP bridge)** | OSS RBI options (e.g. WebGap, browser-isolation projects) exist but quality varies; build with what we already run. |

### 18.7 The integration order that maximizes detection-per-week-of-work

If you only have a quarter to spend, do them in this order:

1. **YARA + Sansec/abuse.ch rules** → catches Magecart, known phishing kits, known droppers — single biggest jump in recall.
2. **dnstwist nightly + PhishTank/OpenPhish ingest** → broad deny cache, cheap.
3. **playwright-stealth + mitmproxy** in sandbox → harder to fingerprint, full traffic capture.
4. **CAPEv2 file-detonator** → finishes the download story.
5. **Multi-egress diff** (3 cloud regions of Playwright + diff job) → closes server-side cloaking.
6. **box-js post-analyzer** on suspicious scripts → HTML smuggling + supply-chain.
7. **Subjack weekly** → subdomain takeover.
8. **Browsertrix behavior profiles** → interaction simulation.

After (1)–(8) and the §16 core five, the matrix in §15 has no remaining W or G ratings except the inherent ones (mobile/QR, DoH bypass, drive-by zero-day detection) — all of which require an endpoint agent.

---

## 19. End-user protection rates — what we can honestly tell users

Numbers below are *recall against attacks of that class the user actually encounters*, not "% safe overall." Calibrated against APWG/PhishLabs/Google Safe Browsing benchmarks and academic blocklist-latency studies. Anyone quoting higher numbers without an eval harness is selling.

**End-user setup assumed:** XGG DNS + XGG Chrome MV3 extension + Chrome with Safe Browsing on.

### 19.1 By attack class (Phase 1 → 2 → 3)

| Attack class | P1 | P2 | P3 |
|---|---|---|---|
| Known phishing on blocklisted domain | 92% | 96% | 97% |
| Zero-day phishing of top-50 brands | 75% | 85% | 88% |
| Zero-day phishing of long-tail brands | 35% | 55% | 60% |
| MFA-relay (Evilginx / EvilProxy) | 78% | 88% | 90% |
| Typosquat / homograph / combosquat | 88% | 95% | 95% |
| OAuth consent phishing | 8% | 75% | 78% |
| Open-redirect on trusted domain | 50% | 80% | 82% |
| Subdomain takeover | 5% | 65% | 65% |
| Browser-in-the-browser (BITB) | 35% | 60% | 65% |
| Magecart / form skimming | 20% | 75% | 80% |
| HTML smuggling | 10% | 60% | 70% |
| ClickFix / paste-to-run | 15% | 45% | 70% |
| Compromised JS supply chain | 25% | 65% | 70% |
| Cryptojacking | 10% | 75% | 80% |
| Tech-support scareware | 30% | 85% | 88% |
| Single popup → unknown URL | 88% | 92% | 92% |
| Nested popup chain | 90% | 94% | 94% |
| Popup → malware download | 80% | 90% | 93% |
| Popup storm / window.open flood | 80% | 95% | 96% |
| Tabnabbing | 30% | 85% | 85% |
| Server-side cloaking | 5% | 65% | 75% |
| Time-bomb payload | 10% | 55% | 70% |
| User-interaction-gated payload | 5% | 60% | 70% |
| Malvertising iframe on clean publisher | 8% | 75% | 78% |
| Drive-by zero-day — *detection* | 5% | 10% | 25% |
| Drive-by zero-day — *containment via ISOLATE* | 75%* | 95% | 97% |
| Generic malicious download | 35% | 82% | 88% |
| Signed-but-malicious download | 20% | 60% | 75% |
| Malware via direct DoH (1.1.1.1) | 0% | 0% | 70% |
| QR phishing on mobile | 0–25%† | 0–25%† | 75% |
| DGA C2 communication | 30% | 70% | 80% |
| DNS rebinding | 95%‡ | 95% | 95% |
| Captcha-walled cloaked page | 20% (containment 80%) | 85% | 88% |

\* Only if the page is verdicted ISOLATE or BLOCK before exploit fires. ALLOW + zero-day = 0%.
† Only if mobile uses XGG DNS — extension cannot run on mobile browsers we don't control.
‡ Assumes resolver drops RFC1918/loopback answers for public names. Verify in code; if not, 0%.

### 19.2 Weighted overall (typical-user threat encounter mix)

Distribution: 70% phishing attempts · 15% malware/drive-by · 10% scam pages · 5% advanced (OAuth/supply chain/cryptojacking).

| Setup | Overall protection |
|---|---|
| Unprotected Chrome, no Safe Browsing | ~10% |
| Chrome alone with Safe Browsing | ~51% |
| **XGG Phase 1 + Chrome+SB** | **~69%** (+18 pp) |
| **XGG Phase 2 + Chrome+SB** | **~84%** (+33 pp) |
| **XGG Phase 3 + Chrome+SB** | **~89%** (+38 pp) |

Different threat-profile users see different overall numbers (e.g., a finance/exec user with high OAuth-phishing exposure benefits more from Phase 2; a power user already cautious about phishing benefits more from Phase 2's malware/cloaking gains).

### 19.3 Side-by-side against other tools (XGG Phase 2 baseline)

Recall per attack class, same end-user setup (browser-only, no managed agent). Empty cells = product doesn't operate at that layer.

| Attack class | Chrome SB | NextDNS | Quad9 | CF 1.1.1.1 family | AdGuard DNS | Umbrella | CF Gateway (ent.) | Zscaler/Netskope | SmartScreen | **XGG P2** |
|---|---|---|---|---|---|---|---|---|---|---|
| Known phishing (blocklist) | 75% | 90% | 85% | 80% | 80% | 95% | 92% | 95% | 85% | **96%** |
| Zero-day phishing (top brand) | 35% | 30% | 25% | 20% | 25% | 50% | 55% | 65% | 50% | **85%** |
| Zero-day phishing (long-tail) | 15% | 15% | 12% | 10% | 12% | 25% | 30% | 40% | 25% | 55% |
| MFA-relay | 20% | 15% | 12% | 10% | 12% | 25% | 35% | 50% | 30% | **88%** |
| Typosquat / homograph | 50% | 70% | 60% | 65% | 70% | 80% | 85% | 88% | 70% | **95%** |
| OAuth consent phishing | 0% | 0% | 0% | 0% | 0% | 5% | 10% | 15% | 5% | **75%** |
| Magecart / skimmer | 5% | 0% | 0% | 0% | 0% | 10% | 15% | 25% | 15% | **75%** |
| Generic malware download | 70% | 25% | 20% | 20% | 20% | 60% | 75% | 85% | 80% | 82% |
| Drive-by exploit *containment* | 0% | 0% | 0% | 0% | 0% | 0% | 30% | 70% | 0% | **95%** |
| Server-side cloaking | 0% | 0% | 0% | 0% | 0% | 10% | 20% | 30% | 5% | 65% |
| Single popup → unknown URL | 0% | 0% | 0% | 0% | 0% | 0% | 5% | 10% | 0% | **92%** |
| Nested popup chain | 0% | 0% | 0% | 0% | 0% | 0% | 5% | 10% | 0% | **94%** |
| Tabnabbing | 0% | 0% | 0% | 0% | 0% | 0% | 5% | 10% | 5% | 85% |
| Tech-support scareware | 5% | 10% | 5% | 5% | 10% | 20% | 30% | 50% | 30% | **85%** |
| Malvertising iframe | 5% | 5% | 5% | 5% | 5% | 15% | 25% | 40% | 15% | 75% |
| Cryptojacking | 5% | 30% | 5% | 5% | 40% | 30% | 50% | 70% | 5% | 75% |
| HTML smuggling | 10% | 0% | 0% | 0% | 0% | 5% | 10% | 25% | 30% | 60% |
| Subdomain takeover | 5% | 5% | 5% | 5% | 5% | 10% | 15% | 25% | 10% | 65% |
| QR phishing (mobile, off-DNS) | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% |
| **Weighted overall** | **~51%** | **~48%** | **~42%** | **~40%** | **~45%** | **~62%** | **~68%** | **~78%** | **~58%** | **~84%** |

### 19.4 What each competitor does best (and where they beat us)

- **Chrome Safe Browsing**: best raw download hash recall — Google's binary corpus is huge. XGG narrows it but doesn't quite catch up.
- **NextDNS / AdGuard DNS**: best consumer-grade DNS, cheap. XGG beats both above the DNS layer; below DNS they have nothing.
- **Cisco Umbrella**: mature commercial threat intel. XGG wins on popups, cloaking, OAuth, scareware; loses to Umbrella on global threat-feed breadth.
- **Cloudflare Gateway (enterprise) / Zscaler / Netskope**: real competitors via TLS inspection + RBI. They match XGG on containment and beat us on managed-endpoint coverage. We win on phishing precision (visual + identity-mismatch beats category filtering), on popup/lineage logic, and on per-URL evidence quality. They win on enterprise breadth — that's Phase 3.
- **SmartScreen**: tied to Edge/Windows; strong downloads, weak above URL reputation.

### 19.6 Paranoid Mode (Executive Mode) impact

Mode definition in §4.4. This table shows the delta vs. normal mode at Phase 2. Boost comes from elevating the floor (no unknown/B/C grades get ALLOW), not from any new detector.

| Attack class | P2 normal | **P2 + Paranoid** | Delta |
|---|---|---|---|
| Zero-day phishing of long-tail brands | 55% | **90%** | +35 |
| Server-side cloaking | 65% | **92%** | +27 |
| Drive-by zero-day containment | 95% | **99%** | +4 |
| HTML smuggling | 60% | **88%** | +28 |
| ClickFix / paste-to-run | 45% | **80%** | +35 |
| Time-bomb / interaction-gated payload | ~58% | **90%** | +32 |
| Cryptojacking | 75% | **92%** | +17 |
| Compromised JS supply chain | 65% | **85%** | +20 |
| Captcha-walled cloaked page | 85% | **95%** | +10 |
| Magecart on already-A checkout | 75% | 75% | **0** (mode does not help here) |
| OAuth consent phishing | 75% | 75% | **0** (depends on client_id registry, not grade) |
| MFA-relay on aged squat domain | 88% | 88% | **0** (caught by detection regardless) |
| Known phishing on blocklist | 96% | 96% | 0 |
| QR phishing on mobile | 0% | 0% | 0 |
| DoH-bypass malware | 0% | 0% | 0 |

**Weighted overall impact:**

| Phase | Normal | Paranoid | Δ |
|---|---|---|---|
| P1 | ~69% | ~80% | +11 pp |
| P2 | ~84% | **~91%** | +7 pp |
| P3 | ~89% | ~95% | +6 pp |

**Friction cost (do not omit when discussing with users):**
- Day 1 (no personal cache): ~30–50% of distinct domains hit an interstitial
- Day 30 (warm personal cache): ~10–15% friction
- Steady state with mature multi-tenant telemetry: ~5–8% friction

**Eligibility filter** (auto-prompt the upgrade for these profiles via the portal):
- Tenant admin marks user role as `executive`, `board`, `ir_analyst`, `journalist`, `sysadmin`
- Device flagged `managed_family` with parental controls active
- User opt-in via Settings (warmup mandatory)

### 19.5 Marketing claims this table allows

**Defensible against scrutiny (Phase 2):**
- "Catches 85% of zero-day phishing impersonations of major brands — 2.4× Cisco Umbrella."
- "Stops 92% of popup-delivered attacks, including nested popup chains. DNS-only providers stop 0%."
- "Contains 95% of drive-by browser exploits via integrated isolation, without an endpoint agent."
- "Detects 75% of OAuth consent phishing — a class no consumer product currently addresses."

**Not defensible (don't say):**
- "Blocks all phishing." — false; long-tail brands and cloaking will slip.
- "Stops all malware downloads." — file-detonator gets 82%, not 100%.
- "Protects mobile users." — only via DNS, and the agent is Phase 3.
- "Safer than Zscaler." — true on phishing precision, false on enterprise breadth.

---

## 20. Deep URL Trial strategy (dev addendum, 2026-05-27)

The core reframing that makes a personal-scale system beat commercial:

> Commercial tools ask: *have we seen this bad URL before?*
> We ask: *can this exact page prove it is authorized to perform this exact sensitive action?*

Commercial tools must decide in milliseconds at billion-URL scale. We can spend seconds-to-minutes per suspicious URL on a tiered ladder. That asymmetry compounds.

### 20.1 Tiered wait policy (must come first)

Replaces "2–15 minute wait" generic. Wait time scales with suspicion:

| Verdict tier | Max wait |
|---|---|
| Cached ALLOW (grade A+/A) | 1 ms |
| Cached BLOCK | 1 ms |
| First-seen, non-sensitive | 1–3 s |
| First-seen, sensitive, no replica match | 5–15 s |
| First-seen, sensitive, replica match, identity unknown | 30–120 s (deep scan) |
| Highly suspicious (multiple signals) on user-profile brand domain | 2–10 min ("deep trial") |

### 20.2 The 20 strategy items + current status

Per the dev's 2026-05-27 strategy document.

| # | Item | Status | Effort | Priority |
|---|---|---|---|---|
| 1 | URL Forgery Engine (punycode, invisible char, nested URL extraction, octal/hex IP, expired-domain reuse) | 70% | Small | P2 |
| 2 | Redirect Chain Courtroom (long wait, CTA click, timer wait, geo/cookie/referrer-gated detection) | 30% | Medium | P2 |
| 3 | Multi-Vantage Cloaking (3+ egress, residential proxy, headful/headless diff) | 0% | Big | **P1** |
| 4 | Credential Sink Proof (instrumentation + canary interaction + payload tracing) | 70% | Medium | **P1** |
| 5 | Brand Identity Binding (per-brand allowed script/CSP/CDN/OAuth/form-action origins) | 40% | Large per-brand | P2 |
| 6 | OAuth Abuse Detection (app age, publisher verification, first-seen client_id, redirect URI cross-domain) | 50% | Medium | P2 |
| 7 | Scam Page Detection (crypto drainers, fake support, fake CAPTCHA-to-command, fake browser update) | 20% | Medium | P2 |
| 8 | Hidden Malware Behind URL (file detonation, archive nesting, LOLBin) | 30% | Large | P3 |
| 9 | HTML Smuggling runtime hooks (Blob + createObjectURL + generated file capture) | 60% | Small | **P1** |
| 10 | Browser-in-the-Browser detection (visual chrome classifier) | 5% | Research | P4 |
| 11 | Interaction Simulation (drive the form with canary credentials, trace post-submit) | 0% | Medium | **P1** |
| 12 | Path-Level Reputation (per-path historical fingerprints, page-class drift) | 15% | Medium | P2 |
| 13 | **Infrastructure Graph Scoring** (nodes: domains/IPs/certs/favicons/webhooks/wallets/phones; edges: redirects/posts-to/shares-cert) | 0% | Medium | **P1** ← KILLER FEATURE |
| 14 | First-Seen Sensitive Page Policy (fail-closed on sensitive) | 80% | done | shipped |
| 15 | Lure Semantics (extract lure type from page text + action-vs-lure mismatch rule) | 0% | Small | P2 |
| 16 | Command Injection Lure Detection (ClickFix, clipboard PowerShell content inspection) | 40% | Tiny | **P1** |
| 17 | QR Phishing (decode QR from screenshot, recurse target through pipeline) | 0% | Small | P2 |
| 18 | Reputation Inversion ("is this domain unusually trusted for what it's doing?") | 30% | Small | P2 |
| 19 | Safe Final Verdict Model (staged hard gates) | 90% | done | shipped |
| 20 | **Personal Brand/Destination Profile** (user-specific allowlist of banks/SaaS/OAuth providers) | 0% | Tiny | **P0** ← KILLER FEATURE |

### 20.3 Why §13 and §20 are the game-changers

**§20 Personal profile** is the cheapest win and the thing commercial **structurally cannot match**:
- You know your ~20 banks/SaaS/OAuth providers
- Anything outside the profile claiming to be your bank → BLOCK
- Anything outside the profile asking for credentials → ISOLATE
- Commercial tools have universal allowlists that must serve millions of users with different habits

**§13 Infrastructure graph** is the personal-scale equivalent of cross-tenant intelligence:
- Every scan writes nodes (domains, IPs, certs, favicons, webhooks, wallets, phones, file hashes) and edges (redirects-to, posts-to, shares-cert, shares-favicon)
- Query: "any other scan share this webhook / wallet / favicon?" via Postgres recursive CTEs
- Catches kit reuse even when no feed has the URL
- Compounds value with every scan

### 20.4 Honest impact estimates with the full strategy implemented

| Attack class | Today | + §20 + §16 + §9 + §11 + §13 + §3 |
|---|---|---|
| Fresh phishing (first hour, no feed coverage) | 30–40% | **55–65%** |
| Phishing impersonating brand on user profile | 60–70% | **95%+** |
| OAuth consent phishing | 70–80% | **85–90%** |
| Compromised legit sites with new sensitive paths | 30–40% | **55–70%** |
| Reused-infrastructure attacks (new URL, same webhook/wallet/cert) | 0% | **75–85%** (infra graph) |
| Cloaked phishing | 5% | **65–75%** (multi-vantage) |
| HTML smuggling | 60% | **80%** |
| ClickFix / paste-to-run | 45% | **80%** |

### 20.5 Where this strategy specifically does NOT beat commercial

Honesty:
- Stale-feed-known phishing (URL reported 6h ago) — they have more feeds + faster ingest
- Non-browser threats (mobile, email, OS malware) — we're browser-only
- Cross-customer correlation (URL hits 200 of their customers in last hour) — they have the data, we don't

That's fine: the strategy is to **beat them for the user, not on average across all users**.

---

## 21. Phase plan — Deep URL Trial implementation

Supersedes the earlier Phase 2 / Phase 3 sections. Sequencing optimised for value-per-week.

### Phase A — One-week wins (cheap, massive impact)

Build these FIRST. Each is small; together they shift recall meaningfully.

| # | Task | Files | LOC | Effort |
|---|---|---|---|---|
| A1 | **Personal profile** — `profile.yaml` with `banks[]`, `saas[]`, `oauth_providers[]`, `cloud_storage[]`; loader in verdict-api; policy stage that BLOCKs profile-brand-claim from non-profile-domain | new `internal/profile/`, migration 0008, edit policy.go | ~300 | 1 day |
| A2 | **ClickFix content inspection** — extend clipboard hook in sandbox-render to capture written text; verdict-api scans for PowerShell/cmd/iex/mshta patterns; emit `CLICKFIX_COMMAND_TEXT_DETECTED` | sandbox-render init script + reasons.go + pipeline.go | ~120 | 1 day |
| A3 | **HTML smuggling runtime hooks** — hook `new Blob()`, `URL.createObjectURL`, programmatic anchor click in sandbox; capture generated-file metadata + first-N bytes | sandbox-render init script + renderResponse + policy.go | ~180 | 2 days |
| A4 | **Reputation inversion rule** — explicit policy rule for "old-clean domain hosting first-time sensitive page on a new path" → BLOCK | policy.go + pipeline.go | ~80 | half day |
| A5 | **URL Forgery Engine extensions** — invisible char detection, octal/hex IP disguise, nested URL extraction from query+base64 | tier1.go (new file) | ~250 | 2 days |
| A6 | **Tiered wait policy** — sandbox-render `render_budget_ms` param; verdict-api scales it per suspicion tier; matches §20.1 ladder | sandbox-render + pipeline.go | ~100 | 1 day |

**Phase A exit gate**: live smoke-scan recall ≥ 80% on user-profile brands; zero false positives on user's top-50 clean URLs; cached ALLOW path < 2 ms p95.

### Phase B — The two killer features

| # | Task | Files | LOC | Effort |
|---|---|---|---|---|
| B1 | **Infrastructure Graph schema** — migration: `intel_nodes` + `intel_edges` tables with bigserial PK, node_type, node_value, edge_type, weight, first_seen, last_seen | migration 0009 | ~150 | 1 day |
| B2 | **Graph writer in scheduler/sandbox** — every scan writes nodes (domain, IP, ASN, cert SHA, favicon pHash, form-action origin, redirect target, webhook URL, OAuth client_id, embedded crypto address, phone number) + edges | new `internal/intelgraph/` package in scheduler | ~500 | 5 days |
| B3 | **Graph correlator in policy** — Stage F.5: query graph for incoming URL's nodes; if any share a node with a known-BLOCK URL or with 5+ first-seen-suspicious URLs in last 30 d → high-risk signal | new `internal/intelgraph/correlate.go` consumed by policymap.go | ~250 | 3 days |
| B4 | **Graph eviction policy** — TTL by node type (favicon 90 d, IP 30 d, wallet/phone forever, cert 180 d) + edge TTL | scheduler/internal/expiry/ | ~100 | 1 day |
| B5 | **Interaction simulation** — Playwright drives the page: type canary email, password, OTP; click primary CTA; trace network calls; flag accept-any-creds + redirect-to-real-brand patterns | sandbox-render new endpoint `/interact` | ~400 | 5 days |
| B6 | **QR phishing** — `pyzbar` decode QR codes from page screenshots; recurse URL through pipeline; compare QR-target brand to visible page brand | sandbox-render + new YaraMatchOut-like field | ~150 | 2 days |

**Phase B exit gate**: graph contains ≥ 1,000 nodes after 7 d of personal use; ≥ 3 verdict-impacting correlation hits per week; interaction simulator catches 2/3 of accept-any-creds kits in eval set.

### Phase C — Multi-vantage cloaking detection

| # | Task | Effort |
|---|---|---|
| C1 | Provision 2 additional sandbox-render nodes (Hetzner Helsinki + DigitalOcean NYC, ~$10/mo total) | half day infra |
| C2 | One residential-proxy session config (Bright Data or similar; on-demand) | half day |
| C3 | Multi-vantage orchestrator in verdict-api — fan out to 3 egress, collect responses, diff (DOM hash, screenshot pHash, redirect chain, sink destinations) | 3 days |
| C4 | Cloaking-diff policy rule — if any vantage shows credential collection while others show clean → force BLOCK | 1 day |
| C5 | Per-vantage caching to avoid re-fanning out for known URLs | 1 day |

**Phase C exit gate**: cloaked-test corpus catch rate ≥ 65%.

### Phase D — Scam page extractors

| # | Task | Effort |
|---|---|---|
| D1 | Crypto-drainer classifier: detect WalletConnect prompts, `eth_sign`/`eth_sendTransaction` requests, seed-phrase form fields | 3 days |
| D2 | Fake support scam: phone-number + remote-control-tool URL + scareware behaviour composite | 2 days |
| D3 | Fake CAPTCHA-to-command: composite of "verify human" text + clipboard write + command syntax | 2 days |
| D4 | Fake browser-update / fake antivirus pages: visual replica detection against known Chrome/Firefox/Edge updater UIs + non-canonical domain | 3 days |
| D5 | IOC extraction (phones, wallets, emails) writes to infra graph (Phase B) | 2 days |

### Phase E — Path-level reputation (Package 5 from earlier plan)

| # | Task | Effort |
|---|---|---|
| E1 | Migration: `url_paths` table with per-path historical hashes | 1 day |
| E2 | Scheduler writes path fingerprint on every scan | 2 days |
| E3 | Policy rule: domain age > 1 yr AND path first-seen < 7 d AND page_class sensitive → high-risk | 2 days |

### Phase F — Brand registry depth

| # | Task | Effort |
|---|---|---|
| F1 | Schema: per-brand `allowed_script_origins[]`, `allowed_form_action_origins[]`, `allowed_oauth_endpoints[]`, `expected_csp[]`, `allowed_cdns[]` | 1 day |
| F2 | Seed top 20 brands fully (curation work) | 2 weeks |
| F3 | Policy: IdentityBinding consults the new fields → emits `IDENTITY_MISMATCH_SCRIPT_ORIGIN`, etc. | 2 days |

### Phase G — OAuth depth + Lure semantics + URL Forgery completion

| # | Task | Effort |
|---|---|---|
| G1 | OAuth: app age via Microsoft / Google verified-publisher API; first-seen client_id tracking via intel graph | 3 days |
| G2 | Lure semantics: page-text classifier (invoice/mailbox/document/crypto/shipping/tax/support/browser-update); action-vs-lure mismatch rule | 5 days |
| G3 | Redirect Chain Courtroom: long-wait + CTA-click loop in sandbox-render | 3 days |

### Phase H — Optional/deferred

| # | Item | Why deferred |
|---|---|---|
| H1 | BITB visual classifier (custom CNN) | Research-grade; structural rule catches ~70% already |
| H2 | Full malware detonation (CAPEv2) | Diminishing returns for phishing focus; file detonation deserves its own service if it ships |
| H3 | Multi-tenancy server wiring | Personal-use deferred indefinitely; only matters if productised |

### Phase totals

| Phase | Items | Estimated effort (one engineer focused) |
|---|---|---|
| A — one-week wins | 6 | 1.5 weeks |
| B — graph + interaction | 6 | 3.5 weeks |
| C — multi-vantage | 5 | 1.5 weeks |
| D — scam extractors | 5 | 2.5 weeks |
| E — path-level reputation | 3 | 1 week |
| F — brand registry depth | 3 | 3 weeks (mostly curation) |
| G — OAuth + lure + redirect | 3 | 2 weeks |
| H — deferred | 3 | not budgeted |
| **Total active phases A–G** | **31** | **~15 weeks of focused work** |

### Order of priority

1. **Phase A first** — cheap wins, foundation for everything else, personal profile is the single highest-value-per-day item in the entire roadmap.
2. **Phase B next** — the two killer features (graph + interaction simulation) that make the system structurally better than commercial.
3. **Phase C** — multi-vantage; closes the cloaking gap.
4. **Phases D + E + F + G** — in parallel as engineering bandwidth allows; F is mostly curation work (brand-seeder time, not Go time).
5. **Phase H** — only if specific signal requires it.

### Engineering rules for this phase plan

1. **Every new policy stage emits orthogonal reason codes.** No lumping into legacy codes like `BRAND_CLAIM_DOMAIN_MISMATCH`.
2. **No new code that bypasses the staged policy.** Even fast-path short-circuits return through `policy.Apply()` so the decision-flow is reproducible.
3. **Intel-graph node writes are best-effort, not blocking.** A failed graph write must not abort a verdict response.
4. **Personal profile is per-user.** Schema lives next to `users` table even though current deploy is single-user — design for multi-user even if multi-tenancy server wiring is deferred.
5. **Interaction simulation has its own service endpoint** (`POST /interact` on sandbox-render) so it's opt-in per-scan, not the default.
6. **Every Phase exit gate measured by `make eval` against stratified test sets** — no "I think it's better".

---

## 22. Multi-mode + content-safety extension (2026-05-27)

Extends the engine from "security only" to **security + content + identity + privacy + child policy** in one staged-policy framework, with mode-based verdict mapping.

### 22.1 Modes (replace single `paranoid_mode` flag)

Schema: `users.mode TEXT NOT NULL DEFAULT 'normal'` with allowed values:

| Mode | Audience | Verdict tightening |
|---|---|---|
| `normal` | default adult | Block proven bad, warn suspicious, allow normal |
| `strict` | cautious adult | Block suspicious login/payment/download/adult/scam |
| `child` | <13 | Allow educational/curated; block adult/chat/gambling/drugs/violence/scams |
| `teen` | 13–17 | Block adult/gambling/drugs/malware/scams; warn social/chat |
| `school` | minor on managed device | Learning + docs + safe search; block distractions |
| `work` | corporate device | Block malware/phishing/scam/risky download/piracy/gambling/adult |
| `executive` | high-target adult | Isolate unknown sensitive pages; stricter OAuth/payment |
| `paranoid` | high-value target | Default-isolate unknown; block first-seen sensitive |
| `allowlist` | young children | Only approved domains/apps; everything else blocked |
| `lockdown` | emergency | Only preapproved essentials; no downloads, no new domains |

Each mode is a YAML policy file mapping `(grade, page_class, category, threat_signals) → verdict`. One engine, many policies.

### 22.2 New verdict states (extends ALLOW/WARN/BLOCK/ISOLATE)

| Verdict | Use case |
|---|---|
| `REQUIRE_APPROVAL` | Child mode hit a new domain → parent must approve before allow |
| `DETONATE` | Download in flight; wait for sandbox file analysis before deciding |
| `ALLOW_TEMP` | Time-limited approval (parent grants 1 hour for a specific URL) |

### 22.3 Content-safety threat classes (additive to security)

| Class | Detection approach | Realistic coverage |
|---|---|---|
| Adult content | StevenBlack + OISD + Cloudflare 1.1.1.1 Family lists | 75–85% |
| Gambling | Curated lists + path patterns | 80–90% |
| Drugs / weapons marketplaces | Tor exit + curated lists | 60–75% |
| Piracy / crack sites | hagezi DNS blocklists + heuristics | 70–85% |
| Browser-notification abuse | NextDNS lists | 75–85% |
| Ad / malvertising | EasyList / uBO filter lists | 90%+ |
| Privacy / fingerprinting | EasyPrivacy + EFF Privacy Badger lists | 85%+ |
| Dark patterns | Structural detection (forced-subscription DOM patterns) | 50–65% |
| Adult content on general sites | NSFW.js TensorFlow model on screenshots | 60–75% |
| **Grooming risk** | Heuristic: anonymous-chat / random-video-chat / dating-for-minors known sites | 50–65% |
| **Self-harm content** | Conservative known-community blocks; do NOT classify-and-block (false positives are actively harmful — blocking suicide prevention resources is real risk) | 40–55% |
| Eating-disorder communities | Conservative known-community blocks | 40–55% |
| Extremism / radicalization | GIFCT public hashes + curated lists | 50–70% |
| Misinformation | **Skip.** No reliable consensus; automated systems fail badly here. | n/a |
| AI abuse (deepfake/nudify) | Weekly-refreshed curated lists from MIT/Stanford research | 60–75% |

### 22.4 Honest tier classification

| Threat surface | Solidness with full implementation |
|---|---|
| Phishing / OAuth / credential theft / payment theft | **Top-tier** (~85–92%) — beats most commercial for personal use |
| Malware / drive-by / HTML smuggling | **Top-tier** (~85–92%) |
| Scam / fake support / wallet drainers | **Top-tier with Phase D extractors** (~80–88%) |
| Cloaking / redirect abuse | **Top-tier with Phase C multi-vantage** (~75–85%) |
| Adult / gambling / piracy categorisation | **Mid-tier** (~75–85%) — matches free DNS-family products |
| Grooming / self-harm / eating-disorder | **Below commercial** (~50–65%) — Bark/Qustodio win here with their ML |
| Misinformation | **Don't attempt** |

### 22.5 Where the architecture explicitly does NOT compete

Honesty about boundaries:
- **Mobile coverage** — browser-only; doesn't cover Discord/Roblox/Snapchat where grooming actually happens
- **In-app messaging** — same
- **Self-harm content classification** — too risky to false-positive; rely on known-community lists
- **Misinformation** — politically charged, no consensus, automated systems fail
- **Cross-platform parental oversight** — Bark and Qustodio do this; needs OS-level agent we don't have

The product positioning is: **best-in-class for security threats + URL/category safety in the browser; complementary to (not replacement for) Bark/Qustodio if a family wants behavioural monitoring across apps**.

### 22.6 Phase I — Multi-mode + content safety (adds to Phases A–G)

| # | Task | Files | Effort |
|---|---|---|---|
| I1 | Mode column on users + per-mode YAML policy files (`modes/normal.yaml`, `modes/child.yaml`, etc.) | migration 0010 + `internal/mode/` package + 10 YAML files | 3 days |
| I2 | Three new verdict constants (`REQUIRE_APPROVAL`, `DETONATE`, `ALLOW_TEMP`) wired into `policy.Apply()` | policy.go + reasons.go | 1 day |
| I3 | Category blocklist ingest (StevenBlack, OISD, Cloudflare, AdGuard Family, hagezi, EasyList, EasyPrivacy) into `feed_entries` with `category` column | new scheduler job + migration | 3 days |
| I4 | Category lookup in policy as Stage F.6 — emits `ADULT_CONTENT_CATEGORY`, `GAMBLING_CATEGORY`, etc. | policymap.go + reasons.go | 2 days |
| I5 | Approval queue + portal UI — pending approvals visible to admin; click-to-approve releases URL with TTL | new `approvals` table + portal-api endpoint + portal UI | 5 days |
| I6 | Per-mode interstitial pages in extension — `category_block.html`, `approval_pending.html`; mode selector in options | extension JS + HTML | 3 days |
| I7 | NSFW.js TensorFlow image classifier in sandbox-render for borderline content screening (only invoked when category lookup is uncertain) | sandbox-render Python + TF model download | 3 days |
| I8 | Curated harmful-community lists (anonymous-chat, dating-for-minors, known self-harm/ED forums) bundled in `data/child-safety/` | YAML curation | 2 days |
| **Phase I total** | | | **~3 weeks** |

### 22.7 Updated total roadmap

| Phase | Items | Effort |
|---|---|---|
| A — one-week wins | 6 | 1.5 weeks |
| B — graph + interaction | 6 | 3.5 weeks |
| C — multi-vantage | 5 | 1.5 weeks |
| D — scam extractors | 5 | 2.5 weeks |
| E — path-level reputation | 3 | 1 week |
| F — brand registry depth | 3 | 3 weeks |
| G — OAuth + lure + redirect | 3 | 2 weeks |
| **I — multi-mode + content safety** | **8** | **3 weeks** |
| **Active phases A–I total** | **39** | **~18 weeks of focused work** |

### 22.8 Engineering principle (extends §21)

The new principle: **one engine, many policies**. The verdict logic stays in `policy.Apply()`; the per-mode tightening lives in YAML config tables consulted at the final Stage G mapping. Adding a new mode (`student`, `parent-monitored`, etc.) is a YAML file, not a code change.

The core rule:
> No sensitive action, harmful content class, unknown download, or child-risk interaction proceeds unless the site proves enough trust for the active mode.

---

## 23. Bypass resistance + action control (2026-05-27 second addendum)

The web-only detection ceiling. Once a user can install another browser, run DoH or VPN, use a mobile phone, or open links in an in-app webview, web-only protection is defeated. Closing those holes requires escalation to OS-level + per-action verdicts. Also captures the strongest architectural insight in the project: **stop classifying websites; control actions.**

### 23.1 The action-control model (architectural shift)

Current verdict signature:
```
policy.Apply(url, page_class, mode) → {ALLOW | WARN | BLOCK | ISOLATE}
```

Action-control signature:
```
policy.Apply(url, action, page_class, mode, profile) → verdict
```

Where `action` ∈ `{read, login, password_step, mfa, payment, oauth_consent, new_account, download, upload, chat, dm_strangers, camera, mic, location, notification, wallet_connect, peer_connection, terminal_command, install_extension, install_app}`.

The same URL can return different verdicts per action. Examples:

| URL | read | login | payment | download | chat | new_account |
|---|---|---|---|---|---|---|
| `github.com` | ALLOW | conditional (profile) | BLOCK | DETONATE per-file | REQUIRE_APPROVAL (child) | REQUIRE_APPROVAL (child) |
| `your-real-bank.com` | ALLOW | ALLOW (in profile) | ALLOW | DETONATE | n/a | REQUIRE_APPROVAL (child) |
| `your-real-bank.com` impersonator | ALLOW | BLOCK | BLOCK | BLOCK | n/a | BLOCK |
| `discord.com/channels/.../invite/...` | ALLOW | conditional | n/a | BLOCK | REQUIRE_APPROVAL (child) | REQUIRE_APPROVAL |

Action detection in the extension:
- `<form>` submit with password field → `login` (or `password_step` if it follows username step)
- form with payment fields → `payment`
- OAuth provider domain + `client_id` param → `oauth_consent`
- "sign up" / "register" / "create account" button click or path → `new_account`
- `<a download>` click or programmatic download → `download`
- `<input type=file>` selection + submit → `upload`
- `getUserMedia({video: true})` → `camera`
- `getUserMedia({audio: true})` → `mic`
- `geolocation.getCurrentPosition` → `location`
- `Notification.requestPermission` → `notification`
- `RTCPeerConnection` → `peer_connection`
- WalletConnect URI / `eth_sign` / `eth_sendTransaction` → `wallet_connect`
- Clipboard write of cmd/PS pattern → `terminal_command`
- Chrome Web Store install button → `install_extension`
- Protocol launch (`ms-appinstaller:`/`steam:`/`tg:`/`zoommtg:`) → `install_app`

### 23.2 OS-level agent (the bypass-resistance answer)

Web-only fundamentally cannot defend against:
- Child opens Firefox Portable from USB
- Child uses mobile phone instead of monitored laptop
- Child clicks link in Discord's in-app browser
- DoH-using malware that bypasses DNS filter
- Compromised router redirecting traffic
- User-installed root CA tampering with TLS
- Local hosts-file modification

Only an OS-level agent closes these. Recommended personal-use architecture (one household, $50 hardware + free software):

```
┌──────────────────────────────────────────────────────────┐
│ Per-device agent (Go single binary)                      │
│ ├ Local DNS proxy (listens on 127.0.0.1:53)              │
│ ├ Blocks DoH endpoints in TLS SNI                        │
│ ├ Blocks Tor exit-list IPs (dan.me.uk hourly refresh)    │
│ ├ Blocks commercial VPN endpoint IP ranges               │
│ ├ App inventory (which app made which connection)        │
│ ├ Enforces resolv.conf / NetworkExtension / Registry     │
│ ├ Tamper-watch on agent binary, policy, hosts file       │
│ └ Pulls signed policy bundle (Ed25519) from XGG server   │
│                                                          │
│ Always-on WireGuard tunnel to home VPS                   │
│ ↓                                                        │
│ XGG engine on home VPS or Pi (DNS + Verdict + RBI)       │
└──────────────────────────────────────────────────────────┘
```

Build on existing OSS:
- Pi-hole or AdGuard Home for network-wide DNS family-blocking ($50 RPi)
- OpenSnitch (Linux) or LuLu (macOS) for app-level firewall
- WireGuard server on the same Pi for mobile devices to tunnel through
- dnscrypt-proxy for blocking DoH endpoints
- Tor exit list from dan.me.uk

### 23.3 Recursive unpacking

URL → page → iframe → download → archive → document → embedded-URL → loop.

Most products stop at depth 1–2. Personal-scale system has time budget to recurse fully:

| Wrapper | Tool | Effort |
|---|---|---|
| HTML page → embedded URLs | already done (sandbox-render) | ✅ |
| iframe → contained URLs | partial (Phase B6 iframe gating) | 🟡 |
| `<a download>` + Blob → generated file | Phase A3 runtime hooks | ⬜ |
| ZIP / RAR / 7z / TAR.GZ archive | `python-libarchive` or `py7zr` | 2 days |
| ISO / IMG / VHD container | `pycdlib` + loop-mount | 3 days |
| OneNote `.one` payload | `oletools` (msodde) | 1 day |
| Office macro extraction | `oletools` (olevba) | 1 day |
| PDF embedded URLs + JS + launch actions | `pdfid` + `pdf-parser` | 1 day |
| SVG embedded scripts and URLs | XML parser + script extraction | 1 day |
| EML / MHTML attachments | `email` stdlib + recursion | 1 day |
| HTML smuggling Blob | Phase A3 (already planned) | ⬜ |
| URL shortener (bit.ly etc) | HEAD + follow | 1 day |
| Google Cache / Translate / AMP rehost | strip wrapper + recurse | 1 day |
| ipfs:// / magnet: / tg:// / discord:// | per-scheme handler | 2 days |

### 23.4 Trusted-platform-as-container

`google.com`, `github.com`, `notion.site`, `discord.com`, `medium.com`, `sites.google.com`, `firebaseapp.com`, `vercel.app`, `netlify.app`, `pages.dev`, `workers.dev` are **platforms**, not safe origins. Each path/user/account on them is a separate trust unit.

Rule: shared-hosting domains use **path-level** reputation (not domain-level) AND require identity binding per-path:

- `github.com` → ALLOW for read
- `github.com/<any user>/<any repo>/raw/<file>` → page-class detection + file detonation (if download)
- `github.com/login/oauth/authorize?client_id=<unknown>` → OAuth check against profile
- `*.vercel.app/login` → IDENTITY UNKNOWN → ISOLATE
- `*.firebaseapp.com/signin` → IDENTITY UNKNOWN → ISOLATE
- `*.notion.site/<page>` → page-class scan, no automatic trust

Already partial: our `sharedHostingDomains` map enforces URL-exact match for these platforms in feed lookup. Action-control extends this to per-action policy.

### 23.5 Per-action modes

| Mode | What it blocks |
|---|---|
| **read-only** | login, payment, oauth, download, upload, camera, mic, notification, terminal_command, new_account, install_* |
| **no-money-movement** | payment, wallet_connect, crypto wallets, gambling, donations, gift-card pages |
| **no-downloads** | download (with allowlist exceptions) |
| **no-contact-with-strangers** | dm_strangers, anonymous chat, random video, dating, invite links, comment forms |
| **no-new-accounts** | new_account, oauth_consent for unverified apps |
| **homework** | block entertainment/social/chat categories; allow education |
| **sleep** | only allowlisted emergency/education resources |
| **isolate-unknown-media** | view unknown video/image/community pages remotely without cookies |

Each is a YAML overlay on the base mode. A child profile might be `child + homework + no-new-accounts + no-contact-with-strangers`.

### 23.6 Bypass-resistance specifics (new phases)

**Phase J — Action-control model** (~1 week)

| # | Task | Effort |
|---|---|---|
| J1 | Add `action` field to verdict request, default `read` for backward compatibility | half day |
| J2 | Extension detects action types (12 listed above); maps to enum | 2 days |
| J3 | Policy gains action × mode decision table (YAML) | 1 day |
| J4 | Per-action reason codes (`BLOCKED_PAYMENT_ON_NON_PROFILE_BRAND`, `LOGIN_OUTSIDE_USER_PROFILE`, etc.) | 1 day |
| J5 | Submit-time recheck — action detected post-DOMContentLoaded → re-verdict | 2 days |

**Phase K — OS-level network agent** (~6–10 weeks for Linux/macOS, ~14 weeks for Windows)

| # | Task | Effort |
|---|---|---|
| K1 | Single-binary Go agent skeleton: local DNS proxy on 127.0.0.1:53 | 1 week |
| K2 | Block DoH endpoints (Cloudflare/Google/Quad9/AdGuard/NextDNS DoH URLs) in TLS SNI | 1 week |
| K3 | Block Tor exit IPs (dan.me.uk hourly fetch) | 3 days |
| K4 | Block commercial VPN endpoint ranges (Proton/Nord/ExpressVPN public lists) | 3 days |
| K5 | App inventory: Linux `nftables`/eBPF, macOS NetworkExtension, Windows WFP | 3 weeks Linux; 4 weeks macOS; 8 weeks Windows |
| K6 | Force-resolv.conf / Configuration-Profile / Registry policy enforcement | 1 week per platform |
| K7 | Hosts-file watcher (detect tampering) | 2 days |
| K8 | Signed policy bundle (Ed25519) + auto-pull from XGG server | 1 week |
| K9 | Tamper alerts: agent disabled, extension disabled, hosts file changed, root CA installed | 1 week |
| K10 | WireGuard server config on home VPS for mobile devices | 2 days |

**Phase L — Recursive unpacking** (~3 weeks)

| # | Task | Effort |
|---|---|---|
| L1 | Archive recursion (zip / 7z / tar / iso / img) via Python libs | 1 week |
| L2 | Office macro + embedded-URL extraction (`oletools`) | 3 days |
| L3 | PDF embedded-URL + JS + launch-action (pdfid/pdf-parser) | 2 days |
| L4 | OneNote payload extraction | 2 days |
| L5 | SVG script + URL extraction | 1 day |
| L6 | EML/MHTML attachment recursion | 2 days |
| L7 | Protocol-scheme handlers (`ipfs://`, `magnet:`, `tg://`, `discord://`, `ms-appinstaller:`) | 3 days |
| L8 | URL-shortener / Google-cache / Translate / AMP unwrap | 2 days |

### 23.7 Updated total roadmap

| Phase | Items | Effort |
|---|---|---|
| A — one-week wins | 6 | 1.5 weeks |
| B — graph + interaction | 6 | 3.5 weeks |
| C — multi-vantage | 5 | 1.5 weeks |
| D — scam extractors | 5 | 2.5 weeks |
| E — path-level reputation | 3 | 1 week |
| F — brand registry depth | 3 | 3 weeks |
| G — OAuth + lure + redirect | 3 | 2 weeks |
| I — multi-mode + content safety | 8 | 3 weeks |
| **J — action-control model** | **5** | **1 week** |
| **K — OS-level agent (Linux + macOS)** | **10** | **10 weeks** |
| **K-win — Windows agent** | (subset of K10) | **+4 weeks** |
| **L — recursive unpacking** | **8** | **3 weeks** |
| **Active phases A–L total** | **62** | **~32 weeks (Linux + macOS); ~36 weeks with Windows** |

### 23.8 Hard ceiling — what still can't be solved

Honest list of attacks that survive even the full stack:

| Attack | Reason it survives |
|---|---|
| Child with full device admin access | They can always disable the agent, flash a new OS, boot from USB |
| iOS — non-WebKit browsers, in-app webviews | Apple forbids non-WebKit engines (except very recent EU); real visibility needs MDM |
| Grooming on Discord / Roblox / Instagram DMs | The harmful conversation never traverses a URL we can see; Bark-style monitoring is a separate (privacy-heavy) product |
| Misinformation | No reliable automated classification |
| Air-gapped harm (kid borrows friend's phone) | Outside our network |
| Determined adult target | A motivated technical attacker can always exfiltrate something |

These are the *honest ceiling*. Anyone claiming a complete solution to these is selling marketing.

### 23.9 The actual final architectural principle

> Stop thinking *"website classification"*. Think *action control*.
> A site may be allowed for reading, blocked for login, isolated for downloads, and require approval for chat or payment.
> Decide at the granularity of (URL, action, profile, mode), not at the granularity of (URL).

This is the single architectural commitment that distinguishes a product worth using from a glorified blocklist. Every other improvement in the plan eventually serves this principle.

---

## 24. ARCHITECTURE LOCK (2026-05-27 — final)

### 24.1 Product identity (locked)

**XGenGuardian = Personal Secure Web Gateway (PSWG) + browser-side enforcement.**

A single-tenant, self-hosted, per-user web-layer security service. Deployed on a small dedicated VPS per user. Devices route through it via WireGuard + browser extension.

**XGG explicitly does NOT:**
- run on the user's OS as a kernel-level agent
- observe processes, file writes, syscalls, memory, persistence
- replace an EDR

**xhelix is the EDR. Integration is via defined API endpoints (§24.5), not source-level merging.** XGG ships standalone today; xhelix wiring is a config flag away.

### 24.2 Layer scope (locked — never build below this line)

| Layer | Owned by |
|---|---|
| 1. Identity / MFA / password manager | external |
| 2. Network DNS + gateway | **XGG-DNS** |
| 3. Web access verdicts + remote isolation | **XGG-Core / XGG-Sandbox / XGG-Visual / XGG-RBI** |
| 4. Browser-side enforcement (extension) | **XGG-Ext** |
| 5. OS / kernel EDR | **xhelix** (integrate later, never replicate) |
| 6. Firmware / measured boot / TPM | external |

### 24.3 Deployment model (locked)

**Per-user dedicated VPS.** Not home Pi. Not shared multi-tenant (initially).

- Reference target: Hetzner CX22 (€4.50/mo, 2 vCPU, 4 GB RAM, 40 GB)
- WireGuard server provisioned per user; all user devices tunnel in
- Postgres + Redis + MinIO + the 5 XGG services co-resident
- Latency target: ≤ 50 ms one-way between user and their VPS

Rationale: home-Pi was rejected because (a) home internet outages kill protection, (b) mobile coverage requires fragile dyndns + port-forward, (c) doesn't scale to a product, (d) users won't manage hardware.

### 24.4 Honest security level WITHOUT xhelix

| Phase | XGG-alone coverage |
|---|---|
| Pre-compromise (URL detection, phishing, scam, drive-by, OAuth) | **~85%** of top-tier |
| Post-compromise (process / file / persistence / memory / C2) | **~20%** of top-tier |

**Without xhelix the unfillable gaps are:**
- Process-tree attribution
- Persistence detection (cron / systemd / login items)
- Credential file access (browser profile, SSH keys, shadow file)
- In-memory C2 and reverse shells
- Real tamper resistance (user disables extension or changes DNS)
- Per-process egress policy

**XGG covers the prevention surface (where most threats are stopped). xhelix covers the post-compromise surface (what survives prevention).** Defense in depth requires both; XGG-alone is still genuinely strong consumer-grade protection.

### 24.5 xhelix integration contract (locked API surface; build empty stubs now)

OpenAPI spec lives at `docs/api/xhelix-bridge.yaml`. Endpoints return `501 Not Implemented` with `X-XHelix-Status: not-configured` until wiring is enabled by config. **These endpoints' shapes are frozen; once committed they don't change.**

| Endpoint | Dir | Purpose |
|---|---|---|
| `POST /v1/xhelix/egress/block` | XGG → xhelix | Kernel cgroup_sock_addr block for host/pid/TTL |
| `POST /v1/xhelix/egress/release` | XGG → xhelix | Reverse of above |
| `POST /v1/xhelix/verdict/notify` | xhelix → XGG | "Saw connect attempt; give me verdict" |
| `GET /v1/xhelix/host/context` | XGG → xhelix | Process-tree + recent-syscall enrichment |
| `POST /v1/xhelix/evidence/correlate` | XGG → xhelix | Tie URL-action chain to on-host activity |
| `GET /v1/xgg/intel/domain/{domain}` | xhelix → XGG | XGG's domain knowledge |
| `POST /v1/xgg/intel/ioc` | xhelix → XGG | Add IOC to graph (wallet/webhook/cert/hash/process) |
| `GET /v1/xgg/intel/correlate/{type}/{value}` | both | Query infra graph |
| `POST /v1/xgg/policy/get` | xhelix → XGG | Current mode + profile |
| `POST /v1/xhelix/policy/health` | XGG → xhelix | Agent alive / tamper status / heartbeat |

### 24.6 Things explicitly DELETED from prior plan (now xhelix-owned)

| Was in plan | Removed because |
|---|---|
| Phase K — build OS-level network agent | xhelix already is one |
| Phase K — Linux/macOS/Windows binaries | xhelix-only (Linux); macOS/Windows wait for separate product or commercial EDR |
| Build process-tree attribution | xhelix has `pkg/proctree` |
| Build host tamper detection | xhelix has `pkg/tamperguard`, `pkg/selfprotect` |
| Build hash-chained evidence ledger | xhelix has `pkg/chain` — XGG evidence_id will eventually become a node in xhelix's ledger |
| Build persistence detection | xhelix has `pkg/persistencewatch` |
| Build LOLBin classifier | xhelix has `pkg/lolbin` |
| Build kernel-level egress policy | xhelix has `pkg/enforce` / `pkg/egress` / cgroup_sock_addr |
| Build NRD service (already partly in xhelix) | consolidate; XGG keeps RDAP age but feeds NRD through xhelix when integrated |

Estimated effort saved by not building these: **~14–18 weeks**.

### 24.7 Things that stay in XGG (web-layer, never overlap xhelix)

- Staged policy engine (Stages A–G) — *web-layer decision logic*
- Page-class classifier
- Personal brand/destination profile (§22.6 R)
- Per-action verdict model (Phase J)
- Sandbox-render with Playwright + YARA + sink instrumentation
- Visual match with CLIP + pHash
- RBI gateway (remote browser isolation)
- Mode-based policy tables (normal / strict / child / teen / school / work / executive / paranoid / allowlist / lockdown)
- Browser extension (verdict polling, popup matrix, tabnabbing, action detection)
- DNS resolver service (category blocklist + feed sinkhole)
- Infrastructure graph (web-side IOCs: domains/IPs/certs/favicons/webhooks/wallets/phones)
- Feed ingest (URLhaus, PhishTank, OpenPhish, PhishDB) — XGG remains canonical owner since this is web-layer
- Threat-intel correlation — graph-level overlaps with xhelix's intel pkg; reconcile at integration time
- Brand registry as policy database
- RDAP for domain age (XGG owns this; xhelix's NRD becomes a consumer)
- Multi-vantage cloaking diff
- Interaction simulation (canary credentials in sandbox)
- Recursive unpacking (URL → page → archive → doc → URL)

### 24.8 Roadmap reset (clean)

Old phases A–L collapse and re-prioritise around the locked architecture. Final plan:

| Phase | Items | Effort | Lock status |
|---|---|---|---|
| **0. Architecture lock** (this doc) | — | 1 day | ✅ done today |
| **1. Per-user VPS provisioning recipe** | docker-compose + WireGuard + Terraform | 1 week | next |
| **2. Phase A (one-week wins)** | personal profile, ClickFix content, HTML smuggling runtime, reputation inversion, URL forgery, tiered wait | 1.5 wk | next |
| **3. Phase J (per-action model)** | action enum + extension detection + policy table | 1 week | next |
| **4. xhelix-bridge API spec + stub endpoints** | OpenAPI + 10 endpoints returning 501 | 3 days | next |
| **5. Phase B (graph + interaction)** | infra graph + canary simulation + QR | 3.5 wk | core |
| **6. Phase C (multi-vantage)** | 3 cloud egress + diff | 1.5 wk | core |
| **7. Phase D (scam extractors)** | crypto drainer + fake support + lure semantics | 2.5 wk | core |
| **8. Phase E (path-level reputation)** | per-path fingerprint store | 1 wk | core |
| **9. Phase F (brand registry depth)** | per-class allowed origins | 3 wk (curation) | core |
| **10. Phase G (OAuth + lure + redirect courtroom)** | | 2 wk | core |
| **11. Phase I (multi-mode + content safety)** | 10 modes + category feeds + approval workflow + new verdicts (REQUIRE_APPROVAL/DETONATE/ALLOW_TEMP) | 3 wk | core |
| **12. Phase L (recursive unpacking)** | archive/Office/PDF/SVG/EML | 3 wk | core |
| **13. RBI gateway (real isolation)** | CDP + WebRTC streaming on top of sandbox-render | 2 wk | core |
| **14. xhelix wiring** | implement the 10 stub endpoints against real xhelix daemon | 4 wk | post-core |

**Active phases 1–13 (standalone, pluggable): ~28 weeks of focused work**
**Phase 14 (xhelix integration): +4 weeks when ready**

### 24.9 Engineering rules (these override anything written earlier)

1. **No XGG code in xhelix's scope.** If a feature requires kernel / process / file visibility, it stops at the xhelix-bridge endpoint and waits for integration.
2. **xhelix-bridge endpoint shapes never change after this commit.** Adding fields is OK; renaming or removing is forbidden.
3. **Per-user VPS is the deployment unit.** No code assumes home-network LAN, dynamic DNS, or shared hardware.
4. **No multi-tenancy in core (yet).** Single-tenant is locked. Multi-tenant migration is a separate phase if/when productised.
5. **Threat-intel / IOC graph stays in XGG.** xhelix consumes our graph via `GET /v1/xgg/intel/...`. Don't fork the data.
6. **OS-level features the user asks for ALWAYS get answered "that's xhelix's job."** Including: tamper detection, kernel egress block, process attribution, file integrity, persistence.

---

## 25. TL;DR for someone joining the team

**The strategy: don't compete on feed scale; compete on slow, adversarial, evidence-based verification.** Commercial tools decide in milliseconds at billion-URL scale. We can spend seconds-to-minutes per *suspicious* URL on a tiered ladder. That asymmetry is the whole game.

- Four verdicts. ISOLATE is real.
- Every popup gets its own verdict request. Unknown popups from anywhere get held on `holding.html` and scanned. Popups from already-blocked openers are blocked without scan.
- Trust registry with A+→F+ grades and a real TTL matrix; sensitive page classes (login/payment/oauth/admin/download) have hard short TTL caps.
- The universal phishing rule (visual match + non-canonical domain + age/ASN/issuer mismatch) is the heart of detection and is already implemented — finish wiring RDAP so it actually fires.
- Behavioral abuse detection is the largest detection gap; add it in Phase 2.
- Build multi-tenancy now even with one tenant.
- Every block ships with reason codes. No mystery blocks.
