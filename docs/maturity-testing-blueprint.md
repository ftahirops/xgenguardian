# XGenGuardian Maturity Testing Blueprint

This document defines the test strategy required to move XGenGuardian from a strong prototype to a stable, NextDNS-class operational system.

The goal is not "no bugs." The goal is:

```text
No hangs.
No silent failures.
No unexplained verdicts.
No irreversible false blocks without strong evidence.
Every false result becomes a regression test.
Every slow path has a bounded timeout and a user-visible escape.
```

## 1. Maturity Principles

| Principle | Meaning |
|---|---|
| External intelligence first | Known-bad feeds, DNS reputation, malware feeds, and blocklists should catch known threats cheaply. |
| XGG action proof second | Even if external systems say clean, XGG must verify sensitive actions: login, payment, OAuth, command copy, support phone, download. |
| Never hang | Extension holding, API calls, sandbox render, and portal evidence views must all exit with a bounded outcome. |
| Unknown is not always block | Unknown normal browsing can allow/warn; unknown sensitive action should isolate, require approval, or deep scan. |
| Positive trust must be scoped | A CDN domain can be trusted for scripts, not for login. Stripe can be trusted as a payment sink, not as page identity. |
| Every FP/FN becomes data | Any user-reported false positive or false negative must become a permanent corpus item. |
| Results must be explainable | Every block/warn/isolate needs reason codes, evidence, and a human-readable explanation. |

## 2.5 Handler Invariant (the bug class that hangs production)

The dominant cause of "extension hung" reports between v0.2.0 and v0.3.1 was a single anti-pattern:

```js
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.kind === "resolve") {
    (async () => {
      const verdict = await fetchVerdict(msg.target);   // may throw
      const key = await sha256(msg.target);             // may throw
      await chrome.storage.session.set({ [key]: v });   // may throw
      sendResponse({ verdict });                        // unreachable on error
    })();
    return true;                                        // says "I will respond"
  }
});
```

When anything inside the IIFE throws, the catch swallows it, `sendResponse` is never called, and Chrome leaves the message channel open forever. The holding page spins indefinitely.

**Invariant:** Every async listener callback registered with `chrome.runtime.onMessage`, `chrome.webNavigation.*`, or `chrome.tabs.*` MUST either:

1. call `sendResponse` exactly once in EVERY branch including the catch arm, OR
2. return `false` synchronously (no response expected, channel closes immediately).

A code path that `return true`s and then can fail without calling `sendResponse` is a release blocker.

**Enforcement:**

| Layer | Tool | Action |
|---|---|---|
| Author-time | ESLint plugin (custom rule `xgg/always-respond`) | Fails CI if a handler returns `true` without a corresponding `sendResponse` in every try/catch branch |
| Test-time | `tests/extension/handler-invariant.spec.ts` | For every registered listener: inject 5 synthetic errors (throw in fetch, throw in storage, throw in crypto, return undefined, sendResponse called twice) and assert each ends with exactly one response within 9s |
| Run-time | `console.warn("[xgg] handler crashed:", e)` in every catch | Telemetry counts handler crashes; alert if rate >0.1 / minute |
| Fail-safe | All handlers fall back to `sendResponse({ verdict: { verdict: "ALLOW", reason: "verification_error" } })` on crash | User is never trapped |

**Why fail-OPEN on crash:** the worst outcome of a crashed handler is the user being allowed onto a page that should have been blocked. The worst outcome of a fail-CLOSED crash is the user being trapped forever, unable to access any page, and uninstalling the extension. Telemetry catches the open-on-crash; uninstalls cannot be undone.

This invariant generalizes to verdict-api Go handlers as well — every HTTP handler must end with `w.WriteHeader` + `w.Write` in every branch, never a bare `return`.

## 2. Release Gates

No extension/API/resolver release should ship unless these pass:

```bash
go test -race ./...
go test ./...
pytest services/sandbox-render/tests
make extension-e2e
make fp-bench
make malicious-bench
make chaos-test
make ui-evidence-test
```

Minimum release criteria:

| Gate | Required Result |
|---|---|
| Extension holding-page test | zero indefinite spinners |
| Backend dependency chaos | no crashes, no unbounded waits |
| Evidence UI | no broken images, no unreadable pages |
| Benign corpus | false-positive rate below release threshold |
| Malicious corpus | recall above release threshold |
| Race test | zero Go data races |
| Raw-IP scenarios | public IPs aggressively scanned; local/operator IPs handled by policy |
| Wrapper URLs | SafeLinks/Proofpoint/Mimecast/etc. unwrap or bypass safely without hanging |
| Reason codes | every verdict has stable reason codes or explicit "unknown" reason |

## 3. Single Command Target

Add one top-level target:

```bash
make maturity-test
```

It should run:

1. unit tests,
2. race tests,
3. resolver integration tests,
4. verdict API integration tests,
5. sandbox mocked tests,
6. Chrome extension E2E tests,
7. benign corpus,
8. malicious corpus,
9. chaos tests,
10. evidence UI screenshot tests,
11. performance budget checks.

The report must include:

```text
benign allow rate
benign warn/isolate/block rate
malicious block/warn/isolate rate
false positives by reason code
false negatives by category
slowest URLs
timeouts
extension hangs
broken evidence pages
dependency failures
policy-version drift
```

## 4. DNS Resolver Test Matrix

DNS tests should use a fake upstream DNS server, fake Redis, and controlled block/allow lists. Resolver is not currently the hot path (extension talks directly to verdict-api), but these tests are required before resolver becomes the production DNS termination point.

| Case | Input | Expected | Status |
|---|---|---|---|
| clean A record | `example.com A` | upstream answer | **TODO** |
| clean AAAA record | `example.com AAAA` | upstream answer | **TODO** |
| strict blocklist | domain in `blocklist:strict` | NXDOMAIN/block | **TODO** |
| weak blocklist | domain in `blocklist:weak` | resolves but logs WARN | **TODO** |
| never-block | bank/payment/gov domain | always upstream | **TODO** |
| allowlist exact | domain in allowlist exact set | upstream | **TODO** |
| allowlist Bloom false hit | Bloom hit but Redis miss | not automatically allow | **TODO** (Bloom NYI) |
| strict Bloom false hit | Bloom hit but Redis miss | not automatically block | **TODO** (Bloom NYI) |
| shared hosting apex | `github.io`, `pages.dev`, `netlify.app` | never punish apex from tenant abuse | SHIPPED (`isSharedHosting`) |
| bad shared tenant | `evil.github.io` | tenant verdict only | SHIPPED |
| CNAME to private IP | public domain CNAMEs to `192.168.1.10` | rebind filter drops private answer | **TODO** |
| A to private IP | public domain returns RFC1918 A | NXDOMAIN or stripped answer | **TODO** |
| AAAA ULA/private | public domain returns private IPv6 | stripped answer | **TODO** |
| DNS upstream timeout | upstream unavailable | bounded SERVFAIL or configured fail-open | **TODO** |
| Redis down | Redis unavailable | local Bloom still works; no crash | **TODO** |
| verdict-api down | API unreachable | bounded behavior, no DNS hang | SHIPPED v0.3.2 (context timeout 500ms) |
| huge QNAME | max-length/near-max QNAME | safe reject or bounded processing | SHIPPED (Go DNS lib bounds) |
| IDN/punycode | `xn--...` | normalized before policy | PARTIAL (`domainFromURL` lowercases; full IDN normalization TODO) |
| mixed-case query | `PaYpAl.com` | case-insensitive policy | SHIPPED |
| TXT/MX query | blocked domain TXT/MX | policy consistent by qtype | **TODO** |
| NXDOMAIN real site | upstream NXDOMAIN | no false XGG block claim | SHIPPED v0.2.6 (vendordns baseline) |
| reload Bloom | SIGHUP reload during traffic | no data race, no panic | **TODO** (Bloom NYI) |
| chunk-boundary list load | line split across read buffer | no corrupt domain entries | **TODO** |

**Required fix when resolver lands:** blocklist loading must use `bufio.Scanner` or `bufio.Reader`, not arbitrary chunk splitting (caught the row-26 case in a peer product, where a 64KB read boundary split a domain across two reads).

## 5. Verdict API Test Matrix

Every rule path must have direct tests and full pipeline tests.

### 5.1 Reputation And Feed Tests

| Case | Expected | Status |
|---|---|---|
| URLhaus hit | BLOCK immediately | SHIPPED v0.2.0 |
| OpenPhish + PhishDB hit | BLOCK immediately | SHIPPED v0.2.0 |
| one weak/community feed hit | WARN or deep scan, not always block | SHIPPED v0.2.5 (single-medium = WARN) |
| external feeds all clean | lower risk only, not full proof | SHIPPED |
| feed timeout | degrade without crash | SHIPPED (2s context timeout) |
| stale feed entry expired | no block after expiry | SHIPPED (14d cutoff in queryFeedHit) |
| feed hit on shared host apex | no apex-level block | SHIPPED (isSharedHosting) |
| feed hit on shared tenant | tenant block | SHIPPED |
| feed hit on URL with empty category (security) AND content category enabled by user | security wins, not stripped | SHIPPED v0.3.0 (cross-categorial fix) |
| 1 high-confidence + 0 medium = BLOCK | corroborates §F.1 rule | SHIPPED v0.2.5 |
| 0 high + 2 medium = BLOCK consensus | corroborates §F.1 rule | SHIPPED v0.2.5 |
| 0 high + 1 medium + fresh domain = BLOCK | corroborates §F.1 promotion | SHIPPED v0.2.8 |

### 5.2 Sensitive Page Tests

| Case | Expected | Status |
|---|---|---|
| `/login` on unknown domain | Tier-2 required | SHIPPED v0.3.1 (pageclass.IsSensitive forces Tier-2) |
| `/signin` on unknown domain | Tier-2 required | SHIPPED v0.3.1 |
| `/billing` on unknown domain | Tier-2 required | SHIPPED v0.3.1 (was missing before — caused opencode.ai FP) |
| `/checkout` on unknown domain | Tier-2 required | SHIPPED v0.3.1 |
| `/oauth/authorize` | OAuth registry required | SHIPPED v0.2.0 |
| `/mfa`, `/2fa`, `/verify` | Tier-2 required | SHIPPED v0.3.1 |
| `/download` | download analysis required | SHIPPED v0.2.6 (downloads.py + page-class-aware verdict) |
| `/docs/install` | command scanner required | SHIPPED v0.2.0 (shellcmd.py) |
| sensitive + sandbox unavailable | ISOLATE or approval, not blind allow | SHIPPED v0.2.5 (`SENSITIVE_PAGE_VERIFICATION_UNAVAILABLE`) |
| sensitive + trusted identity + sandbox unavailable | allow/warn based on action-scoped trust | SHIPPED (TrustedIdentity carve-out) |
| `/billing` on trusted brand domain | ALLOW without forcing Tier-2 | SHIPPED v0.3.1 (trusted-host short-circuit) |
| Login page with multi-destination POST to known payment processor | sink rule respects IsCredentialPage; payment destinations not flagged | SHIPPED v0.3.1 |

### 5.3 Raw-IP URL Tests

DNS cannot see direct IP URLs, so browser/API must handle them.

| Case | Expected | Status |
|---|---|---|
| `http://1.2.3.4/payload.exe` | BLOCK/DETONATE | SHIPPED v0.2.0 (RawIPBinaryDrop) |
| `http://1.2.3.4/x86` | BLOCK, botnet pattern | SHIPPED v0.2.0 |
| `http://1.2.3.4/mips` | BLOCK, botnet pattern | SHIPPED v0.2.0 |
| public IP + login path | ISOLATE/BLOCK unless allowlisted | SHIPPED v0.2.0 |
| public IP + payment/admin path | ISOLATE/BLOCK unless allowlisted | SHIPPED v0.2.0 |
| public IP + normal page | force Tier-2 and warn/isolate by result | SHIPPED |
| public IP + popup opener | block/isolate | SHIPPED |
| public IP + self-signed cert | warn/isolate | PARTIAL (cert mismatch flagged; self-sign-specific TODO) |
| operator allowlisted IP | ALLOW (TrustedIdentity carve-out) | SHIPPED v0.3.1 |
| user-allowlisted IP from extension Options | bypass before verdict-api | SHIPPED v0.3.1 |
| private IP `192.168.x.x` | bypass at extension; never reaches verdict | SHIPPED v0.2.0 (shouldSkipURL) |
| private IP `10.x.x.x` | bypass at extension | SHIPPED |
| loopback `127.0.0.1`, `localhost` | bypass | SHIPPED |
| IPv6 literal | equivalent policy to public/private IPv4 | PARTIAL (basic v6 parse; full classification TODO) |
| IPv4 in decimal-only encoding (`16909060`) | normalize then classify | **TODO** |
| IPv4 in hex (`0x01020304`) | normalize then classify | **TODO** |

Public raw IPs are NEVER globally bypassed. Malware uses raw IPs to avoid DNS reputation. The Phase 7 stabilization added a `TrustedIdentity` carve-out specifically for the operator's own self-hosted IPs (via `XGG_LOCAL_TRUSTED_HOSTS`); this is the only way an unallowed raw IP can ALLOW.

### 5.4 Credential Sink Tests

| Case | Expected | Status |
|---|---|---|
| password form posts same origin | allow if identity is trusted | SHIPPED v0.2.0 |
| password form posts unknown cross-origin | BLOCK | SHIPPED v0.2.0 |
| hidden mirror field | BLOCK | SHIPPED v0.2.0 (CredentialSinkHiddenMirror) |
| pre-submit keystroke capture | BLOCK | SHIPPED v0.2.0 (CredentialSinkPreSubmitCapture) |
| multi-destination credential sink | BLOCK unless known trusted identity/payment flow | SHIPPED v0.2.0 |
| payment page posts to Stripe | allow as payment sink, not page identity | SHIPPED v0.3.1 (Stripe in trustreg) |
| payment page posts to PayPal/Braintree/Adyen/Paddle | allow as payment sink, not page identity | PARTIAL (PayPal SHIPPED; Braintree/Adyen/Paddle **TODO**) |
| login page posts to analytics domain | warn/advisory unless credentials leave trusted auth endpoint | PARTIAL (treated as multi-destination; analytics-allowlist **TODO**) |
| form action is empty/current page | normal | SHIPPED |
| JavaScript fetch sends credentials | sink analysis catches destination | SHIPPED v0.2.0 (window.__xgg_sink instrumentation) |
| WebSocket credential sink | warn/block depending identity | SHIPPED v0.2.0 (WS in capture_mode list) |
| Download page with download links to brand's own CDN | NOT flagged as cross-origin sink | SHIPPED v0.3.1 (IsCredentialPage gate) |
| OAuth init that POSTs to identity provider | recognized as OAuth, not phishing | SHIPPED v0.2.0 (oauthreg) |

Payment processors must be action-scoped:

```text
stripe.com trusted as payment sink
stripe.com not trusted as "Microsoft login" identity
```

### 5.5 Command-Copy Tests

| Case | Expected | Status |
|---|---|---|
| official install command on official docs | ALLOW | SHIPPED v0.2.0 (installreg + OfficialInstallMatch) |
| official host but modified command | WARN | SHIPPED v0.2.0 (OfficialMatchMissOnTrusted) |
| unknown host with `curl-to-shell` | WARN/approval | SHIPPED v0.2.0 (SuspiciousInstallCommand) |
| unknown host with `irm-to-iex` | WARN/approval | SHIPPED v0.2.0 |
| `mshta http://...` | BLOCK | SHIPPED v0.2.0 (MaliciousInstallCommand) |
| `rundll32 \\host\share` | BLOCK | SHIPPED v0.2.0 |
| PowerShell encoded command (-enc / -e) | BLOCK | SHIPPED v0.2.0 |
| visible text differs from clipboard text | BLOCK | PARTIAL (copy-guard runs; visible-vs-clipboard not specifically compared) |
| base64 piped to shell | WARN/BLOCK depending host | SHIPPED v0.2.0 |
| raw GitHub installer from unknown docs | WARN/approval | SHIPPED v0.2.0 |
| command from user allowlisted host | bypass (no /v1/command-check call) | SHIPPED v0.3.1 (isUserAllowlisted) |
| copy-guard fires on sensitive-class page | suppressed (don't capture login-page copies) | SHIPPED v0.2.6 |
| 1000-char cap on command sent to API | enforced | SHIPPED v0.2.6 |

### 5.6 OAuth Tests

| Case | Expected | Status |
|---|---|---|
| known Microsoft/Google/GitHub client | ALLOW | SHIPPED v0.2.0 (oauthreg) |
| unknown client with low scopes | WARN | SHIPPED v0.2.0 |
| unknown client with high scopes | BLOCK | SHIPPED v0.2.0 (OAuthUnverifiedHighScopeApp) |
| suspicious redirect URI | BLOCK | PARTIAL (redirect URI not specifically checked against brand allowlist) |
| real provider domain but unknown high-scope app | BLOCK | SHIPPED v0.2.0 |
| OAuth URL wrapped in SafeLinks | unwrap and analyze destination | PARTIAL (safelinks bypassed v0.3.2; unwrap-and-scan-destination **TODO**) |
| OAuth popup from suspicious opener | inherit opener risk | SHIPPED v0.2.0 (opener lineage) |
| accounts.google.com / login.microsoftonline.com direct nav | bypass (WELL_KNOWN_AUTH_HOSTS) | SHIPPED v0.2.3 |
| `client_id` in URL not in registry, sensitive scopes | BLOCK | SHIPPED |
| OAuth callback with malformed `state` parameter | log + ALLOW (state validation is the app's job) | SHIPPED |

### 5.7 Scam Page Tests

| Case | Expected | Status |
|---|---|---|
| fake Microsoft support + unknown phone | BLOCK | PARTIAL (FakeSupportScareware behavior detection; specific phone-extraction **TODO**) |
| fake Apple support + phone in image only | BLOCK after OCR | **TODO** (OCR not wired) |
| support page + AnyDesk/TeamViewer/RustDesk | BLOCK/WARN | **TODO** (RAT-link detector not built) |
| popup storm + phone number | BLOCK | PARTIAL (popup storm fires; phone correlation **TODO**) |
| refund page + gift card phrase | BLOCK | **TODO** (lexical detector for gift-card phrases) |
| tax page + wire/crypto payment | BLOCK | **TODO** |
| fake chat widget asks for phone/email/order | WARN/BLOCK | **TODO** |
| government logo + non-government domain | BLOCK/ISOLATE | PARTIAL (visual brand match if seeded; .gov-specific gate **TODO**) |
| same phone across 3 unrelated domains | campaign BLOCK | **TODO** (no campaign graph yet) |
| same wallet across unrelated refund pages | campaign BLOCK | **TODO** |
| popup storm + alert loop + fullscreen trap | BLOCK as scareware | SHIPPED v0.2.0 (FakeSupportScareware composite) |
| clipboard tampering | BLOCK | SHIPPED v0.2.0 (ClipboardHijackAttempt) |
| drive-by auto-download | BLOCK | SHIPPED v0.2.0 (AutoDownloadTrigger) |

### 5.8 Adversarial Input Matrix

Real attackers probe URL parsers, normalizers, and policy boundaries. These cases caught real bugs in production at peer products (Cloudflare, Microsoft Defender, Google Safe Browsing).

| Adversarial input | Expected | Status |
|---|---|---|
| Unicode NFC normalization tricks (`paypal.com` with combining accents) | NFC-normalize before homoglyph check | PARTIAL (homoglyph runs on raw lowercase; NFC step missing) |
| Emoji-in-domain (`xn--ws8h.example` ↔ 💩.example) | punycode-aware match; treat both forms identically | **TODO P1** |
| Mixed-script confusables (Latin `a` U+0061 + Cyrillic `а` U+0430) | confusables.txt mapping; canonical form for comparison | **TODO P1** |
| Bidirectional override character (U+202E) in URL | strip before display; warn on presence | **TODO P1** |
| Very long single-label (256-char SLD) | RFC-1035 cap; reject or truncate | SHIPPED (URL parse fails cleanly) |
| Zero-width char in URL fragment (`#​`) | normalize before hashing for token | SHIPPED v0.2.6 (`#` stripped) |
| URL with `\` separators instead of `/` (legacy Windows path style) | parser-level normalization | SHIPPED (`new URL()` normalizes) |
| Double-encoded params (`%2520` rather than `%20`) | decode once for display; raw-pass for forward | SHIPPED v0.3.1 (safelinks URL is this exact case) |
| Nested `data:` URI inside `url=` param | recognize as nested URL; refuse to forward | **TODO P1** |
| Userinfo in URL (`http://attacker@victim.com`) | strip before display; never log credentials | **TODO P1** |
| Port forgery (`host:80@evil.com`) | parser per WHATWG URL spec; correct host = evil.com | SHIPPED (Go and JS URL parsers handle this) |
| Right-to-left override in displayed URL | strip on render OR warn-flag | **TODO P1** |
| IPv4 in IPv6-mapped form (`::ffff:1.2.3.4`) | normalize to v4; classified as raw IP | **TODO P2** |
| IPv4 dotted-decimal vs decimal-only (`16909060` ↔ `1.2.3.4`) | normalize to dotted; classified as raw IP | **TODO P2** |
| IPv4 hex (`0x01020304`) | normalize; classified as raw IP | **TODO P2** |
| Hostname starting/ending with `.` | parser-level trim | SHIPPED (`new URL()` rejects) |
| Underscore in hostname (RFC-illegal but Chrome accepts) | classify as suspicious-hostname | **TODO P2** |
| Whitespace inside URL (`https://e xample.com`) | URL parse rejects; treat as unparseable | SHIPPED |
| Query string >100 KB | bounded read; truncate-for-log; full-pass-through to verdict-api | SHIPPED v0.3.1 (4 MB cap on sandbox responses) |
| URL path >100 KB | bounded; truncate-for-log | **TODO P2** |
| HTTP/HTTPS-mixed redirect chains | each hop verdicted; downgrade to http warn-flagged | PARTIAL |
| `javascript:`, `data:`, `file:`, `chrome:` URL schemes in user input fields | scheme allowlist (already in `isHttpURL`) | SHIPPED v0.2.4 |
| Punycode that decodes to obvious phishing brand | both forms tested against trustreg and homoglyph | PARTIAL |
| URL with > 8 hash characters used as deep-link | preserve; treat as same URL minus fragment | SHIPPED v0.2.6 |
| Same-host redirect loop (HTTP 302 → self) | bounded redirect count (sandbox-render cap) | SHIPPED |
| Adversarial Content-Type (`text/html; charset=../../../`) | strict parse; refuse invalid encoding declarations | **TODO P2** |
| HTTP response with `Content-Length: -1` | parser rejects | **TODO P2** |
| HTTP response with chunked encoding ending mid-chunk | parser bounded error | SHIPPED (Go http stdlib handles) |

Adversarial corpus lives at `tools/fp-bench/corpus/adversarial-inputs.txt`, one entry per case with expected verdict pinned.

## 6. Extension E2E Test Matrix

Use Playwright with Chromium extension loaded. Run against a fake verdict API server that can return controlled responses or hang.

### 6.1 Holding Page Reliability

| Case | Expected | Status |
|---|---|---|
| verdict returns ALLOW | navigates to target | SHIPPED v0.2.0 |
| verdict returns WARN | warn page | SHIPPED v0.2.0 |
| verdict returns BLOCK | blocked page | SHIPPED v0.2.0 |
| verdict returns ISOLATE | isolate page | SHIPPED v0.2.0 |
| verdict API hangs | manual choice UI by 12s hard deadline | SHIPPED v0.3.2 |
| verdict API returns ANALYZING | retry once, then manual choice | SHIPPED v0.3.2 |
| background service worker restarts | no indefinite spinner | SHIPPED v0.3.2 |
| `sendMessage` never resolves | manual choice by 12s hard deadline | SHIPPED v0.3.2 (Promise.race with timeout) |
| cache write throws | still routes with verdict | SHIPPED v0.3.2 (try/catch around cache; main path independent) |
| invalid URL | safe bypass or safe error page | SHIPPED v0.2.4 (isHttpURL guards) |
| giant URL (10 KB) | no crash/hang | SHIPPED v0.3.2 (verified against 695-char safelinks URL) |
| repeated navigation to same URL | no loop | SHIPPED v0.2.2 (just-verified token) |
| back button from holding | no loop | SHIPPED v0.3.2 (Go back clears timers) |
| reload extension during holding | no indefinite spinner | SHIPPED v0.3.2 (handler crash → fail-open) |
| network offline | manual choice or DNS-fail page | SHIPPED v0.3.0 |
| handler throws before sendResponse | fail-open ALLOW with `reason=verification_error` | SHIPPED v0.3.2 |
| 5 sequential attempts with all 5 timing out | still routes within 12s × 2 attempts ≈ 9s | SHIPPED v0.3.2 |

Hard invariant:

```text
No extension view may spin forever. Maximum wall-clock to UI = 12 seconds.
```

### 6.2 Wrapper URL Tests

Email security wrappers are common and long. They must not hang.

| Wrapper | Test |
|---|---|
| Microsoft SafeLinks | regional hostnames: `nam*`, `eur*`, `ind*`, `gbr*`, `apc*`, `jpn*`, `aus*`, `can*` |
| Proofpoint URL Defense | `urldefense.com`, `urldefense.proofpoint.com` |
| Mimecast | `protect-eu.mimecast.com`, `protect-us.mimecast.com`, `protect.mimecast.com` |
| Cisco Secure Email | `secure-web.cisco.com` |
| Barracuda | `linkprotect.cudasvc.com` |
| Symantec/Broadcom | `clicktime.symantec.com` |
| Sophos/Reflexion | `url.emailprotection.link`, `messages.reflexion.net` |

Expected behavior:

```text
wrapper URL -> decode destination -> scan destination -> allow wrapper redirect if destination passes
```

Do not only bypass wrappers forever. The wrapper is trusted transport, but the destination still needs classification.

### 6.3 User Allowlist Tests

| Entry | Expected | Status |
|---|---|---|
| `opencode.ai` | exact host bypass | SHIPPED v0.3.1 |
| `.mycorp.com` | subdomain bypass | SHIPPED v0.3.1 |
| `135.181.79.27` | exact IP bypass | SHIPPED v0.3.1 |
| `10.0.0.0/8` | private CIDR bypass | SHIPPED v0.3.1 (ipInCIDR helper) |
| invalid CIDR | ignored safely | SHIPPED v0.3.1 |
| comment line (`# foo`) | ignored | SHIPPED v0.3.1 |
| mixed case host | normalized to lowercase | SHIPPED v0.3.1 |
| trailing slash | ignored/normalized | SHIPPED |
| port in URL (host:8443) | host match port-agnostic | SHIPPED v0.3.1 |
| empty allowlist | normal scanning | SHIPPED |
| 1000 entries in allowlist | performance acceptable (parse + check ≤5ms) | PARTIAL (parsed every call; cache: **TODO**) |
| Allowlist updated mid-session | takes effect on next navigation | SHIPPED v0.3.1 |
| Browser sync of allowlist via `storage.local` | does not sync (intentional — `local` is per-browser) | SHIPPED v0.2.7 |

Allowlist modes should be added:

| Mode | Meaning |
|---|---|
| bypass all | no scanning, no logging |
| trust but log | do not block, still record verdict data |
| scan risky actions | allow page, still inspect downloads/commands/OAuth |
| path-only | trust only exact path prefix |
| port/IP scoped | trust only specific host:port or CIDR |

### 6.4 DNS-Fail Page Tests

| Case | Expected | Status |
|---|---|---|
| `ERR_NAME_NOT_RESOLVED` | friendly DNS-fail page | SHIPPED v0.3.0 |
| `ERR_DNS_TIMED_OUT` | friendly DNS-fail page | SHIPPED v0.3.0 |
| `ERR_CONNECTION_REFUSED` | friendly network-fail page | SHIPPED v0.3.0 |
| `ERR_CONNECTION_TIMED_OUT` | friendly network-fail page | SHIPPED v0.3.0 |
| after ALLOW then DNS fail | cache entry cleared | SHIPPED v0.3.0 |
| retry button | retries real URL | SHIPPED v0.3.0 |
| go back button | returns without loop | SHIPPED v0.3.0 |
| `chrome-error://` URL itself triggers onBeforeNavigate | skipped in shouldSkipURL | SHIPPED v0.3.0 |
| message clearly states "this is NOT an XGG block" | text matches | SHIPPED v0.3.0 |
| common causes listed (typo / Pi-hole / offline / site DNS down) | bullet list visible | SHIPPED v0.3.0 |

### 6.5 Copy Guard Tests

| Case | Expected | Status |
|---|---|---|
| normal text copy | no API call | SHIPPED v0.2.0 (shellcmd regex gate) |
| harmless command on official docs | allow | SHIPPED v0.2.0 (OfficialInstallMatch) |
| suspicious command | warning modal | SHIPPED v0.2.0 |
| hard-fail command | block modal | SHIPPED v0.2.0 |
| API timeout | fail-open (500ms budget; ALLOW on error) | SHIPPED v0.2.0 |
| repeated same command | cached verdict | PARTIAL (no client-side cache; relies on server cache) |
| visible-vs-clipboard mismatch | BLOCK | **TODO** (compare event.target.textContent vs clipboard) |
| malicious site tries HTML injection into modal | safe textContent only | SHIPPED v0.2.0 |
| copy on sensitive-class page (login/payment) | skip entirely (no API call, no telemetry) | SHIPPED v0.2.6 |
| User host on allowlist | skip | SHIPPED v0.3.1 |
| 1000-char command cap | enforced before sending | SHIPPED v0.2.6 |
| Telemetry URL stripped (no query strings) | enforced | SHIPPED v0.2.6 |

### 6.7 MV3 Service-Worker Lifecycle Matrix

The MV3 background context is a service worker, not a persistent page. It has seven distinct lifecycle states and any of them can be the state when a message arrives. Section 6.1 lists "background service worker restarts" as one row — that undersells it.

```
installing → ready → idle (~30s after last event) → terminating → terminated
↑                                                                     ↓
└────────────── on-event cold-start ←─────────────────────────────────┘
```

| SW state at message receipt | Test | Expected | Status |
|---|---|---|---|
| `ready` (fresh, hot caches) | `sendMessage("resolve")` | response within p95 budget | SHIPPED v0.3.0 |
| `idle` (29s into idle, just under eviction) | `sendMessage("resolve")` | SW services event, response normal | SHIPPED v0.3.0 |
| `terminating` (Chrome scheduled eviction in flight) | `sendMessage("resolve")` | message may drop OR be queued; holding-page retry covers both | SHIPPED v0.3.2 (retry+watchdog) |
| `terminated` (idle eviction completed) | `sendMessage("resolve")` | SW cold-starts, settings cache empty, settings refetched, response within budget | SHIPPED v0.3.2 |
| `installing` (mid-update) | `sendMessage("resolve")` | rejected with `runtime.lastError = "Could not establish connection"`; holding page retries | SHIPPED v0.3.2 (catch retries) |
| event loop blocked (handler awaits a hung promise) | second `sendMessage("resolve")` call | client-side timeout fires at 8s; first call may never complete | SHIPPED v0.3.2 |
| extension reload mid-flight | both `resolve` and `apply` race | every in-flight call gets `lastError`; no orphan tabs; user lands somewhere | SHIPPED v0.3.2 (fail-open) |
| storage quota exceeded mid-handler | cache write throws | sendResponse still called with verdict; user routes | SHIPPED v0.3.2 |
| chrome.tabs API rejected (tab closed mid-update) | `apply` arrives after tab closed | log + drop; no exception leak | SHIPPED v0.2.4 |
| ALARM fires during idle event handling | concurrent triggers | both serviced; no double-response | SHIPPED v0.2.4 |

**Test harness:** Playwright with a fake verdict API that responds to a `/control/{action}` endpoint allowing the test to suspend / kill / hang the background SW deterministically. See `tests/extension/sw-lifecycle.spec.ts`.

**Failure that escapes this matrix is a P0 bug.**

### 6.8 Versioning and Storage Migration Matrix

Between v0.2.0 and v0.3.2 the extension storage schema added: `mode`, `categories`, `portalApiBase`, `paranoidMode`, `userAllowlist`, the `at:<host>` ALLOW_TEMP keys, the `bl:<key>` BLOCK persistent cache, and the `jv:<key>` just-verified tokens. The verdict-api response added: `clearance_checks`, `vendor_dns_blocked_by`, `domain_age_days`, `cached`. Each addition is a backward-compat surface.

| Scenario | Test | Expected | Status |
|---|---|---|---|
| `chrome.storage.local` from v0.2.0 (no `mode` field) loaded by v0.3.2 | settings() default-merge | normal operation; user sees `safe` mode | SHIPPED v0.3.0 |
| Old `at:` ALLOW_TEMP entries from v0.2.x | `isAllowTemp` parsing | honored | SHIPPED v0.3.0 |
| Verdict-api v0.3 → v0.4 with new `clearance_checks` field | extension v0.3.2 renders gracefully when field absent | works | SHIPPED v0.2.8 |
| Extension v0.3 reading verdict-api v0.2 response (no `clearance_checks`) | falls back to codes-derived checklist | works | SHIPPED v0.2.8 |
| Migration on update: `chrome.storage.session` wiped, `local` preserved | nominal | persistent BLOCK cache survives | SHIPPED v0.2.7 |
| `chrome.storage.sync` legacy entries from v0.2.0 | one-shot read-and-migrate-to-local | values copied; sync entries deleted | **TODO P1** |
| Verdict-api shipped with new reason code unknown to extension's REASONS map | `REASONS[code] || fallback` template | generic card rendered, no JS crash | SHIPPED v0.2.6 |
| Extension v0.3.2 sends `mode: "ultra"` to verdict-api v0.2 (unknown mode) | server defaults to "normal" + warn-log | no crash | SHIPPED v0.2.8 |
| Manifest `version` rollback (downgrade) | manifest comparison | user sees install notification; new entries ignored gracefully | **TODO P2** |
| Storage corruption (manually-edited JSON) | error path | reset to defaults + log; user warned | **TODO P2** |

**Contract:** every new field added to `chrome.storage.local`, `checkResponse`, or `policy.Inputs` must have a default that produces v0.x behavior. A field becoming required (no default) is a major version bump.

## 7. Evidence UI Test Matrix

Evidence pages must stay readable with missing data.

| Case | Expected | Status |
|---|---|---|
| no screenshot URL | no broken image | SHIPPED v0.3.1 (img.onerror) |
| screenshot URL expired (15-min presigned) | image hidden with explanation | SHIPPED v0.3.1 |
| brand reference missing | no empty comparison card | SHIPPED v0.3.1 |
| unknown reason code | generic explanation card | SHIPPED v0.2.6 |
| no reason codes | explicit "no reason codes attached" | SHIPPED v0.2.0 |
| very long URL (1 KB+) | wraps without layout break | SHIPPED v0.2.5 (word-break: break-all) |
| raw IP URL | clear raw-IP explanation | SHIPPED v0.2.5 |
| no domain age | shows unknown, not failure | SHIPPED v0.2.7 |
| no vendor DNS data | shows not checked/unknown | SHIPPED v0.2.7 |
| portal API down | warn/block page still usable from URL params alone | SHIPPED v0.2.5 |
| evidence ID missing | page still usable from URL params | SHIPPED v0.2.5 |
| mobile viewport 390×844 | no overlap | SHIPPED v0.2.6 (responsive compare grid) |
| dark mode contrast | readable | PARTIAL (Phase 4 §7.5 a11y audit pending) |
| repeated reason codes in list | deduped | SHIPPED v0.2.6 |
| WARN page renders full evidence (parity with BLOCK) | yes | SHIPPED v0.3.1 |
| 8-layer clearance checklist visible | always | SHIPPED v0.2.8 |
| `clearance_checks` absent → fallback to codes-derived grid | works | SHIPPED v0.2.8 |
| Screenshot URL pointed at `javascript:` (MITM) | rejected by isHttpURL gate | SHIPPED v0.2.4 |
| Brand reference URL pointed at `data:` | rejected | SHIPPED v0.2.4 |
| Side-by-side compare stacks vertically on mobile | yes | SHIPPED v0.2.6 |

Screenshot tests should compare:

```text
desktop 1440x900
laptop 1280x800
tablet 768x1024
mobile 390x844
```

### 7.5 Accessibility Audit Criteria

The block / warn / isolate / dnsfail / holding pages are shown to users during high-stress moments (their browser was just intercepted). They must be usable by every user, including those using assistive technology.

| Audit | Tool | Pass criteria | Status |
|---|---|---|---|
| WCAG 2.1 AA color contrast on body text | `axe-core` automated scan | every text element ≥4.5:1 against background | **TODO P1** |
| WCAG 2.1 AA contrast on signal-card severity colors | manual + Stark plugin | critical/high/medium/low all distinguishable for protanopia & deuteranopia | **TODO P1** |
| ARIA labels on icon-only buttons (verdict pill, age badge, provider tag) | `axe-core` | every interactive element has accessible name | **TODO P1** |
| Tab order through interstitials | manual keyboard nav | logical: pill → reason → checklist → screenshots → actions | **TODO P1** |
| `aria-live="polite"` on verdict pill, scanning subtitle on holding page | manual + NVDA/VoiceOver | screen reader announces state changes | **TODO P1** |
| Skip-to-content link at top of every interstitial | manual | jumps past the pill+title to first action | **TODO P2** |
| `prefers-reduced-motion` for spinner on holding.html | CSS media query | static `aria-busy` indicator instead | **TODO P1** |
| Focus visible (`:focus-visible`) on all interactive elements | manual keyboard nav | high-contrast focus ring meets WCAG 2.4.7 | **TODO P1** |
| Semantic HTML (`<button>`, `<nav>`, `<main>`, `<h1>`-`<h3>`) | `axe-core` | no clickable `<div>`s, no `<h1>` skipped to `<h3>` | PARTIAL (some `<div>` actions remain) |
| Form labels on Options page | `axe-core` | every input has `<label for="">` | SHIPPED v0.2.5 |
| Language attribute on `<html>` | `axe-core` | `lang="en"` set | SHIPPED v0.2.0 |
| Mobile-viewport readability (390×844 portrait) | screenshot test | no horizontal scroll, no clipped text | PARTIAL (compare grid stacks correctly) |
| Keyboard-only complete workflow on warn page | manual | tab to "Proceed anyway" → countdown announced → Enter activates | PARTIAL (Enter works; countdown not announced) |
| Zoomed-text 200% layout | manual | layout reflows; no text overlap | **TODO P1** |
| High-contrast Windows mode | manual | system colors honored | **TODO P2** |

**Test harness:** automated axe-core scan in `tests/extension/a11y.spec.ts` runs per page per viewport; manual sweep documented in `docs/runbooks/a11y-audit.md` quarterly.

A failing axe-core check on a P0/P1 row is a release blocker.

## 8. False-Positive Corpus

Create:

```text
tools/fp-bench/corpus/benign-real-world.txt
tools/fp-bench/corpus/benign-sensitive.txt
tools/fp-bench/corpus/benign-downloads.txt
tools/fp-bench/corpus/benign-wrappers.txt
tools/fp-bench/corpus/benign-raw-ip-operator.txt
```

Include:

| Category | Examples |
|---|---|
| Microsoft auth | `login.microsoftonline.com`, `invitations.microsoft.com`, SafeLinks |
| Google auth | `accounts.google.com`, Google OAuth |
| GitHub auth | `github.com/login`, OAuth apps |
| SaaS billing | Stripe Checkout, Paddle, LemonSqueezy, PayPal |
| Dev docs | OpenAI, Anthropic, Claude, Cursor, Cline, opencode, Processing |
| Downloads | Signal, Firefox, Chrome, Python, Node, Rust, Go, VS Code |
| Banks/payment | major banks, PayPal, Stripe dashboard |
| Government | IRS, SSA, FTC, HMRC, DVLA, CRA, ATO, myGov |
| Shared hosting benign | GitHub Pages, Netlify, Vercel, Cloudflare Pages |
| Ad-heavy benign | news/media sites |
| Long URLs | SafeLinks, Proofpoint, nested redirects |
| Operator self-host | public IP + custom port, internal hostnames |

Every real user false positive must be added with:

```text
URL
expected verdict
actual verdict
reason codes
date found
policy version
fix commit
```

## 9. Malicious Corpus

Create:

```text
tools/fp-bench/corpus/malicious-phishing.txt
tools/fp-bench/corpus/malicious-scam.txt
tools/fp-bench/corpus/malicious-command-copy.txt
tools/fp-bench/corpus/malicious-raw-ip.txt
tools/fp-bench/corpus/malicious-oauth.txt
tools/fp-bench/corpus/malicious-downloads.txt
tools/fp-bench/corpus/malicious-popup.txt
tools/fp-bench/corpus/malicious-qr.txt
```

Include:

| Category | Examples |
|---|---|
| credential phishing | login clones, MFA pages, bank clones |
| OAuth abuse | unknown high-scope clients |
| command-copy | fake docs with PowerShell, `mshta`, `rundll32`, encoded payloads |
| raw-IP malware | botnet arch paths, public IP executables |
| fake support | Microsoft/Apple/browser alert pages |
| refund/tax scams | IRS/HMRC/CRA refund fraud |
| crypto scams | fake airdrop, wallet drainer, investment pages |
| malvertising | fake update ads, redirect chains |
| popup storm | alert loop, fullscreen trap, beforeunload trap |
| HTML smuggling | JS-generated downloads |
| QR phishing | QR code to login/payment |
| image-only phishing | login form or phone number hidden in image |

## 10. Chaos Test Matrix

Run tests where dependencies are killed, delayed, or return malformed data.

| Failure | Expected | Status |
|---|---|---|
| Redis down | resolver/API degrade, no crash | SHIPPED (rdb nil guards) |
| Postgres down | no crash; limited verdict; clear reason | SHIPPED |
| sandbox-render down | sensitive unknown isolates; non-sensitive degrades | SHIPPED v0.2.5 |
| visual-match down | no block from missing visual | SHIPPED |
| portal-api down | extension UI still usable from URL params | SHIPPED v0.2.5 |
| MinIO down | no broken images (img.onerror hides) | SHIPPED v0.3.1 |
| RDAP timeout | domain age unknown only | SHIPPED v0.2.6 |
| WebRisk timeout | optional signal missing only | SHIPPED |
| DNS upstream timeout | bounded DNS behavior | SHIPPED v0.3.2 (500ms ctx) |
| verdict-api slow | extension timeout UI by 12s | SHIPPED v0.3.2 |
| background service worker killed | holding page exits at 12s deadline | SHIPPED v0.3.2 |
| corrupted evidence JSON | UI shows fallback | SHIPPED v0.2.7 |
| malformed feed row | skipped safely | SHIPPED |
| huge HTML page (10 MB+) | sandbox bounded (Playwright timeout) | SHIPPED |
| infinite redirects | bounded by Chromium (max 20) | SHIPPED |
| download server hangs | bounded download probe (10s timeout) | SHIPPED v0.2.0 |
| browser context leak test | no Chromium process growth over 1h soak | PARTIAL (Phase 4 to add to CI) |
| Vendor DNS provider timeouts | per-provider 200ms cap; baseline check 200ms | SHIPPED v0.2.6 |
| Sandbox returns truncated JSON | LimitReader 4MB cap | SHIPPED v0.3.1 |
| Verdict cache returns stale (mode mismatch) | mode-isolated keys | SHIPPED v0.2.8 |
| Rate limit denial in stampede | 429 with Retry-After | SHIPPED v0.3.0 |
| Sandbox returns IsChallengePage=true | render result accepted; policy uses challenge gate | SHIPPED v0.2.0 |

### 10.5 Supply-Chain / Self-Poisoning Matrix

The corpus pipelines (brand seeder YAML, feed ingest, brand_screenshots) are themselves attack surfaces. A compromised feed source or a malicious commit to `brands.yaml` could disable detection of real threats or poison the visual-match registry.

| Vector | Test | Expected | Status |
|---|---|---|---|
| `brands.yaml` modified to mark a typosquat as canonical | CI schema check + required code-owner review | PR rejected at gate | SHIPPED v0.2.6 (schema check); code-owner: **TODO P1** |
| Feed source (URLhaus, PhishDB) compromised and ingests benign URLs as malicious | nightly anomaly check: if today's adds >10× rolling-7d-avg, hold for review | TBD | **TODO P1** |
| Feed source compromised and removes real malicious URLs | nightly anomaly check: if removals >5× avg, hold for review | TBD | **TODO P1** |
| `feed_entries` ingest with malformed CSV (smuggled NULL bytes, very long line) | `bufio.Scanner` with safe defaults; line discarded with structured warning | SHIPPED (bufio.Scanner used) | SHIPPED |
| `brand_screenshots.embedding` poisoned (degenerate hash with low bit-count) | pHash bit-count filter at query time excludes degenerate hashes | SHIPPED v0.2.5 |
| `brand_screenshots.embedding` poisoned with a brand's name pointing at attacker URL | manual review on every PR touching this table | TBD | **TODO P1** |
| Operator sets `XGG_LOCAL_TRUSTED_HOSTS=".com"` | suffix-length + label-count validator rejects | SHIPPED v0.3.0 |
| Operator misconfigures `XGG_LOCAL_TRUSTED_HOSTS` to include a known-phish domain | telemetry alert on "trusted-host hit ratio" anomaly: if >5% of verdicts on a host classify as ALLOW-via-trust, flag | TBD | **TODO P2** |
| sandbox-render YARA ruleset replaced with `rule x { condition: true }` | rule-loader signature check OR exact-hash allowlist | TBD | **TODO P1** |
| Code-signing key for verdict-api binary compromised | reproducible build verification | TBD | **TODO P3** |
| MinIO bucket policy regression (accidentally set public after Phase 2 hardening) | nightly `mc anonymous get` check; alert if !=`private` | TBD | **TODO P0** |
| `psycopg-pool` or other Python dependency replaces module-level objects at import time (supply-chain attack via npm/pypi takeover) | pin via `requirements.txt` + lock-file hash + `pip-audit` weekly | PARTIAL (pinning v0.2.6); hash + audit: **TODO P1** |
| Go dependency replaced (e.g. `go.mod` mutated in PR) | CODEOWNERS on `go.sum` + Renovate config | TBD | **TODO P1** |
| GitHub Actions secret rotation: `XGG_INTERNAL_TOKEN` leaked | rotation runbook; downstream service rolling restart accepts both old + new for 24h | TBD | **TODO P1** |
| Postgres-restore from compromised backup (e.g. backup encrypted with key in same repo) | encrypted-at-rest backup; key in separate KMS | TBD | **TODO P2** |
| Operator's `~/.kube/config` leaked, attacker spawns deep-scan jobs | rate limit per-cluster + per-user concurrency cap on `/v1/deep-scan` | PARTIAL (rate limit on `/v1/check`; deep-scan TODO) | **TODO P1** |

The bucket-policy regression (row 11) is P0 because the fix already shipped and a silent regression would un-do the Phase 2 hardening work without any visible symptom until exfiltration is discovered.

## 11. Performance Budgets, SLIs, and SLOs

Performance is measured against three orthogonal dimensions: latency, success rate, and hang count. The third is non-negotiable — every other dimension can degrade gracefully; hangs cannot.

### 11.1 Latency budgets per path

| Component | p50 | p95 | p99 | Hard ceiling | Status |
|---|---:|---:|---:|---:|---|
| DNS cache hit (resolver) | <5ms | <10ms | <20ms | 50ms | SHIPPED |
| DNS local Bloom path | <20ms | <50ms | <100ms | 200ms | **TODO P1** (Bloom not yet built) |
| DNS verdict-api fallback | <300ms | <800ms | <1.5s | 3s | SHIPPED |
| Verdict-api `/v1/check` cached | <50ms | <150ms | <300ms | 500ms | SHIPPED v0.2.5 |
| Verdict-api `/v1/check` Tier-1 only | <250ms | <500ms | <1s | 2s | SHIPPED |
| Verdict-api `/v1/check` Tier-2 (sandbox) | <8s | <15s | <25s | 90s | SHIPPED v0.2.6 |
| Verdict-api `/v1/check` end-to-end | <500ms | <12s | <22s | 90s | SHIPPED |
| Verdict-api `/v1/deep-scan` (depth=1, 5 pages) | <30s | <60s | <90s | 120s | SHIPPED v0.2.8 |
| Sandbox render single URL | <3s | <15s | <25s | 45s | SHIPPED |
| Visual-match `/match` | <1s | <5s | <12s | 15s | SHIPPED |
| Portal-api `/v1/evidence/:id` | <100ms | <500ms | <1s | 3s | SHIPPED |
| Extension holding-page deadline | n/a | n/a | n/a | **12s (HARD)** | SHIPPED v0.3.2 |
| Extension first-paint after `tabs.update` | <100ms | <300ms | <500ms | 1s | SHIPPED |

### 11.2 Success-rate SLOs and error budgets

| Indicator | Objective (30-day) | Error budget | Alert threshold | Status |
|---|---:|---:|---|---|
| `/v1/check` success (HTTP 2xx) | ≥99.5% | 0.5% (~216 req/30d if 1k/h) | >2% errors over 5 min | SHIPPED |
| `/v1/check` hangs (response time >25s with no error) | 0 (HARD) | 0 | any single occurrence | SHIPPED v0.3.2 |
| sandbox-render success | ≥97% | 3% | >5% failures over 15 min | SHIPPED |
| visual-match success | ≥98% | 2% | >5% failures over 15 min | SHIPPED |
| portal-api `/v1/evidence/:id` success | ≥99.5% | 0.5% | >2% over 5 min | SHIPPED |
| extension verdict cache hit rate on repeat traffic | ≥75% | n/a | <50% sustained for 1h indicates cache wipe | SHIPPED v0.2.5 |
| `runtime.lastError` rate per session-worker hour | <0.1% of messages | 0.1% | >1% over 15 min | **TODO P1** (telemetry not wired) |
| Service-worker cold start time (first event after wake) | <500ms p95 | n/a | >2s indicates settings cache miss-storm | SHIPPED |

### 11.3 Concurrency and stampede tests

```text
100 concurrent DNS queries to same hot domain
1000 cache-hit /v1/check calls (verify Redis hit ratio stable)
50 concurrent unknown URLs to /v1/check (verify rate-limiter behavior)
10 concurrent sandbox renders (verify coalescing — should converge to 1 in-flight job per URL)
50 users hit same URL simultaneously (one sandbox call, all 50 verdicts populated from coalesce)
1 user fires 200 /v1/check requests in 60s (verify rate-limiter denies +204 of them with 429)
SW-wake-storm: 100 tabs simultaneously trigger onBeforeNavigate after browser restart
```

### 11.4 Recovery time objectives (RTO)

| Failure | RTO | How |
|---|---:|---|
| verdict-api crash | <10s | systemd Restart=on-failure, 3s RestartSec |
| sandbox-render crash | <30s | playwright re-init on systemd restart |
| Redis crash | <15s | docker compose restart; resolver/API fail-open during gap |
| Postgres crash | <60s | docker compose restart; verdict-api degrades to no-feed mode |
| MinIO crash | <30s | restart; portal-api signed-URL re-fetch on next view |
| extension SW crash | <500ms cold start | Chrome auto-restarts on event |

A regression in any latency p95 by >50% week-over-week is a release blocker.



## 12. Aggressive Deep Analysis Mode

Realtime mode should stay bounded. Aggressive mode can be slow and should run async.

Aggressive scan should:

1. render from multiple user agents,
2. render from multiple viewports,
3. render from multiple geographies/egress points,
4. compare datacenter vs residential/mobile views,
5. follow redirect chains,
6. click likely buttons: continue, verify, login, download, allow, copy,
7. submit canary credentials only in isolated sandbox,
8. detect all forms, sinks, scripts, iframes, service workers,
9. decode QR codes from screenshot,
10. OCR screenshot for hidden phone/brand/payment text,
11. extract phone numbers, wallet addresses, emails, tracking IDs,
12. hash downloads,
13. detonate risky downloads in separate sandbox,
14. build infrastructure graph,
15. compare against campaign graph.

Aggressive mode outputs:

```json
{
  "url": "...",
  "final_url": "...",
  "claimed_brands": [],
  "phones": [],
  "wallets": [],
  "downloads": [],
  "scripts": [],
  "form_sinks": [],
  "oauth_clients": [],
  "redirects": [],
  "popup_targets": [],
  "qr_urls": [],
  "campaign_links": [],
  "reason_codes": []
}
```

### 12.5 Aggressive-mode Guardrails

Section 12 enumerates capabilities. Without guardrails the same list reads as an open invitation to burn unbounded GPU + bandwidth. Hard constraints:

| Constraint | Value | Rationale |
|---|---|---|
| Endpoint | `POST /v1/deep-scan` only | Token-protected; not reachable from extension's anonymous `/v1/check` path |
| Auth | `X-Internal-Token` required | Bandwidth-heavy; not public-facing |
| Per-user concurrent jobs | 1 | Prevents queue exhaustion by one tenant |
| Per-domain rate limit | 1 aggressive scan per hour per domain | A targeted attack would burn GPU on a single domain otherwise |
| Per-target page count | ≤15 | Already enforced; covers landing + ≤14 children |
| Per-job wall-clock | ≤10 minutes | Hard kill at 600s; partial results emitted |
| Per-page render budget | ≤45s | Same as realtime sandbox tier |
| Item 7 (canary credential submission) | Separate sandbox pod with `--network=none` + ingress proxy that only accepts the canary domain | Real-credential submission to attacker infra is unacceptable even in test |
| Item 13 (download detonation) | Separate sandbox pod with seccomp `RUNTIME_DEFAULT` + `--read-only` rootfs + network namespace isolated from production | Detonated payload must not reach production network |
| Compute cost class | Premium tier — billed separately from realtime | One operator's deep-scan habit cannot starve realtime traffic |
| Output retention | Same `retention_until` policy as realtime evidence | Aggressive results don't get special long-term storage |
| Audit log | Every `/v1/deep-scan` invocation logged with caller identity + target URL | Operator can detect abuse of their own API key |
| Telemetry | `xgg_deep_scan_total{caller_id}`, `xgg_deep_scan_duration_seconds`, `xgg_deep_scan_failures_total{reason}` | Cost & abuse visibility |

A regression that allows aggressive-mode behavior on the realtime path (`/v1/check`) is a P0 bug. The realtime path must never call into items 1-15 above except for items already wired (sandbox render + visual match + DOM inventory).


## 13. Correlation Graph Testing

The correlation engine should link:

```text
URL
domain
subdomain
path prefix
IP
ASN
certificate
favicon hash
screenshot hash
brand
phone number
wallet address
OAuth client_id
redirect URI
script origin
form sink
download hash
command hash
popup target
```

Test campaign rules:

| Rule | Expected |
|---|---|
| same phone on 3 unrelated domains | scam campaign |
| same wallet on 2 refund/crypto pages | crypto scam campaign |
| same favicon on many new domains | phishing kit cluster |
| same form sink across brand clones | credential phishing backend |
| same command hash on fake docs | developer malware campaign |
| same OAuth client across lures | OAuth abuse campaign |
| same cert across typosquats | infrastructure cluster |
| same ASN + new domains + same kit | hosting risk signal |

## 14. False-Result Triage Workflow

Every user-reported bad verdict must follow:

1. capture URL, final URL, evidence ID, verdict, reason codes,
2. classify as FP, FN, timeout, UI bug, dependency bug, or policy bug,
3. add URL to correct corpus,
4. write regression test,
5. fix rule/data/policy/UI,
6. run maturity tests,
7. document root cause.

Required root-cause categories:

| Category | Example |
|---|---|
| missing positive trust | real domain not in brand graph |
| overbroad rule | raw IP blocked operator self-host |
| missing scoped trust | Stripe payment sink treated as malicious |
| dependency timeout | sandbox did not return |
| extension state bug | holding page hung |
| evidence UI bug | broken image |
| incomplete parser | SafeLinks wrapper not unwrapped |
| stale data | old feed entry |
| model threshold | short keyword homoglyph FP |

## 15. Priority Implementation Plan

| Priority | Work item | Acceptance criteria | Why | Status |
|---|---|---|---|---|
| **P0** | Extension no-hang E2E | 100 URLs × 30 dependency-failure modes; **0 indefinite spinners**; ≤12s wall-clock per URL; CI gate | user-visible reliability | PARTIAL (v0.3.2 watchdog ships; E2E suite TBD) |
| **P0** | Go `-race` in CI | `go test -race ./...` on every PR; **0 new races introduced** | correctness | SHIPPED v0.2.5 |
| **P0** | Resolver chunk-safe list loading | property-based test (1000 random lists × random chunk sizes); **0 corrupt domains** | blocklist correctness | **TODO** (resolver still in dev) |
| **P0** | MinIO bucket-policy nightly check | nightly `mc anonymous get` returns `private`; alert if not | silent regression of Phase 2 hardening | **TODO** |
| **P0** | Handler-invariant lint rule | `eslint-plugin-xgg/always-respond` blocks PRs that `return true` without `sendResponse` in every branch | stops the bug class that caused most hangs | **TODO** |
| **P1** | Wrapper URL decoder | unwrap ≥95% of SafeLinks regional prefixes + Proofpoint + Mimecast + Cisco; behavior preserved when destination is itself a wrapper (nested) | enterprise emails ubiquitously use these | PARTIAL (bypass shipped v0.3.2; unwrap+forward TBD) |
| **P1** | Raw-IP nuanced policy | operator IPs ALLOW; public-IP malware-arch URLs BLOCK; public-IP+login ISOLATE; **no policy rewrites needed for known shape** | malware risk + operator FPs both addressed | SHIPPED v0.3.1 |
| **P1** | Payment scoped trust | Stripe/Paddle/PayPal sink trusted on payment-class pages; NOT trusted as identity for login-class pages | fixes billing FPs without enabling impersonation FPs | PARTIAL (Stripe added to trustreg; action-scoping in brandgraph not enforced) |
| **P1** | Evidence UI fallbacks | screenshot/DOM/HAR each independently missing → page still readable with explicit "not available"; no broken-image icons | trustworthy block-page experience | SHIPPED v0.3.1 (img.onerror) |
| **P1** | MV3 SW-lifecycle test suite | all 10 rows in §6.7 pass; failure of any is P0 | reliability under Chrome's eviction | PARTIAL (manual tested in soak; automated TBD) |
| **P1** | Backward-compat migration tests | every storage schema and API response field has a default that preserves v0.x behavior | smooth rollout | PARTIAL (informal; §6.8 codifies) |
| **P1** | Adversarial inputs (NFC, emoji, mixed-script) | rows in §5.8; each maps to a Go or JS unit test | typosquat detector tightening | **TODO** |
| **P2** | Benign real-world corpus (N≥500) | curated by category; FP rate ≤0.5% in Safe mode; ≤2% in Strict mode; ≤15% in Ultra mode | systematic FP reduction | **TODO** |
| **P2** | Malicious category corpus (N≥300) | recall ≥80% per category by Phase 3 release; per-category breakdown reported | systematic FN reduction | **TODO** |
| **P2** | Sandbox concurrency + coalescing tests | 50 concurrent same-URL → 1 in-flight sandbox job; verify pool semaphore behavior | production stability | PARTIAL (coalesce shipped; load test TBD) |
| **P2** | Scam-page detectors (phone, RAT, gift card) | per-category recall ≥70% on labelled corpus | covers major scam classes the engine misses today | **TODO** |
| **P2** | Accessibility audits | axe-core 0 violations on Critical/Serious; manual NVDA + VoiceOver pass | inclusive UX | **TODO** |
| **P2** | Privacy/retention SLA enforcement | automated retention-cleanup nightly; user-facing data-export endpoint | compliance posture | PARTIAL (cleanup ships; export TBD) |
| **P3** | OCR/QR detection | quishing recall ≥40% | quishing is rising in enterprise threats | **TODO** |
| **P3** | Correlation graph campaign tests | given known campaign indicators (phone + wallet + ASN), detector groups ≥80% of campaign URLs | mature detection | **TODO** |
| **P3** | Tracker-list dynamic ruleset | `chrome.declarativeNetRequest` dynamic rules per user category toggle | NextDNS/uBlock-like hygiene | **TODO** |
| **P3** | Aggressive-mode (§12) implementation | gated by §12.5 guardrails | premium tier feature | **TODO** |
| **P3** | Supply-chain CODEOWNERS + signed releases | every brand-yaml/feed-source/yara-rule PR requires code-owner approval | mature change-control | **TODO** |

Each row owns a `tools/maturity/status.md` entry. When a row moves to SHIPPED, its acceptance test is added to `make maturity-test` so regressions are caught.

## 17. Privacy and Data-Retention SLA

The product processes URLs (which can contain account IDs and tokens), screenshots (which may include PII rendered by the page), and DOM snapshots. Each data class has an explicit retention window, an access policy, and a deletion mechanism.

| Data class | Storage | Retention | Access | Right-to-delete | Status |
|---|---|---|---|---|---|
| Visited URL hash (cache key) | Redis `verdict:<sha256>` | 6h ALLOW / 24h BLOCK / 30m WARN | none (key only, never reversed) | TTL expiry | SHIPPED v0.2.5 |
| Verdict log line | stderr → journald → operator's log aggregator | 14d | operator | log rotation + retention policy on aggregator | SHIPPED v0.3.1 (sanitizer strips query strings) |
| Evidence bundle (screenshot, DOM, HAR) | MinIO `xgg-evidence/` + Postgres `evidence` | `retention_until` (default 30d; configurable) | portal-api admin only | weekly cleanup script + MinIO orphan-blob cleanup | SHIPPED Phase 4 |
| `/v1/check` source IP | structured log | strip after 24h analytics window | operator | log-rotation pipeline | PARTIAL (logged in plaintext; rotation: TODO) |
| Browser-side ALLOW_TEMP user list | `chrome.storage.local["at:<host>"]` | 24h auto-expiry | extension-local | "Revoke" button in Options OR clear-extension-data | SHIPPED v0.2.8 |
| Browser-side verdict cache | `chrome.storage.session` + `chrome.storage.local` BLOCK mirror | session lifetime / 1h BLOCK | extension-local | browser-data-clear | SHIPPED v0.2.7 |
| Telemetry submissions | TBD endpoint (currently a no-op) | TBD 30d | aggregator (TBD) | opt-in required (`telemetry` toggle in Options) | PARTIAL (toggle exists; pipeline TBD) |
| Brand registry (`brands`, `brand_screenshots`) | Postgres | Permanent | maintainer-only PR | seeder rerun | SHIPPED |
| Feed ingest (`feed_entries`) | Postgres | 14d after `last_seen` | operator | scheduled DELETE WHERE | PARTIAL (cleanup ships; auto-prune TODO) |
| OAuth client registry | Postgres `oauth_clients` | Permanent | maintainer-only PR | manual | SHIPPED |
| Sandbox YARA matches | Postgres `scan_history` | inherits `evidence.retention_until` | operator | cascade with evidence cleanup | SHIPPED |

**Operator obligations:**
- Document retention policy in `docs/runbooks/retention.md` (SHIPPED Phase 4)
- Provide a `data-export` endpoint where a user can retrieve everything stored under a given ClientID (`TODO` — required for GDPR/CCPA compliance once telemetry pipeline lands)
- Provide a `data-delete` endpoint where a user can purge all data for their ClientID (`TODO`)
- Log access to `evidence` and `urls` tables with the accessor's identity (audit log) (`TODO`)

**Sensitive data NEVER logged:**
- Query strings (stripped by `sanitizeURLForLog`, SHIPPED v0.3.1)
- Fragments (stripped by `normalizeForToken`, SHIPPED v0.2.6)
- HTTP request bodies (not logged anywhere)
- Cookies (sandbox renders without cookies; not captured)
- Authorization headers (not forwarded by sandbox or extension)

## 18. Game-Day Runbook

Run quarterly to verify the operational story holds. Each scenario has an expected user-visible outcome that is NOT "everything fails" — graceful degradation is the contract.

### 18.1 Dependency-failure exercises

| Exercise | Command | Expected user-visible outcome | Detection |
|---|---|---|---|
| Verdict-api hard stop | `sudo systemctl stop xgg-verdict-api` | Extension shows holding 12s, then manual-choice UI. User can Allow once / 24h / Isolate / Go back. No spinner forever. | `xgg_verdict_total` drops to 0 in Prometheus |
| Sandbox-render hard stop | `sudo systemctl stop xgg-sandbox-render` | Sensitive pages get ISOLATE (verification unavailable, correctly); non-sensitive get Tier-1-only ALLOW/WARN. No 30s timeouts on holding page. | `xgg_render_total{result="failure"}` spike |
| Visual-match stop | `sudo systemctl stop xgg-visual-match` | Visual signal absent in policy; replica/identity rules skip; no other regression. | `xgg_clip_inference_total` drops |
| Redis stop | `docker compose stop redis` | Cache misses → every request runs full pipeline (slower); no crash; no incorrect verdicts. | `xgg_redis_errors_total{op="GET"}` spike |
| Postgres stop | `docker compose stop postgres` | Feed lookup unavailable → verdicts based on Tier-1 + vendordns only; degraded but functional. Brand registry uses in-memory cache from last refresh. | All pgxpool errors logged |
| MinIO stop | `docker compose stop minio` | New evidence renders fail upload → render result discarded → fallback to Tier-1-only verdict. Existing block pages may show broken screenshots (handled by img.onerror). | sandbox-render `s3.put_object` errors |
| Network partition (firewall verdict-api ↔ sandbox-render) | `iptables -A INPUT -p tcp --dport 8002 -j DROP` | Tier-2 calls timeout after 45s; verdict falls through to Tier-1; user sees ALLOW or WARN promptly. | sandbox timeouts in verdict-api logs |
| Slow Redis (high latency) | `docker exec code-redis-1 redis-cli DEBUG SLEEP 5` | 200ms timeout on getVerdictCache fires; pipeline proceeds without cache hit; no hang. | `xgg_redis_errors_total{op="GET"}` rises |
| Slow sandbox (responds in 50s) | inject delay via test harness | verdict-api 45s timeout fires; retry once at 30s; both fail; fail-open to Tier-1 verdict | sandbox retry logs |
| Verdict-api flapping (restart loop) | restart 10 times in 60s | Extension shows manual-choice UI by 12s; user picks; cache absorbs verdict on next attempt | `xgg_verdict_total` rate noisy |

### 18.2 Browser-side game-days

Run with Playwright + the loaded extension:

| Exercise | Setup | Expected | Status |
|---|---|---|---|
| Browser offline mid-resolution | `chrome.runtime.disconnect` simulated | Holding page hits 12s deadline → manual choices | SHIPPED v0.3.2 |
| Tab closes mid-resolve | close tab while holding | No background-side leak; no orphan storage entries | SHIPPED |
| Extension reload mid-resolve | `chrome.runtime.reload()` during holding | New SW handles, holding page either auto-retries or shows manual choices | SHIPPED v0.3.2 |
| Network DNS down (`ERR_NAME_NOT_RESOLVED`) | block DNS via `iptables` | dnsfail.html explainer | SHIPPED v0.3.0 |
| Slow user actions (countdown timer pause/resume) | `chrome.tabs.update` between background | warn page countdown progresses on visibility; no double-fire | SHIPPED |
| User navigates away from holding | press Back during holding | holding deregisters cleanly | SHIPPED v0.3.2 |

### 18.3 Recovery validation

After each exercise, verify:
1. `make smoke` passes
2. Prometheus metrics return to baseline within RTO from §11.4
3. No orphaned Chrome processes (`pgrep chromium | wc -l` matches the soak baseline)
4. No leaked file descriptors (`lsof -p $(pgrep verdict-api)` returns to baseline)
5. `journalctl --since "<exercise start>"` contains structured errors, not panic traces

A failed exercise blocks the quarter's release until the contract is restored.

## 19. Mode-Specific FP/FN Budgets

Different modes have different acceptable failure rates. A single "FP rate <1%" threshold doesn't fit because Ultra mode is explicitly designed to ISOLATE unknown sites — which is, by definition, a high "false ISOLATE" rate.

| Mode | FP rate ceiling | FN rate ceiling | What "FP" means | What "FN" means |
|---|---:|---:|---|---|
| **Normal** | ≤0.5% | ≤30% | Block/Warn/Isolate on a clean URL | Allow on a malicious URL |
| **Safe** (default, recommended) | ≤0.5% | ≤20% | Same | Same |
| **Family** | ≤2% | ≤15% | Block on a benign general-audience site | Allow on adult / gambling category leakage |
| **Strict** | ≤5% | ≤10% | Block on a benign piracy-adjacent or community site | Allow on download / install lure |
| **Paranoid** | ≤8% | ≤7% | Isolate on a clean sensitive page | Allow on subtle credential-sink failure |
| **Ultra** | ≤15% (Isolate) / ≤2% (Block) | ≤3% | Isolate on a clean unknown destination (BY DESIGN) | Allow on a fully-clearance-passing malicious page |

**Measurement methodology:**
- Per-mode benign corpus drives FP measurement: e.g. `tools/fp-bench/corpus/benign-ultra-friendly-set.txt` is a curated set of 200 mainstream URLs that should clear all 8 Ultra gates
- Per-mode malicious corpus drives FN measurement: 100 known-bad per category × 6 categories
- Reported in `make fp-bench` output as a per-mode block: `Mode safe: FP 0.3%, FN 18%` etc.
- A release that raises any mode's FP ceiling OR FN ceiling by more than 2pp is a major version bump.

**User-mode-switch UX consequence:** When the user moves from Safe → Ultra, they should see a tooltip: "Ultra blocks unknown sites by default. You may see more isolation prompts." This sets the expectation that the higher FP rate is intentional, not a bug.

## 16. Final Standard

XGenGuardian reaches mature operational quality when:

```text
ordinary browsing rarely sees the product,
dangerous actions are verified before trust,
unknown sensitive pages never fail silently,
timeouts produce choices instead of hangs,
false positives shrink every release,
false negatives become campaign intelligence,
and every verdict can be explained in one screen.
```

