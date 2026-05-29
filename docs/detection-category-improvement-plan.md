# XGenGuardian Detection Category Improvement Plan

**Status:** execution companion to
[`deeptrust-zero-trust-url-analysis.md`](deeptrust-zero-trust-url-analysis.md).

**Purpose:** improve detection accuracy threat-by-threat, starting with the
weakest categories and ending with already-strong categories.

**Last reviewed:** 2026-05-29.

This document does not replace the locked DeepTrust strategy. DeepTrust defines
the final architecture. This document breaks that strategy into concrete
detection categories, features, data sources, tests, and engineering ideas.

The order is intentional:

```text
worst current protection first
highest security gaps first
already-strong categories last
```

Scoring:

```text
A  = strong protection, low FP, production-worthy
B  = catches most cases, some known gaps
C  = partial protection, meaningful misses expected
D  = weak protection, mostly signal-only
F  = no real coverage today
```

## 1. Priority Map

| Priority | Category | Today | Mature Target | Why It Comes Here |
|---:|---|---|---|---|
| P0 | support scam / fake helpdesk | F | B+ | common real-world scam, no current OCR/phone/remote-tool detector |
| P0 | QR-code phishing / quishing | F | B+ | no QR extraction or recursive scan today |
| P0 | crypto-drainer / wallet / gift-card / wire fraud | F | B | no wallet/fraud-language/action detector |
| P0 | zero-day phishing with no feed hit | F | B+ | requires full page graph, visual, action, sink, trust/risk fusion |
| P0 | email-wrapped URLs: SafeLinks/Proofpoint/Mimecast | D | B+ | enterprise email coverage gap; high ROI |
| P0 | credential phishing with wrong sink | D | A | core phishing class; depends on sandbox/action/sink reliability |
| P0 | hidden iframe / clickjack / hidden anchors | D | B | current rules exist but depend on sandbox evidence |
| P0 | obfuscated JS / malware loader | D | B | current soft rule exists but needs richer script evidence |
| P0 | drive-by download / suspicious installer | D | A- | needs sandbox download graph + hash/YARA/reputation |
| P1 | visual brand impersonation | C- | A- | visual service exists but must be operational + better corroboration |
| P1 | OAuth consent phishing | C | B+ | registry exists but needs seeded clients and richer app risk model |
| P1 | compromised legitimate site | C | B+ | hard evidence must beat trust; needs live content analysis |
| P1 | DGA / random-host C2 callbacks | B- | B+ | lexical signal exists; classifier and DNS/time features missing |
| P2 | ad/tracker pollution | B | B+ | useful but not primary anti-phishing risk |
| P2 | ClickFix / command-copy attacks | B | A- | good base; needs broader official-command registry |
| P2 | typosquat / homoglyph | B+ | A- | good base; needs IDN/confusables hardening |
| P2 | adult/gambling/piracy filtering | B+ | A- | mostly feed/list quality and policy tuning |
| P3 | fresh-domain phishing | B+ | A- | RDAP + sensitive-page policy already useful |
| P3 | DNS known-bad / malware / C2 feeds | A- | A | strong; improve feed freshness and consensus |
| P3 | local DNS hijack / router compromise | A | A | strong connection-identity base; improve CDN/ASN proof |
| P3 | raw-IP malware drops | A | A | strong hard rule; expand IP encoding normalization |

## 2. P0: Support Scam / Fake Helpdesk

### Current Weakness

Current grade: **F**.

The system does not yet reliably detect:

```text
fake Microsoft/Apple/Google support pages
phone numbers embedded in images
remote-tool lure language
refund scam flows
browser-lock scareware with support number
chat widgets asking for phone/order/email under fake brand
```

### Mature Detection Strategy

Support scam detection should combine:

```text
OCR text from screenshots
visible DOM text
phone-number extraction
brand visual match
domain/brand mismatch
remote-access-tool mentions
scareware behavior
fullscreen/popup/beforeunload traps
payment language
support-page action classifier
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| OCR text extraction | content evidence | extract phone numbers and scam phrases from screenshots |
| phone-number parser | content evidence | normalize E.164, country, repeated use across domains |
| remote-tool dictionary | content evidence | AnyDesk, TeamViewer, RustDesk, UltraViewer, Quick Assist |
| scareware behavior | behavioral evidence | alert loops, fullscreen traps, popup storms, beforeunload abuse |
| fake support brand relation | identity evidence | visual brand match + non-brand domain + support action |
| phone reputation graph | campaign evidence | same number across unrelated domains raises risk |
| support-action classifier | action evidence | distinguishes real support docs from urgent scam prompt |

### Hard And Soft Rules

Hard block:

```text
brand impersonation + phone number + scareware behavior
remote-tool install request + fake support context
same phone number already seen in confirmed scam corpus
```

Warn/isolate:

```text
support page + unknown phone + weak brand mismatch
support page + remote tool mention but no scareware
OCR-only phone number on brand-looking page
```

### Tests

Create corpus:

```text
tools/fp-bench/corpus/scam-support-benign.txt
tools/fp-bench/corpus/scam-support-malicious.txt
```

Test cases:

```text
real Microsoft support page -> ALLOW
fake Microsoft support + phone in DOM -> BLOCK
fake Apple support + phone in image -> BLOCK after OCR
refund page + AnyDesk install -> BLOCK
popup storm + phone number -> BLOCK
legit vendor docs mentioning TeamViewer -> ALLOW/WARN only if no scam action
```

### Engineering Order

1. OCR extraction from sandbox screenshot.
2. Phone-number extraction from DOM + OCR.
3. Scam phrase dictionary.
4. Remote-tool detector.
5. Campaign graph by phone number.
6. Evidence UI section: "Support scam indicators."

## 3. P0: QR-Code Phishing / Quishing

### Current Weakness

Current grade: **F**.

The system does not extract QR codes from screenshots or images. If a page says
"scan this QR to continue", the actual phishing URL may never be scanned.

### Mature Detection Strategy

Treat every QR code as a hidden link.

```text
detect QR in screenshot/images
decode QR payload
classify payload type
if URL, recursively run DeepTrust on extracted URL
link child verdict back to parent page
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| QR detector | visual evidence | scan screenshot and embedded images |
| QR payload classifier | parser | URL, payment, Wi-Fi, text, crypto address |
| recursive URL scan | graph evidence | extracted URL gets its own evidence object |
| QR context classifier | action evidence | login continuation, payment, MFA, delivery scam |
| QR evidence UI | UX | show decoded target and child verdict |

### Hard And Soft Rules

Hard block:

```text
QR target is high-confidence malicious
QR target asks for credentials and fails identity proof
QR target is raw IP / fresh domain / feed hit
```

Warn/isolate:

```text
page requests QR scan for login/payment but QR target is unknown
QR target is shortened/wrapped and cannot be fully unwrapped
QR target differs from parent organization
```

### Tests

```text
benign restaurant menu QR -> ALLOW
benign bank app QR on official bank domain -> ALLOW
fake Microsoft QR login -> BLOCK/ISOLATE
QR to shortened URL -> unwrap and scan child
QR to crypto wallet/payment address -> classify as payment action
```

### Engineering Order

1. Add QR extraction to sandbox-render.
2. Add recursive child URL scan with depth limit.
3. Add graph edge: `parent_page -> qr_target`.
4. Add corpus with generated QR images.
5. Add evidence UI for decoded QR target.

## 4. P0: Crypto-Drainer / Wallet / Gift-Card / Wire Fraud

### Current Weakness

Current grade: **F**.

The system lacks a scam-finance language and action model. It does not yet
reliably detect:

```text
seed phrase requests
wallet connect drainers
gift-card payment instructions
wire/crypto refund scams
fake airdrops
fake exchange support
malicious wallet approval flows
```

### Mature Detection Strategy

Detect the requested financial action, not only the URL.

```text
wallet connection request
seed phrase entry
token approval
gift card code request
wire transfer instruction
crypto address display
refund overpayment language
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| wallet-address extraction | content evidence | BTC/ETH/Solana/etc. patterns |
| seed-phrase form detector | DOM/action evidence | 12/24 word inputs, paste trap |
| walletconnect detector | script evidence | WalletConnect, MetaMask, provider APIs |
| token-approval detector | behavior evidence | approve/spender contract requests where observable |
| gift-card phrase detector | content evidence | "buy gift cards", "scratch code", "Apple card" |
| refund scam classifier | content evidence | overpayment/refund/tax/wire/crypto phrases |
| address campaign graph | graph evidence | same wallet across unrelated domains |

### Hard And Soft Rules

Hard block:

```text
seed phrase entry requested on non-wallet canonical domain
gift-card payment request in support/refund/tax context
known scam wallet address
wallet connect flow on fresh/impersonating domain
```

Warn/isolate:

```text
crypto payment request on unknown domain
wallet connect on domain with weak trust score
wallet address appears with urgency/refund language
```

### Tests

```text
official Coinbase login -> ALLOW
fake Coinbase support + wallet phrase -> BLOCK
fake airdrop + wallet connect -> ISOLATE/BLOCK
refund page asks for Apple gift card -> BLOCK
legit crypto docs mentioning wallet address -> ALLOW/WARN depending action
```

### Engineering Order

1. Add wallet/gift-card/wire phrase extractors.
2. Add seed-phrase form detector.
3. Add wallet address graph.
4. Add scam-finance corpus.
5. Add evidence UI: "Financial scam indicators."

## 5. P0: Zero-Day Phishing With No Feed Hit

### Current Weakness

Current grade: **F** when sandbox/visual/action data is unavailable.

No feed will catch every fresh phishing site. The engine must detect behavior:

```text
what brand does it claim?
what action does it request?
where do credentials/payment/OAuth/downloads go?
does the infrastructure match the claimed identity?
```

### Mature Detection Strategy

Use action-aware identity proof.

```text
claimed identity
requested action
observed sink
domain/infrastructure trust
visual similarity
credential/payment/OAuth/download behavior
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| claimed-brand extractor | content/visual evidence | logo, title, favicon, text, OpenGraph |
| action classifier | action evidence | login, payment, OAuth, download, support, read-only |
| sink verifier | graph evidence | form action, fetch/beacon/ws destination |
| orggraph/brandgraph binding | identity evidence | same org vs unrelated third-party |
| proof-required matrix | policy | sensitive action cannot clear without proof |
| missing-proof evidence | policy/evidence | explicit "not verified", not silent pass |

### Hard And Soft Rules

Hard block:

```text
password form posts to unrelated unknown host
visual brand match + identity mismatch + credential action
OAuth high-risk scopes + unknown client + suspicious redirect
download executable from raw IP/fresh domain with lure language
```

Warn/isolate:

```text
sensitive action + missing sandbox proof
brand-like page + weak identity mismatch
fresh domain + login/payment action
```

### Tests

```text
fresh clean blog -> ALLOW/WARN by mode
fresh domain + login form -> ISOLATE
fake Microsoft page + credential sink -> BLOCK
clean old domain + hidden credential sink -> BLOCK
Google Sites phishing kit -> BLOCK if credential sink/brand mismatch present
```

### Engineering Order

1. Make sandbox-render and visual-match release gates.
2. Build canonical `Action` object.
3. Build sink verifier.
4. Add missing-proof policy.
5. Expand zero-day phishing corpus.

## 6. P0: Email-Wrapped URLs

### Current Weakness

Current grade: **D**.

Enterprise users click links wrapped by:

```text
Microsoft SafeLinks
Proofpoint URL Defense
Mimecast
Cisco Secure Email
Barracuda
Symantec/Broadcom clicktime
Sophos/Reflexion
```

If XGenGuardian only scans the wrapper host, the actual destination may be
missed.

### Mature Detection Strategy

Unwrap before scoring, then scan both wrapper and destination.

```text
original wrapper
decoded destination
redirect chain
nested wrapper chain
final URL
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| SafeLinks decoder | parser | regional prefixes, double-encoded `url=` |
| Proofpoint decoder | parser | `u=` / rewritten path variants |
| Mimecast decoder | parser | protect subdomains, encoded target |
| nested unwrap engine | parser | wrapper inside shortener inside wrapper |
| wrapper evidence UI | UX | show "email security wrapper unwrapped to..." |
| wrapper corpus | tests | real samples with expected destination |

### Rules

```text
wrapper itself is not trusted as destination identity
destination gets full DeepTrust scan
wrapper chain preserved in evidence
unknown/broken wrapper decode -> WARN/ISOLATE for sensitive actions
```

### Tests

```text
SafeLinks -> Microsoft login -> ALLOW
SafeLinks -> fake login -> BLOCK
Proofpoint -> benign news URL -> ALLOW
Mimecast -> shortener -> phishing page -> BLOCK
nested wrappers preserve final destination
```

### Engineering Order

1. Implement decoder library with fixtures.
2. Add recursive unwrap limit.
3. Add destination scan before verdict.
4. Add wrapper-specific E2E tests.

## 7. P0: Credential Phishing With Wrong Sink

### Current Weakness

Current grade: **D** when sandbox evidence is unavailable.

The most important question is:

```text
Where do credentials go?
```

### Mature Detection Strategy

Every credential page needs sink proof.

```text
form action
JS fetch/XHR/beacon/WebSocket destinations
hidden mirror fields
pre-submit key capture
same-origin vs same-org vs third-party
known auth provider vs unknown collector
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| form sink inventory | DOM evidence | form action + method + inputs |
| JS sink instrumentation | behavior evidence | fetch/XHR/beacon/ws destinations |
| pre-submit capture detector | behavior evidence | key events sent before submit |
| hidden mirror detector | DOM evidence | hidden duplicate password/email fields |
| auth endpoint registry | identity evidence | known first-party auth hosts |
| credential sink graph | graph evidence | page -> collector edge |

### Hard Rules

```text
password sent to unrelated unknown origin -> BLOCK
pre-submit credential capture -> BLOCK
hidden mirror field to third-party -> BLOCK
credential form on visual brand replica without identity proof -> BLOCK
```

### Tests

```text
same-origin login -> ALLOW
known IdP login -> ALLOW
password form posts to attacker host -> BLOCK
JS fetch sends password to third party -> BLOCK
analytics beacon without credentials -> no hard block
```

### Engineering Order

1. Make sandbox sink extraction mandatory for sensitive pages.
2. Add credential sink graph to evidence object.
3. Add identity-aware sink policy.
4. Add test pages with synthetic sink variants.

## 8. P0: Hidden Iframe / Clickjack / Hidden Anchors

### Current Weakness

Current grade: **D**.

Rules exist, but without reliable sandbox DOM evidence they cannot fire.

### Mature Detection Strategy

Detect hidden active surfaces, then decide by context.

```text
hidden iframe
opacity/zero-size clickable layer
offscreen credential form
hidden anchor farms
overlay over legitimate page
cross-origin active frame
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| layout geometry capture | DOM evidence | size, visibility, z-index, viewport relation |
| clickable overlay detector | behavior evidence | elementFromPoint / pointer interception |
| hidden iframe classifier | DOM evidence | hidden analytics vs hidden credential/active content |
| same-org relation | identity evidence | hidden same-org widgets less risky |
| risk context | policy | hidden thing + sensitive action = high risk |

### Rules

```text
hidden cross-origin credential frame -> BLOCK
clickjacking overlay on sensitive page -> BLOCK/ISOLATE
hidden anchor farm alone -> soft risk
hidden same-org analytics/widget -> usually suppress
```

### Tests

```text
legit analytics iframe -> ALLOW
hidden cross-origin login iframe -> BLOCK
clickjack overlay over payment button -> BLOCK
hidden anchor farm on old benign blog -> WARN only if corroborated
```

## 9. P0: Obfuscated JS / Malware Loader

### Current Weakness

Current grade: **D**.

Obfuscated JS alone has high FP risk. It must be correlated with behavior.

### Mature Detection Strategy

Classify script behavior, not just script shape.

```text
obfuscation
dynamic code execution
credential access
clipboard access
download trigger
external loader chain
anti-debug/anti-sandbox
time-delayed payload
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| script entropy metrics | static evidence | weak alone |
| dynamic eval/function detector | static/behavior evidence | stronger with network/download |
| network loader graph | graph evidence | script -> remote payload |
| anti-analysis detector | behavior evidence | webdriver checks, debugger checks |
| delayed behavior rerender | T4 evidence | render at t+5m/t+30m |
| JS behavior corpus | tests | benign obfuscated apps vs malware loaders |

### Rules

```text
obfuscated JS + credential sink -> BLOCK
obfuscated JS + auto-download -> BLOCK
obfuscated JS alone on trusted app -> suppress/low signal
anti-sandbox + fresh domain + sensitive action -> ISOLATE/BLOCK
```

## 10. P0: Drive-By Download / Suspicious Installer

### Current Weakness

Current grade: **D**.

The system has signals, but full protection requires download capture,
reputation, file type analysis, and optional detonation.

### Mature Detection Strategy

Treat downloads as child artifacts.

```text
page -> download URL -> file hash -> reputation -> static scan -> detonation
```

### Features To Add

| Feature | Type | Notes |
|---|---|---|
| download interception | sandbox evidence | capture URL, MIME, filename |
| file hash reputation | reputation evidence | hash lookups, local malware corpus |
| file type classifier | artifact evidence | PE, script, archive, Office macro |
| YARA/static scan | artifact evidence | local fast scan |
| detonation worker | T4 evidence | separate network namespace |
| official-download registry | trust evidence | vendor official download domains |

### Rules

```text
raw IP + executable path -> BLOCK
fresh domain + executable download lure -> BLOCK/ISOLATE
known malware hash/YARA -> BLOCK
official vendor download -> ALLOW if identity proof passes
archive with executable from unknown domain -> WARN/ISOLATE
```

## 11. P1: Visual Brand Impersonation

### Current Weakness

Current grade: **C-**.

Visual-match capability exists but must be operational and tied to identity and
action proof.

### Mature Detection Strategy

Visual match is not enough. Use:

```text
visual brand similarity
claimed brand text
favicon/logo match
domain/org relation
TLS/cert/ASN relation
requested action
sink verification
```

### Rules

```text
high visual match + credential action + identity mismatch -> BLOCK
weak visual match alone -> soft risk
visual match on same-org domain -> suppress
visual match on shared-hosting tenant -> verify tenant, not apex
```

### Engineering Ideas

```text
pHash near-duplicate screenshots
logo-region detection
favicon hash registry
brand text in title/OpenGraph
negative corpus for news articles about brands
visual service health as release gate
```

## 12. P1: OAuth Consent Phishing

### Current Weakness

Current grade: **C**.

OAuth registry exists, but client/app reputation needs more data.

### Mature Detection Strategy

Classify OAuth application risk:

```text
provider
client_id
publisher verification
scope severity
redirect URI
app name impersonation
opener lineage
known-good registry
```

### Rules

```text
unknown client + high-risk scopes -> BLOCK/WARN by mode
known provider + known client -> ALLOW
app name impersonates brand + unknown publisher -> BLOCK
suspicious redirect URI -> BLOCK
OAuth URL wrapped in email wrapper -> unwrap and scan destination
```

### Engineering Ideas

```text
seed oauth_clients for top IdPs and common SaaS
scope severity table per provider
app-name brand impersonation check
redirect URI orggraph relation
OAuth consent screenshot evidence
```

## 13. P1: Compromised Legitimate Site

### Current Weakness

Current grade: **C**.

Trust scoring helps with FPs, but attackers can compromise legitimate sites.
Therefore trust cannot erase hard evidence.

### Mature Detection Strategy

```text
trusted domain + malicious behavior -> still block
trusted domain + weak suspicious signal -> suppress/warn
trusted domain + sensitive action proof failure -> isolate/block
```

### Features

```text
subpage-level reputation
path-level feed hits
script supply-chain graph
new third-party script detection
unexpected download/sink on trusted host
CT/name-server/ASN drift
```

### Rules

```text
trusted site serving known malware -> BLOCK
trusted site with credential exfiltration -> BLOCK
trusted site with weak obfuscated JS only -> suppress/warn
trusted site newly loading unknown third-party credential collector -> ISOLATE/BLOCK
```

## 14. P1: DGA / Random-Host C2

### Current Weakness

Current grade: **B-**.

Random-host heuristic exists, but a real classifier and DNS-time features are
needed.

### Features

```text
character n-gram model
word-breakability score
entropy and vowel/consonant patterns
NXDOMAIN neighborhood
domain age
TTL/fast-flux profile
ASN/hosting reputation
feed/cohort correlation
```

### Rules

```text
random hostname alone -> soft risk
random hostname + fresh domain + suspicious action -> ISOLATE/BLOCK
DGA model high confidence + C2 feed/ASN evidence -> BLOCK
old dictionary-word brand/domain -> suppress
```

## 15. P2: Ad / Tracker Pollution

### Current Weakness

Current grade: **B**.

This is useful hygiene but should not distract from phishing/scam classes.

### Improvements

```text
declarativeNetRequest dynamic rules per mode
category-specific toggles
tracker list update verification
breakage reports
allowlist by site
performance budget for rule count
```

### Tests

```text
news site still readable
banking/payment sites not broken
tracker domains blocked
user category toggle works
rule update rollback works
```

## 16. P2: ClickFix / Command-Copy Attacks

### Current Weakness

Current grade: **B**.

Good base exists. Need broader official-command registry and visible-vs-
clipboard mismatch detection.

### Improvements

```text
expand installreg beyond Anthropic
visible text vs clipboard text comparison
PowerShell/cmd/bash/zsh/fish syntax-aware parser
base64/deobfuscation preview
official docs registry
copy modal evidence UI
```

### Rules

```text
mshta/rundll32/encoded PowerShell from unknown site -> BLOCK
curl|sh from unknown site -> WARN/ISOLATE
official vendor command exact match -> ALLOW
visible command differs from clipboard -> BLOCK
```

## 17. P2: Typosquat / Homoglyph

### Current Weakness

Current grade: **B+**.

Core logic is good after short-keyword edit-distance tightening. Remaining
work is IDN/confusables coverage.

### Improvements

```text
Unicode NFC normalization
confusables.txt mapping
mixed-script detection
punycode canonicalization
brand-keyword length-aware thresholds
visual skeleton comparison
negative corpus for coincidental short strings
```

### Rules

```text
d=1 typo near protected brand -> WARN/BLOCK by action
d=2 only for longer brand keywords
mixed-script protected-brand skeleton -> BLOCK/WARN
short random coincidence -> suppress
```

## 18. P2: Adult / Gambling / Piracy Filtering

### Current Weakness

Current grade: **B+**.

Mostly list quality, regional policy, and mode UX.

### Improvements

```text
feed source confidence tiers
regional category packs
family-mode explicit defaults
appeal/allowlist UX
shared-hosting tenant handling
category evidence UI
```

## 19. P3: Fresh-Domain Phishing

### Current Weakness

Current grade: **B+**.

Fresh domain alone is not malicious. It becomes high risk when paired with
sensitive action, brand claim, suspicious sink, or weak infrastructure.

### Improvements

```text
RDAP cache reliability
nameserver age
first-seen date
CT first-seen
fresh-domain + sensitive-action policy
fresh-domain + visual brand mismatch policy
```

### Rules

```text
fresh domain + read-only blog -> maybe ALLOW/WARN
fresh domain + login/payment/OAuth/download -> ISOLATE
fresh domain + brand impersonation + sink mismatch -> BLOCK
```

## 20. P3: DNS Known-Bad / Malware / C2 Feeds

### Current Weakness

Current grade: **A-**.

This is already one of the strongest lines.

### Improvements

```text
feed freshness monitoring
source anomaly detection
strict/weak source tiers
feed replay tests
source drift alerts
path-level URL feed matching
```

### Rules

```text
high-confidence fresh feed hit -> BLOCK
two medium independent hits -> BLOCK/WARN by source quality
one weak/community hit -> soft risk
feed hit on shared-hosting apex -> do not punish apex
feed hit on tenant path/subdomain -> tenant verdict only
```

## 21. P3: Local DNS Hijack / Router Compromise

### Current Weakness

Current grade: **A** for private-IP hijack; partial for CDN/ASN authority.

### Improvements

```text
XGG resolver returned-IP ledger as release gate
browser actual IP mandatory where browser API supports it
authorized CDN/ASN sets
TLS/SNI/Host consistency
DoH bypass detection where possible
operator UI for connection identity
```

### Rules

```text
public domain -> private IP -> BLOCK
unexpected ASN + TLS mismatch -> BLOCK/ISOLATE
unexpected IP but valid CDN/TLS -> soft only
missing browser IP -> evidence missing, not pass
```

## 22. P3: Raw-IP Malware Drops

### Current Weakness

Current grade: **A** for direct raw IP and common binary-drop paths.

### Improvements

```text
IPv4 decimal encoding normalization
IPv4 hex normalization
IPv6 mapped IPv4 normalization
ASN/AbuseIPDB lookup for raw IP
file download probe
botnet architecture path expansion
```

### Rules

```text
public raw IP + executable/archive/script path -> BLOCK
public raw IP + login/payment/admin -> ISOLATE/BLOCK
private/loopback raw IP -> local policy/user allowlist
operator trusted IP -> allow only via scoped operator config
```

## 23. Cross-Cutting Engineering Work

These improvements affect many categories.

### 23.1 Health-Gated Protection

If a detector is required for a category, its service health must affect the
verdict.

```text
sandbox down + sensitive page -> ISOLATE
visual-match down + visual-only claim -> missing proof, not pass
RDAP down -> domain age unknown, not old
external source timeout -> source missing, not clean
```

### 23.2 Source Adapter Schema

Every external source adapter must declare:

```text
name
confidence_tier
cost_class
rate_limit
timeout
cache_ttl
privacy_class
hard_block_eligible
failure_policy
```

Add a test:

```text
TestAdapter_DeclaresAllRequiredFields
```

### 23.3 Threshold Migration

Current shipped model:

```text
softWarnThreshold = 1.0
soft weights = 1.0 for most soft rules
DNS divergence = 0.5
```

Target mature model:

```text
normalized risk score 0.0-1.0
mode-specific WARN/BLOCK thresholds
hard evidence outside normalized score
```

Migration path:

```text
Phase 1: keep current accumulator, log normalized candidate score in shadow
Phase 2: compare old accumulator verdict vs normalized verdict on corpus
Phase 3: tune thresholds until FP/FN deltas pass budget
Phase 4: enforce normalized score only after shadow approval
Phase 5: remove old accumulator
```

### 23.4 Tranco / Popularity Caveat

Popularity is not safety.

Tranco/Cloudflare Radar may contribute weak trust only when:

```text
domain is not on a strict feed
domain is not a shared-hosting suffix tenant problem
domain has no hard evidence
domain has no sensitive-action proof failure
```

Never allow popularity to suppress:

```text
credential exfiltration
malware download
public-domain-private-IP
known feed hit
```

### 23.5 Standards Mapping

The DeepTrust strategy references CISA, NIST, OWASP, and MITRE. That is useful
only if mapped to implementation.

Create later:

```text
docs/standards-mapping.md
```

With rows:

```text
standard/control/technique
DeepTrust category
code path
test path
evidence field
status
```

## 24. Execution Order

The next engineering sequence should be:

| Order | Work | Why |
|---:|---|---|
| 1 | health-gate sandbox/visual/RDAP degraded modes | prevents silent fake safety |
| 2 | email wrapper unwrappers | high ROI for enterprise phishing |
| 3 | credential sink hardening | core phishing class |
| 4 | support-scam OCR/phone/remote-tool detector | currently F, high real-world harm |
| 5 | QR extraction and recursive scan | currently F and rising threat |
| 6 | download artifact pipeline | closes malware/install scams |
| 7 | normalized risk-score shadow model | fixes threshold coherence |
| 8 | visual-match operational gate and brand evidence | improves zero-day phishing |
| 9 | OAuth app-risk registry expansion | closes SaaS consent attacks |
| 10 | T4 exhaustive worker split into subprojects | analyst-grade deep scans |

Do not add another ordinary domain to global trustreg as a substitute for any
of the above.
