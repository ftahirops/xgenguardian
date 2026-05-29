# XGenGuardian DeepTrust Zero-Trust URL Analysis Engine

**Status:** canonical for per-URL deep investigation design; not the global
architecture roadmap.

**Owner:** XGenGuardian detection-engine maintainers.

**Last reviewed:** 2026-05-29.

**Implementation state:** working target spec. Current implementation status is
tracked in §1.1. Cross-engine rollout remains governed by
[`final-engine-architecture-plan.md`](final-engine-architecture-plan.md).

This document defines the long-form target design for analyzing one URL or
domain as deeply as possible. The purpose is to move XGenGuardian beyond
"known bad URL lookup" into a zero-trust investigation engine that can answer:

```text
Can this exact page, on this exact connection, safely ask this user for this exact action?
```

The default stance:

```text
Do not trust a website because DNS is clean.
Do not trust a website because HTTPS is valid.
Do not trust a website because one vendor says clean.
Do not trust a website because the domain is old.
Do not trust a website because it belongs to a big company.

Trust must be earned from independent, corroborating evidence.
Hard malicious evidence always wins.
```

This document is a practical product/engine specification, not a promise that
every adapter exists today and not an instruction to run every expensive check
on every navigation. The current codebase already implements a large part of
the shape below, but some pieces are intentionally marked as partial or future.

Canonical companion documents:

- [`final-engine-architecture-plan.md`](final-engine-architecture-plan.md) is the broader engine architecture and rollout plan.
- [`maturity-testing-blueprint.md`](maturity-testing-blueprint.md) defines release gates, chaos tests, privacy, and corpus rules.
- [`real-user-acceptance-test-plan.md`](real-user-acceptance-test-plan.md) defines human browser acceptance testing.

## 1. Objective

Given one URL, XGenGuardian should be able to:

```text
resolve it
unwrap it
connect to it
download it
render it
inspect it
compare it
score it
explain it
store evidence
learn from the outcome
```

The output is not only:

```text
ALLOW / WARN / ISOLATE / BLOCK
```

The output is a full investigation dossier:

```text
trust score
risk score
hard evidence
external source verdicts
DNS and connection identity
domain and infrastructure history
page action
credential/payment/OAuth/download/command sinks
visual brand evidence
behavioral evidence
missing proof
final policy reasoning
```

## 1.1 Current Implementation Status

The table below maps the DeepTrust target to the current codebase. It should be
updated whenever a phase ships so this document stays a working tracker rather
than a static north-star.

| DeepTrust Step | Current Implementation | Status | Next Practical Gap |
|---|---|---|---|
| Normalize and unwrap | URL normalization, shortener handling, SafeLinks bypass patterns | Partial | true SafeLinks/Proofpoint/Mimecast unwrap and recursive destination scan |
| DNS first-line check | resolver, vendor DNS, feed-backed domain checks, returned-IP ledger design | Partial/mostly shipped | make returned-IP ledger a release-gated dependency for connection identity |
| Connection identity | `connid`, browser `details.ip`, public-domain-private-IP hard rule | Shipped core | CDN/ASN authorized-set comparison and evidence UI expansion |
| External reputation | local feeds, vendor DNS providers, URLhaus/OpenPhish-style corpus | Partial | paid/source-tiered adapters for VT, Talos, Netcraft, AbuseIPDB, APWG, MISP |
| Domain/infrastructure history | RDAP/domain age, cert/Tier-1 metadata, brandgraph/orggraph signals | Partial | CT history, ASN reputation, historical clean verdict aggregation |
| Sandbox render | sandbox-render service exists | Partial/ops-sensitive | ensure it is running in production profile; enforce p95/hard timeout budgets |
| Page dissection | DOM inventory, forms, scripts, links, sinks, downloads | Partial | phone/wallet/gift-card extraction, richer support-scam features |
| Visual/OCR/QR | visual-match/CLIP path exists | Partial | OCR, QR extraction, recursive scan of extracted URLs |
| Action and sink verification | pageclass, OAuth, credential sink, command-copy, download signals | Shipped core | canonical `Action` object from cheap+verified signals |
| Trust/risk scoring | `trustscore`, soft-rule accumulator, decision trace | Shipped scaffold | more inputs, calibrated weights, telemetry-backed tuning |
| Action-aware policy | staged `policy.Apply`, mode handling, Ultra checks | Shipped core | split giant policy into hard/soft/trust/action modules |
| Evidence/telemetry/corpus | evidence UI, FP bench, maturity tooling, policy events | Partial | per-rule override telemetry and weekly rule-health report |

Honest maturity reading:

```text
architecture match: strong
operational completeness: medium
data-source depth: early
OCR/QR/scam extraction: early
latency/cost governance: must be enforced before broad rollout
```

## 2. Core Principle

No single source can declare a site safe.

Many independent sources can contribute trust:

```text
old domain
stable infrastructure
valid TLS
clean high-quality feeds
known organization
known CDN/payment/OAuth relationship
historical clean verdicts
benign page behavior
clean action sink
```

Many independent sources can contribute risk:

```text
fresh domain
raw IP
DNS divergence
unexpected ASN
bad TLS
visual impersonation
credential exfiltration
malicious command
popup scareware
auto-download
obfuscated JavaScript
support-scam language
gift-card/crypto/wire fraud language
```

Hard malicious evidence short-circuits:

```text
confirmed credential exfiltration -> BLOCK
known malware URL -> BLOCK
known malware hash/YARA -> BLOCK
raw IP serving botnet binary -> BLOCK
public domain resolving to private IP -> BLOCK
malicious command pattern -> BLOCK
```

## 3. Full Analysis Pipeline

```text
URL submitted / user navigates
        |
        v
1. Normalize and unwrap
        |
        v
2. DNS first-line check
        |
        v
3. Connection identity check
        |
        v
4. External reputation enrichment
        |
        v
5. Domain and infrastructure history
        |
        v
6. Sandbox render and page capture
        |
        v
7. Page dissection
        |
        v
8. Visual/OCR/QR analysis
        |
        v
9. Action and sink verification
        |
        v
10. Trust score + risk score
        |
        v
11. Action-aware policy matrix
        |
        v
12. Evidence report + telemetry/corpus feedback
```

This diagram is logical order, not strict serial execution. In the real system,
DNS, feeds, RDAP/domain age, local cache, trustscore, and vendor-DNS lookups can
run in parallel. Sandbox/visual/OCR/QR are conditional deep paths, not mandatory
for every page.

## 3.1 Latency And Cost Budget

DeepTrust must be powerful without making normal browsing unusable. Every
source and analysis step belongs to one of four execution tiers.

| Tier | Budget | Runs On | Examples | User Experience |
|---|---:|---|---|---|
| T0 cached/local | 5-50ms | every navigation | session cache, local verdict cache, user allowlist, trusted wrapper bypass | invisible |
| T1 fast online | 50-500ms | every uncached navigation | local feeds, vendor DNS cache, URL shape, raw IP, trustscore from cached features | brief hold acceptable |
| T2 conditional online | 500ms-3s | suspicious/unknown/sensitive only | RDAP cache miss, redirect unwrap, source fanout, ASN/CDN lookup | holding page with progress |
| T3 deep analysis | 8-45s, hard cap 90s | sensitive unknown, manual scan, Ultra, suspicious | sandbox render, visual match, OCR/QR, download probe | isolate/manual choice if not ready |

Release SLOs:

```text
cached repeat navigation: p95 <300ms
normal uncached Safe-mode page: p95 <1s
sensitive unknown page: p95 <12s to verdict or explicit user choice
deep manual scan: hard cap 90s with partial-result report
no extension spinner may exceed 12s without choices
```

Cost discipline:

```text
free/local/cache sources may run broadly
paid/rate-limited sources run only when risk justifies cost
deep sandbox/OCR/QR never runs for every ordinary cached page
manual deep-scan may be slower and more expensive than live browsing
```

This is mandatory. A comprehensive engine that users disable because it adds
30 seconds to normal browsing is a failed engine.

## 4. Step 1: Normalize And Unwrap

Normalize:

```text
scheme
host
registrable domain
punycode/IDN
port
path
query
fragment
tracking parameters
encoded nested URLs
```

Unwrap:

```text
Microsoft SafeLinks
Proofpoint URL Defense
Mimecast
Cisco Secure Email
Symantec/Broadcom clicktime
Barracuda
Sophos/Reflexion
shorteners such as bit.ly/t.co/tinyurl
redirect chains
```

Persist:

```json
{
  "original_url": "https://ind01.safelinks.protection.outlook.com/?url=...",
  "wrapper_type": "microsoft_safelinks",
  "unwrapped_url": "https://login.microsoftonline.com/...",
  "canonical_host": "login.microsoftonline.com",
  "registrable_domain": "microsoftonline.com"
}
```

## 5. Step 2: DNS First-Line Check

DNS is the first line of defense.

XGG resolver should check:

```text
known malicious domains
category/content policy
malware/phishing/C2 feeds
DNS rebinding
public-domain-to-private-IP answers
NXDOMAIN / DNS fail
TTL abnormalities
CNAME chain
authoritative nameserver stability
```

XGG resolver must also store what it returned:

```json
{
  "client_id": "device-or-profile-id",
  "domain": "example.com",
  "qtype": "A",
  "returned_ips": ["203.0.113.10", "203.0.113.11"],
  "ttl": 300,
  "timestamp": "2026-05-29T12:00:00Z",
  "resolver_region": "eu-1"
}
```

This returned-IP ledger is required for local DNS-poisoning detection.

## 6. Step 3: Connection Identity

Backend DNS can be clean while the user reaches a different IP due to:

```text
router DNS hijack
local malware
hosts file tampering
browser DoH bypass
VPN/corporate resolver rewrite
captive portal rewrite
malicious ISP resolver
malware-installed root CA
```

The browser extension should capture:

```text
browser actual remote IP
tab URL
main-frame request
timestamp
```

Verdict API compares:

```text
browser actual IP
vs XGG resolver returned IPs for this client/domain/TTL
vs backend trusted resolver answers
vs CNAME/CDN ownership
vs expected ASN set
vs TLS certificate identity
vs historical domain infrastructure
```

Never compare one IP to one IP. CDN sites legitimately return many IPs.

Correct comparison:

```text
browser_connected_ip ∈ authorized infrastructure set
```

Connection identity verdict examples:

| Case | Meaning | Policy |
|---|---|---|
| exact IP matches XGG resolver answer | DNS path consistent | pass |
| IP differs but same CDN/ASN and valid TLS | normal CDN variance | pass/soft pass |
| IP differs and ASN unexpected | possible hijack | WARN/ISOLATE |
| IP differs and TLS invalid | confirmed identity failure | BLOCK |
| public domain resolves to private IP | DNS rebind/local hijack | BLOCK |
| no browser IP supplied | insufficient data | no hard action |

## 7. Step 4: External Reputation Sources

External sources are witnesses, not gods.

Use them as independent signals:

| Tier | Source | Purpose | Call Policy |
|---|---|---|---|
| Always/local | URLhaus/local feed mirror | malware-distribution URLs and payload infrastructure | local feed/cache, fast path |
| Always/local | OpenPhish/curated phishing feeds if mirrored | high-confidence phishing URLs | local feed/cache, fast path |
| Always/local | vendor DNS consensus cache | independent protective-DNS corroboration | cached or bounded fast query |
| Always/local | Tranco/Cloudflare Radar rank snapshots | popularity/trust signal, not safety proof | local imported snapshot |
| Conditional | Google Safe Browsing / Web Risk | known unsafe URL lists, social engineering, malware, unwanted software | suspicious/unknown URLs, cached aggressively |
| Conditional | Spamhaus DBL | poor-reputation domains used in spam/malicious links | suspicious domains and email-originated URLs |
| Conditional | AbuseIPDB | IP abuse confidence and infrastructure abuse reports | raw IP, unexpected ASN, DNS divergence |
| Conditional | VirusTotal | aggregate URL/file scanner results, first/last submission, community reputation | manual/deep scan, suspicious unknowns, not every page |
| Conditional | Cisco Talos | URL/IP/domain category and reputation intelligence | suspicious unknowns, operator-enabled |
| Conditional | WOT-style reputation | crowd/web reputation and categories | weak advisory only; never hard block |
| Operator-gated | Netcraft | phishing, fake shops, support scams, web-inject malware, cryptominers | paid/licensed feed; high-value deployment |
| Operator-gated | APWG eCrime Exchange | phishing/cybercrime exchange | membership/licensed feed |
| Operator-gated | MISP | private/community threat-intel sharing | self-host/operator communities |

Rules:

```text
high-confidence malware feed hit -> hard BLOCK
two independent high-quality hits -> strong BLOCK/WARN
one community/crowd hit -> advisory signal
clean result from any source -> weak positive, not proof of safety
source disagreement -> show disagreement in evidence UI
```

Source governance:

```text
Every external source must define:
- confidence tier
- rate limit
- cost class
- cache TTL
- privacy impact
- false-positive appeal path
- whether it can hard-block or only score
```

No paid/rate-limited source is called on every URL by default. The engine first
uses local cache/feed/trust data, then escalates to conditional sources when the
URL is suspicious, sensitive, unknown, or manually deep-scanned.

## 8. Step 5: Domain And Infrastructure History

Collect:

```text
domain age
registrar
nameserver history
certificate age
certificate issuer
certificate transparency history
ASN
hosting provider
CDN provider
country/region
historical IPs
historical verdicts
historical clean verdicts from independent sessions
historical FP/FN reports and override rates for telemetry only
historical feed hits
```

Signals:

```text
old stable domain -> trust contributor
recently registered domain -> risk contributor
nameserver changed recently -> risk contributor
new cert on sensitive page -> risk contributor
unexpected ASN for known brand -> risk contributor
stable clean history -> trust contributor
high override/report rate -> rule-health signal, not trust contributor
```

Governance rule for historical trust:

```text
One user's override is never a trust signal.
Repeated overrides by the same device are never a global trust signal.
Override counts are rule-health telemetry, not trust evidence.
Only independently verified clean verdict history, not "user clicked proceed",
may contribute weak positive trust.
```

Reason: user overrides are relief valves, not truth. A user repeatedly clicking
"Proceed" must not convert a malicious domain into trusted infrastructure.

## 9. Step 6: Sandbox Render And Capture

Render in isolated Chromium:

```text
no real cookies
no user credentials
bounded network
bounded time
bounded memory
download interception
script instrumentation
form instrumentation
popup instrumentation
clipboard instrumentation
```

Capture:

```text
final URL
redirect chain
screenshot
DOM after JS execution
HTML
forms
inputs
buttons
scripts
iframes
links
downloads
console errors
network requests
XHR/fetch/beacon/WebSocket destinations
clipboard writes
popup attempts
fullscreen attempts
beforeunload traps
```

## 10. Step 7: Page Dissection

Inspect the rendered page:

```text
hidden elements
hidden anchors
cross-origin iframes
password fields
payment fields
OAuth params
install commands
download links
remote support tool links
phone numbers
crypto wallet addresses
gift-card phrases
wire-transfer phrases
tax/refund/government scare phrases
brand names
logos
external scripts
form actions
pre-submit capture
multi-destination sinks
```

Every finding must be tagged:

```text
hard evidence
soft risk
trust evidence
unknown/missing proof
```

## 11. Step 8: Visual, OCR, And QR Analysis

Analyze screenshot:

```text
visual brand match
logo match
pHash similarity
OCR text extraction
QR code extraction
support phone in image
crypto address in image
brand logo in image
fake browser/security warning UI
fake Microsoft/Apple/Google support UI
```

Recursive scan:

```text
QR code URL -> submit back into DeepTrust pipeline
OCR URL -> submit back into DeepTrust pipeline
image-only phone/wallet -> scam evidence
```

## 12. Step 9: Action And Sink Verification

Classify what the page wants the user to do:

```text
read_only
login
password_reset
mfa
payment
oauth_consent
download
developer_install
support_refund
admin_panel
unknown_sensitive
```

Verify action sinks:

| Action | Required Proof |
|---|---|
| login | trusted identity + clean credential sink |
| payment | payment-class page + scoped payment processor trust |
| OAuth | provider, client ID, scopes, redirect URI, publisher |
| command copy | official template or command safety |
| download | source trust, MIME/type, hash, YARA, sandbox |
| support/refund | phone/tool/wallet/gift-card legitimacy |
| read-only | lower proof, but hard evidence still blocks |

## 13. Trust Score

Trust score answers:

```text
Why should we believe this domain/page is legitimate?
```

Initial trust features:

```text
domain age
valid HTTPS
clean threat feeds
clean vendor DNS
known organization
known scoped brand relationship
known CDN/payment/OAuth relationship
stable historical verdicts
Cloudflare/Tranco popularity
stable ASN/CDN
```

Trust score must never suppress hard malicious evidence.

Correct:

```text
high trust + hidden menu links -> suppress weak warning
high trust + credential exfiltration -> BLOCK
high trust + DNS private-IP hijack -> BLOCK
```

Initial implementation alignment:

```text
HighTrustScoreThreshold = 0.70
trust suppresses selected soft rules only
trust does not suppress vendor-DNS consensus, feed-high, raw-IP binary,
public-domain-private-IP, YARA critical, hidden credential mirror,
pre-submit credential capture, or malicious command hard-fail
```

Trust contributors must be shown in evidence UI. If a rule was suppressed by
trust, the decision trace must show the suppressed rule and the reason.

## 14. Risk Score

Risk score answers:

```text
What evidence says this page/action may be harmful?
```

Risk features:

```text
fresh domain
random hostname
homoglyph/typosquat
DNS divergence
unexpected ASN
bad TLS
raw IP
visual brand mismatch
credential sink mismatch
unknown OAuth high scopes
malicious command
hidden iframe
hidden suspicious links
obfuscated JavaScript
popup storm
auto-download
remote support scam language
gift-card/crypto/wire phrases
malware feed hit
download YARA hit
```

Current soft-rule scoring alignment:

```text
softWeightRandomHostname      = 1.0
softWeightObfuscatedJS        = 1.0
softWeightHiddenIframeXOrigin = 1.0
softWeightSuspiciousDownload  = 1.0
softWeightHiddenAnchors       = 1.0
softWeightDNSDivergenceSoft   = 0.5
softWarnThreshold             = 1.0
```

Interpretation:

```text
one full-weight soft rule -> WARN unless trust suppresses it
DNS divergence alone -> transparency signal, no WARN by itself
DNS divergence + another soft rule -> WARN
two soft rules -> higher confidence than one
hard rules bypass this accumulator
```

Future weights must be changed only with corpus evidence and a shadow-mode diff.

## 15. Final Policy

```text
if hard_evidence:
    BLOCK

    examples:
      public_domain_private_ip
      tls_identity_failure_on_sensitive_action
      high_confidence_feed_hit
      credential_mirror
      malicious_command
      raw_ip_binary_drop

if sensitive_action and proof_missing:
    ISOLATE

if risk_score >= mode.block_threshold:
    BLOCK

if risk_score >= mode.warn_threshold:
    WARN

if trust_score high and no risky action:
    ALLOW

else:
    ALLOW or WARN depending mode
```

Hard blocks ignore mode.

Ultra mode requires affirmative clearance.

Current implemented soft-rule baseline:

```text
softWarnThreshold = 1.0
DNS divergence soft weight = 0.5
full soft-rule weights = 1.0 each
```

Target per-mode thresholds for the future generalized risk score:

| Mode | WARN | BLOCK | Notes |
|---|---:|---:|---|
| Normal | 0.70 | 0.95 | low friction |
| Safe | 0.55 | 0.85 | default balanced mode |
| Strict | 0.45 | 0.80 | more warnings |
| Paranoid | 0.35 | 0.75 | sensitive unknown -> isolate |
| Ultra | n/a | n/a | requires full clearance, not threshold-only |

Until the generalized score exists, code constants in `policy.go` are the
source of truth for shipped soft-rule thresholds.

## 16. Example Full Report

```text
Verdict: BLOCK
Confidence: 94%

URL:
https://microsoft-login-verify.example/login

Action:
login

Trust Score:
0.14

Risk Score:
0.92

Hard Evidence:
- password form posts to unrelated host
- visual Microsoft match with identity mismatch

External Sources:
- Google Web Risk: clean
- VirusTotal: 2/95 engines malicious (advisory only; not the block driver)
- URLhaus: no hit
- PhishTank: no hit
- Spamhaus DBL: no hit
- Netcraft: unknown
- AbuseIPDB IP: moderate abuse

Connection Identity:
- browser IP: AS12345 unknown VPS
- expected Microsoft/Akamai ASN: no
- TLS valid: yes
- CDN consistent: no

Page Evidence:
- Microsoft logo detected
- password field present
- form action: https://collector-attacker.example/post
- no same-org relationship
- domain registered 3 days ago

Final Reason:
BLOCK because a sensitive credential action fails brand identity and sink
verification. Clean feed results do not clear a first-seen phishing page.
```

## 17. Test Families

Build generators and corpora around these families. Extend existing
infrastructure first:

```text
tools/fp-bench/          benign/malicious corpus and FP/FN gate
tools/maturity/          extension E2E, RUAT sessions, game-day runbooks
docs/maturity-testing-blueprint.md
docs/real-user-acceptance-test-plan.md
services/verdict-api/internal/oauthreg/     OAuth client/scope registry tests
services/verdict-api/internal/installreg/   official install-command registry tests
```

```text
DNS tests
connection identity tests
CDN variance tests
URL parser tests
wrapper/shortener tests
reputation-source disagreement tests
domain-history tests
TLS/CT tests
ASN/CDN tests
DOM/form/sink tests
JavaScript behavior tests
visual-brand tests
OCR/QR tests
OAuth tests
download tests
command-copy tests
support-scam tests
raw-IP tests
mode-threshold tests
evidence UI tests
latency/chaos tests
```

This should produce thousands of meaningful test cases without writing
thousands of one-off tests by hand.

Required generator outputs:

```text
expected verdict
expected reason codes
expected hard/soft classification
expected latency tier
whether source calls are allowed
whether sandbox/OCR/QR is allowed
```

Every real false positive/false negative discovered during RUAT becomes:

```text
corpus entry
regression test
rule-health event
session-log finding
```

## 18. Implementation Workstreams

This section is subordinate to
[`final-engine-architecture-plan.md`](final-engine-architecture-plan.md). That
document is canonical for cross-engine rollout. This DeepTrust document is
canonical for per-URL investigation depth.

These workstreams are not strictly sequential. External source adapters,
evidence UI, and corpus work can proceed while trust/risk scoring is being
refined. Any enforcement-changing policy work still requires shadow rollout.

### DT-1: Evidence Object

Create one `DeepTrustEvidence` object containing all source outputs:

```text
dns
connection_identity
external_reputation
domain_history
tls
infrastructure
render
visual
action
sink
trust_score
risk_score
policy
```

### DT-2: External Source Aggregator

Add adapters for:

```text
Google Web Risk / Safe Browsing
VirusTotal
URLhaus
PhishTank
Spamhaus DBL
Cloudflare Radar / Tranco
Cisco Talos
Netcraft / APWG if licensed
AbuseIPDB
MISP
WOT-style reputation if licensed/available
```

Adapter acceptance criteria:

```text
bounded timeout
cache TTL
cost class
privacy classification
source confidence tier
unit tests with timeout/error/malformed response
no source can hard-block unless explicitly marked high-confidence
```

### DT-3: Trust Score

Start with available data:

```text
domain age
feed cleanliness
vendor DNS cleanliness
known org
known scoped brand relationship
HTTPS validity
historical clean verdicts
```

### DT-4: Risk Score

Convert noisy soft rules into weighted evidence:

```text
hidden links
random hostname
obfuscated JS
hidden iframe
suspicious download
DNS divergence
```

Keep hard rules separate.

### DT-5: Full Page Dissection

Expand sandbox extraction:

```text
DOM
forms
scripts
links
iframes
downloads
commands
phone/wallet/gift-card text
OCR/QR
network requests
behavioral events
```

### DT-6: Evidence UI

Report:

```text
top trust reasons
top risk reasons
hard evidence
source disagreements
connection identity
missing proof
final policy
```

### DT-7: Corpus And Telemetry

Every wrong decision becomes:

```text
corpus entry
regression test
rule-health event
weekly tuning report
```

### DT-8: Shadow Rollout

Any meaningful policy/scoring change must run in shadow mode before enforcement.

```text
current_policy_verdict
new_policy_verdict
diff_reason
latency_delta
source_cost_delta
```

Promotion criteria:

```text
corpus passes
RUAT passes
no P0 false negatives
false-positive delta within budget
latency SLO unchanged or explicitly approved
source-call cost within budget
top disagreements manually reviewed
```

No large engine rewrite ships directly to enforcement mode.

## 19. Final Standard

DeepTrust is mature when:

```text
DNS first-line checks work
browser actual IP is compared against authorized infrastructure
CDN variance does not false-positive
public-domain-to-private-IP blocks
external sources are normalized and weighted
trust score is explainable
risk score is explainable
hard evidence cannot be suppressed by trust
sensitive actions require proof
evidence UI can explain every verdict
every FP/FN becomes a permanent test
RUAT passes
latency budgets hold
```

Numeric final standard:

```text
normal cached page: p95 <300ms
normal uncached Safe-mode page: p95 <1s
sensitive unknown page: verdict or explicit choice <=12s
manual deep scan: hard cap 90s, partial report allowed
Safe-mode false block rate on personal-100: 0
Safe-mode false warn rate on personal-100: <1%
known-bad corpus false negative rate: 0 for high-confidence feed/hard-rule cases
public-domain-private-IP: always BLOCK
CDN variance: no WARN unless corroborated by another risk signal
```

This is the target engine that makes XGenGuardian a serious anti-scam,
anti-phishing, and zero-trust web investigation platform.
