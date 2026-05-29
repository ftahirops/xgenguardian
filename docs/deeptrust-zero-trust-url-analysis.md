# XGenGuardian DeepTrust Zero-Trust URL Analysis Engine

**Status:** canonical final strategy for per-URL DeepTrust investigation; not
the global architecture roadmap.

**Strategy version:** DeepTrust v2 / final mature-engine target.

**Owner:** XGenGuardian detection-engine maintainers.

**Last reviewed:** 2026-05-29.

**Review cadence:** quarterly, plus immediate review after any P0 false
negative, systemic false-positive class, or major browser/API change.

**Implementation state:** working target spec. Current implementation status is
tracked in §1.1. Cross-engine rollout remains governed by
[`final-engine-architecture-plan.md`](final-engine-architecture-plan.md).

**Precedence:** if this document conflicts with older architectural notes about
per-URL analysis, this document wins. Code and tests remain the final proof of
what is actually shipped.

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

## 0. Final Engineering Verdict

The mature XGenGuardian engine is not a domain list, a DNS blocklist, a visual
matcher, or a sandbox by itself. It is an evidence-fusion system:

```text
one URL
one canonical evidence object
many bounded detectors
one decision kernel
one evidence report
one feedback loop
```

Final design stance:

```text
DNS is line one, never the only line.
The browser's actual connection identity is mandatory evidence.
Big-company domains are not automatically safe.
CDN variance is normal and must be modeled, not guessed.
Hard malicious evidence always wins.
Soft suspicious evidence must compose, not short-circuit randomly.
Trust can suppress weak soft signals, never hard evidence.
Sensitive actions require stronger proof than read-only pages.
Manual deep scan may be slow; live browsing may not hang.
Every wrong verdict becomes corpus, test, and rule-health data.
```

This is the design that stops the trust-registry stuffing pattern. A reported
false positive must not be fixed by adding the host to a global allowlist unless
the host belongs to the small global identity/payment/government tier where all
users benefit. Ordinary false positives go through corpus + structural fix.

## 0.1 Security Standards This Strategy Follows

DeepTrust is aligned to these external engineering principles:

| Source | Principle Applied Here |
|---|---|
| CISA Secure by Design | XGenGuardian owns customer security outcomes; safety is measured, not pushed onto the user. |
| NIST CSF 2.0 | Govern/identify/protect/detect/respond/recover maps to policy governance, source inventory, protective verdicts, telemetry, triage, and corpus recovery. |
| OWASP ASVS | Security controls require repeatable verification, not developer claims. |
| MITRE ATT&CK phishing techniques | Detectors map to real attacker techniques such as spearphishing links, malicious attachments/downloads, credential theft, and social-engineering flows. |

References:

- CISA Secure by Design: <https://www.cisa.gov/securebydesign>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
- OWASP ASVS: <https://owasp.org/www-project-application-security-verification-standard/>
- MITRE ATT&CK Spearphishing Link: <https://attack.mitre.org/techniques/T1598/003/>

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
| T3 live deep analysis | 8-45s, hard cap 90s | sensitive unknown, Ultra, suspicious live browsing | sandbox render, visual match, OCR/QR, download probe | isolate/manual choice if not ready |
| T4 exhaustive investigation | 2-30 minutes, operator cap | manual "deep scan", analyst queue, high-risk report | multi-region DNS, recursive crawl graph, paid source fanout, detonation, OCR/QR recursion, archive unpacking, repeated render passes | asynchronous report; not used to hold live browsing |

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

## 3.2 Final Mature Architecture

The mature engine is organized as a pipeline of pure evidence producers feeding
one policy decision kernel.

```text
request
  -> normalizer
  -> wrapper/redirect expander
  -> DNS and resolver-ledger collector
  -> browser connection-identity collector
  -> reputation source aggregator
  -> domain/infrastructure history collector
  -> sandbox/render collector
  -> page graph builder
  -> visual/OCR/QR analyzer
  -> action/sink classifier
  -> DeepTrustEvidence object
  -> hard-evidence gate
  -> trust/risk/action scorer
  -> mode policy matrix
  -> verdict + evidence report + telemetry
```

Engineering rule:

```text
detectors emit evidence, not final verdicts
the decision kernel emits the verdict
```

Exceptions are hard-evidence modules. A detector may mark evidence as
`hard_block_eligible`, but the central hard-evidence gate still performs the
final short-circuit. This keeps the system explainable and prevents scattered
rules from mutating verdicts independently.

## 3.3 Canonical Evidence Object

Every analysis path writes into one versioned object. This object is the
contract between detectors, policy, UI, tests, telemetry, and future ML.

```text
DeepTrustEvidence v1
  request:
    original_url
    normalized_url
    registrable_domain
    user_mode
    client_id_hash

  unwrap:
    wrapper_chain[]
    redirect_chain[]
    final_url

  dns:
    xgg_resolver_answers[]
    public_resolver_answers[]
    authoritative_ns
    cname_chain
    ttl_profile
    dnssec_state
    nxdomain_or_failure

  connection_identity:
    browser_remote_ip
    browser_remote_asn
    browser_tls_cert
    sni
    http_host
    resolver_ledger_match
    authorized_cdn_or_asn_match
    private_ip_for_public_domain

  reputation:
    source_results[]
    feed_hits[]
    vendor_dns_results[]
    source_disagreements[]

  domain_history:
    rdap_age
    registrar
    nameserver_age
    ct_log_history
    cert_issuer_history
    asn_history
    hosting_reputation

  page_graph:
    nodes[]
    edges[]
    forms[]
    scripts[]
    iframes[]
    downloads[]
    network_requests[]
    extracted_urls[]

  content:
    dom_summary
    visible_text
    ocr_text
    qr_urls[]
    phone_numbers[]
    wallets[]
    gift_card_phrases[]
    remote_tool_mentions[]

  visual:
    brand_matches[]
    favicon_matches[]
    screenshot_hashes[]
    logo_regions[]

  action:
    class
    sensitivity
    required_proof[]
    observed_sinks[]
    missing_proof[]

  scoring:
    trust_score
    trust_contributors[]
    risk_score
    risk_contributors[]
    hard_evidence[]
    suppressed_soft_evidence[]

  policy:
    verdict
    confidence
    reason_codes[]
    decision_trace[]
    latency_tier
    source_cost
```

Versioning rule:

```text
fields may be added with defaults
fields may not become required without a schema version bump
policy must tolerate absent fields from older producers
```

## 3.4 Decision Kernel Contract

The final decision kernel is the only place where `ALLOW`, `WARN`, `ISOLATE`,
or `BLOCK` is chosen.

```text
1. Hard evidence gate
2. Sensitive-action proof gate
3. Trust/risk/action score gate
4. Mode threshold gate
5. Evidence/report generation
```

Hard evidence examples:

```text
public-domain-to-private-IP
browser connected to unauthorized IP with TLS identity failure
high-confidence feed hit
confirmed credential exfiltration
malicious command
known malware hash/YARA
raw IP serving botnet binary
confirmed drive-by download
```

Soft evidence examples:

```text
random hostname
fresh domain
DNS divergence on CDN-like host
hidden iframe
hidden anchors
obfuscated JavaScript
suspicious download text
weak visual brand match
low-confidence external source hit
```

Trust evidence examples:

```text
old stable domain
clean high-confidence feeds
valid TLS identity
known organization graph
known scoped CDN/payment/OAuth relation
stable ASN/cert/nameserver history
authorized CDN edge match
```

Trust suppression rule:

```text
trust may suppress weak soft evidence
trust may reduce WARN to ALLOW on read-only pages
trust may not suppress hard evidence
trust may not clear sensitive-action proof failures
```

This is the central anti-false-positive design: benign sites stop being harmed
by weak signals, while real attacks still block when evidence is strong.

## 3.5 Live Scan vs Exhaustive Scan

XGenGuardian has two product modes with different promises.

| Mode | Goal | Time Budget | Output |
|---|---|---:|---|
| Live browser protection | protect the user without breaking browsing | 0-12s before choice UI | verdict + concise evidence |
| Exhaustive DeepTrust investigation | dissect one URL from every angle | minutes, operator-configured | full dossier + graph + source matrix + artifacts |

Exhaustive scan may do things live browsing must not do:

```text
multi-region DNS resolution
repeated render passes over time
full link graph crawl with depth limit
OCR/QR recursive URL extraction
archive unpacking
download detonation in isolated network namespace
paid reputation fanout
TLS/CT historical analysis
ASN/hosting reputation expansion
similar-domain search
campaign clustering
LLM-assisted scam-language classification over sanitized text
manual analyst review queue
```

Exhaustive scan must be asynchronous. It can keep improving a report after the
initial verdict, but it must not hold a browser tab hostage.

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

Resolver strategy:

```text
browser may use any resolver
XGG still runs its own resolver path
XGG stores what its resolver returned per client/domain/TTL
extension reports what the browser actually connected to
policy compares both paths with CDN-aware rules
```

The XGG resolver is not optional for mature deployments. It provides the
baseline needed to detect user-side DNS manipulation. Without a returned-IP
ledger the server can only say "my DNS looked safe"; it cannot prove the user
reached the same infrastructure.

Required DNS evidence:

| Evidence | Why It Matters |
|---|---|
| recursive answer set | what XGG would have returned |
| authoritative answer set | whether recursive answers match the domain's authority |
| CNAME chain | CDN and SaaS ownership path |
| TTL profile | fast-flux and suspicious low-TTL patterns |
| DNSSEC state | signed/unsigned/broken signature context |
| multi-region answers | CDN variance vs localized poisoning |
| returned-IP ledger | user-path comparison |
| sinkhole/private-IP detection | hard hijack evidence |

DNS alone never clears a site. DNS can only contribute:

```text
hard block evidence
soft risk evidence
trust evidence
missing-proof evidence
```

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

The mature comparison is set-based:

```text
browser_remote_ip ∈ authorized_answer_set(domain, client_region, timestamp)
```

Where `authorized_answer_set` is derived from:

```text
XGG resolver returned IPs within TTL
authoritative DNS answer set
CNAME/CDN ownership
known CDN edge ASN ranges
TLS certificate SAN/CN identity
SNI and HTTP Host consistency
historical ASN/cert/nameserver profile
operator allowlist for private infrastructure
```

Verdict behavior:

| Case | Verdict Behavior |
|---|---|
| public domain resolves to private IP | hard BLOCK |
| browser IP not in XGG ledger but TLS/cert/ASN/CDN are valid | soft DNS divergence, usually no block alone |
| browser IP not in ledger and ASN/cert/CDN mismatch | ISOLATE or BLOCK on sensitive action |
| browser IP private for public domain | hard BLOCK |
| browser IP matches known CDN ASN but not exact returned IP | ALLOW/WARN based on other evidence |
| browser IP missing from extension | mark connection identity missing; do not pretend verified |

TLS identity is required for DNS-poisoning resistance. An attacker can make a
domain resolve to their IP, but they normally cannot present a valid certificate
for the target host unless the device also trusts a malicious root CA or the
attacker controls certificate issuance. Therefore:

```text
DNS mismatch + valid TLS + authorized CDN ASN -> soft signal
DNS mismatch + invalid TLS on sensitive action -> hard/near-hard signal
public-domain-to-private-IP -> hard signal even before TLS
```

This design handles large companies correctly. Google, Microsoft, Cloudflare,
Amazon, Akamai, Fastly, and CloudFront-backed sites may legitimately use many
IPs. The system should verify authorized infrastructure, not demand exact IP
equality.

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

The final policy implementation must be a single decision kernel. Legacy
fusion, strictness remapping, trustscore suppression, and staged policy may
exist during migration, but mature production has one authoritative decision
path:

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

Production decision-kernel invariants:

```text
one request -> one evidence object -> one decision kernel -> one verdict
no detector directly mutates final verdict outside the hard-evidence gate
all hard blocks include hard_evidence[]
all WARN/ISOLATE decisions include top risk contributors
all ALLOW decisions on sensitive actions include required proof
all suppressed soft evidence is logged and explainable
all missing critical evidence is explicit, never silently treated as pass
```

Sensitive-action proof matrix:

| Action | Minimum Proof Required | Missing Proof Result |
|---|---|---|
| read-only page | DNS/reputation sanity, no hard evidence | ALLOW/WARN by risk |
| login/password | identity binding, valid TLS, safe credential sink | ISOLATE or BLOCK |
| OAuth consent | known provider, scoped client risk, redirect sanity, scope severity | WARN/ISOLATE/BLOCK |
| payment/checkout | payment processor scope, form/iframe sink verification | ISOLATE if unknown |
| download/install | download URL, file reputation/hash/YARA, official command registry if command-copy | WARN/BLOCK |
| support/contact | phone/wallet/remote-tool scam extraction, brand/domain relation | WARN/BLOCK if scam indicators |
| QR/link handoff | recursive URL scan of extracted target | same as extracted URL |

Mode behavior:

```text
Normal: minimize friction, hard evidence still blocks
Safe: default balance, sensitive unknowns may isolate
Strict: lower soft-risk thresholds, stricter download/scam handling
Paranoid: sensitive proof missing -> isolate aggressively
Ultra: default-deny unless every clearance gate passes
Manual DeepTrust: no friction constraint; produce full dossier
```

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

### DT-0: Collapse Verdict Paths

Before adding more detectors, collapse the runtime into one authoritative
decision path.

Current migration smell:

```text
fusion.Score still runs
policy.Apply makes the newer decision
strictness still references fusion-era behavior
trustscore suppresses some soft rules
connection-identity enrichment is partly post-decision
```

Target:

```text
fusion becomes either:
  - a detector that emits visual/form evidence into DeepTrustEvidence, or
  - deleted after parity tests pass

strictness becomes:
  - mode thresholds inside the decision kernel

trustscore becomes:
  - one component of DeepTrustEvidence.scoring

connection identity becomes:
  - pre-policy evidence, not only response enrichment
```

Acceptance criteria:

```text
one exported production decision function
legacy fallback available only behind explicit shadow/debug flag
all existing policy/fusion/strictness tests ported or mapped
100% parity on current corpus where old behavior is intentionally preserved
documented intentional diffs for improved behavior
no new detector may return final verdict directly
```

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

External source rollout order:

```text
1. finish wrapper unwrappers: SafeLinks, Proofpoint, Mimecast, Cisco, Barracuda
2. AbuseIPDB for raw IP / unexpected ASN / DNS divergence
3. Google Web Risk / Safe Browsing conditional checks
4. VirusTotal only for manual/deep scan and suspicious unknowns
5. Netcraft/APWG/MISP only for licensed/operator deployments
```

Reason: wrapper unwrapping improves real enterprise-email coverage more than
adding another reputation source. It reveals the actual destination before
scoring and reduces both false positives on wrappers and false negatives hidden
behind wrappers.

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

Page graph acceptance criteria:

```text
landing URL is one node, not the whole truth
every form action becomes a sink node
every iframe/script/download becomes a graph node
every QR URL becomes a recursively scanned node
every redirect hop is preserved
same-organization edges are distinguished from third-party edges
cross-origin does not mean malicious; unauthorized sensitive sink does
```

Graph verdict rule:

```text
a read-only clean landing page may still BLOCK if a graph child performs a
credential/payment/download/command action that fails identity verification
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

### DT-9: Exhaustive DeepTrust Worker

Build a separate asynchronous worker for T4 exhaustive investigation. Do not
put these operations on the live `/v1/check` path.

Capabilities:

```text
multi-region DNS and authoritative DNS comparison
full crawl graph with depth/page/time limits
OCR and QR recursion
download detonation in separate network namespace
archive unpacking
source fanout to paid/slow providers
similar-domain and campaign clustering
repeated render passes at t+0, t+5m, t+30m for cloaking
sanitized LLM-assisted scam-language classification
analyst annotation queue
```

Acceptance criteria:

```text
job queue with per-user and per-domain limits
partial report emitted within 90s
full report continues asynchronously
all artifacts retention-controlled
no credentials/cookies from user browser enter sandbox
download detonation cannot reach production network
every child URL has its own evidence object
```

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

Numeric final standard for release:

```text
normal cached page: p95 <300ms
normal uncached Safe-mode page: p95 <1s
sensitive unknown page: verdict or explicit choice <=12s
manual deep scan: partial report <=90s, full report async <=30m unless operator extends
Safe-mode false block rate on personal-100: 0
Safe-mode false warn rate on personal-100: <1%
known-bad corpus false negative rate: 0 for high-confidence feed/hard-rule cases
public-domain-private-IP: always BLOCK
CDN variance: no WARN unless corroborated by another risk signal
```

Numeric final standard for broad corpus:

```text
Safe mode WARN+ false-positive rate on curated benign corpus: <=0.5%
Safe mode BLOCK false-positive rate on curated benign corpus: <=0.1%
Strict mode WARN+ false-positive rate: <=2%
Ultra mode isolate false-positive rate: expected higher, but BLOCK FP <=0.5%
high-confidence feed/hard-rule false-negative rate: 0
fresh-phishing corpus recall target: >=80% in Safe, >=90% in Strict/Ultra
credential-sink phishing recall target: >=95% when sandbox data available
visual-brand phishing recall target: >=90% when visual service available
support-scam recall target: >=75% after OCR/phone/wallet detectors ship
QR phishing recall target: >=80% after QR recursion ships
```

Operational final standard:

```text
all production verdicts come from one decision kernel
sandbox-render and visual-match health are release gates
source adapters have timeout, TTL, cost class, and privacy class
T4 deep scans are queued and rate-limited
new policy ships shadow-first
top policy disagreements reviewed before enforcement
weekly rule-health report lists top FP/FN-producing reasons
every P0/P1 finding produces corpus + test + code/doc update
```

Threat coverage target at maturity:

| Threat Family | Mature Target |
|---|---|
| DNS known-bad / malware / C2 | A |
| local DNS hijack / router compromise | A |
| public domain to private IP | A |
| raw-IP malware drops | A |
| credential phishing with wrong sink | A |
| visual brand impersonation | A- |
| OAuth consent phishing | B+ |
| ClickFix / command-copy attacks | A- |
| malicious downloads | A- |
| compromised legitimate site | B+ |
| SafeLinks/Proofpoint/Mimecast wrapped phishing | B+ |
| support scam / fake helpdesk | B+ after OCR/scam extraction |
| QR-code phishing | B+ after QR recursion |
| crypto-drainer / wallet fraud | B after wallet/action classifiers |
| unknown zero-day phishing | B+ with sandbox+visual+action graph, not A because no zero-day detector is perfect |

The product is never called "done" because a document says so. It is called
mature only when the metrics above pass continuously.

## 20. Non-Negotiable Engineering Rules

```text
1. No global trustreg additions for ordinary false positives.
2. No detector owns final verdict except through the central hard-evidence gate.
3. No paid source runs on every URL by default.
4. No sensitive page is silently allowed when required proof is missing.
5. No DNS result is treated as proof of safety.
6. No exact-IP comparison for CDN-backed domains.
7. No user override becomes global trust evidence.
8. No engine rewrite ships without shadow-mode comparison.
9. No report hides missing evidence.
10. No real-user bug is closed without a corpus entry and regression test.
```

These rules matter more than adding another detector. They are what prevent the
system from drifting back into patching symptoms.

This is the target engine that makes XGenGuardian a serious anti-scam,
anti-phishing, and zero-trust web investigation platform.
