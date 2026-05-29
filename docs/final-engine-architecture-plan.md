# XGenGuardian Final Engine Architecture Plan

## Status (as of 2026-05-29)

| Phase | State | Notes |
|---|---|---|
| **A — Stop The Bleeding** | ✅ **Shipped** | orggraph (26 orgs), `xgg_rule_fired_total`, PR template, `CLAUDE.md` three-tier policy, FP-driven trustreg entries reverted, corpus + regression tests added. Tier 2 user-allowlist UI is **not** yet built — tracked for the extension Options page. |
| **B — DNS + Connection Identity** | ✅ **Shipped (B.5a)** | `internal/connid` contract + 8 reason codes; extension `browser_remote_ip` capture via `chrome.webRequest.onResponseStarted`; `PUBLIC_DOMAIN_PRIVATE_IP` hard rule (pre-Stage-0, ignores trust); `internal/iledger` resolver write + verdict-api read; `USER_DNS_PATH_MATCH/MISMATCH/EXPECTED_RESOLVER_BYPASSED` emitted; blocked-page UI row; `make ruat-connection-identity` Makefile target. **B.5b deferred:** CDN_ASN_*, TLS_IDENTITY_MISMATCH, LOCAL_RESOLVER_HIJACK_SUSPECTED need ASN tables + TLS introspection that don't exist yet. |
| **C — Scoped Trust** | ✅ **Shipped (conservative)** | brandgraph backfilled from trustreg (curated narrow scopes preserved); all 4 production call sites moved from `trustreg.IsTrusted` → `brandgraph.IsAnyTrust`; `policy.Inputs` gained 7 scoped fields (`TrustedForLogin/Payment/OAuth/Script/CDN/Docs/AnyScope`) populated from `brandgraph.Trust(host, scope)`. `TrustedIdentity` retained as legacy alias for `TrustedAnyScope` — Phase D rewrites soft rules to consult the right scope and removes the alias. |
| **D — Trust Score** | ✅ **Shipped (additive)** | `internal/trustscore/` package — pure function aggregating domain age, feed/vendor-DNS cleanliness, brand/org membership, HTTPS validity into a 0.0–1.0 score with named contributors. Populated on `policy.Inputs` from existing context + brandgraph + orggraph. Surfaced on `checkResponse.trust_score` + `trust_contributors` and rendered in the extension's blocked-page evidence UI as "Trust score: 0.74 / 1.00" + a contributor list. **No rule consults the score yet** — Phase E rewrites soft rules to suppress on trust. |
| **E — Soft Rule Scoring** | ⏳ Pending | Refactor the 6 soft rules listed in §25 into weighted risk deltas. |
| **F — Shadow Engine** | ⏳ Pending | Old vs new policy diff log, 2–3 week soak. |
| **G — Data Flywheel** | ⏳ Pending | Override telemetry, labeling, weekly rule-health report. |

**Governance artifacts in force:**
- [`CLAUDE.md`](../CLAUDE.md) — "Three-tier trust policy" + "Definition of a Real Fix" + hard-vs-scored rule guidance
- [`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md) — 6-bullet contract enforced on every PR
- [`internal/orggraph/`](../services/verdict-api/internal/orggraph/) — same-org cross-origin collapsing (**membership ≠ trust**)

---

This is the target architecture for a mature XGenGuardian detection engine.
It consolidates the current lessons from false positives, raw-IP handling,
DNS divergence, trust registry overuse, real-user acceptance testing, and
engine refactoring.

The goal is not to replace every rule with vague scoring. The goal is a
production-grade security engine:

```text
DNS first line of defense
+ connection identity verification
+ hard evidence short-circuits
+ scoped trust graph
+ positive trust score
+ soft risk score
+ action-aware policy
+ evidence UI
+ telemetry/corpus feedback loop
```

## 1. Core Diagnosis

The product vision is strong:

```text
Protect users before risky web actions:
DNS lookup, navigation, login, payment, OAuth, command copy, download, popup.
```

The current weakness is not the idea. The weakness is that the active
detection path is still too often:

```text
single rule fires -> WARN/BLOCK
false positive appears -> add domain to trustreg
```

That does not scale. There are millions of legitimate sites.

The mature path must be:

```text
reported issue
  -> add corpus case
  -> reproduce wrong verdict
  -> identify exact rule or missing feature
  -> structural fix
  -> verify benign corpus
  -> verify malicious corpus
  -> ship with regression test
```

## 2. Final Architecture

```text
User / Browser / Device
  |
  | DNS query, navigation, copy, OAuth, form submit, download
  v
+---------------------------+
| 1. XGG DNS Resolver       |
| - known-bad block         |
| - category policy         |
| - rebind protection       |
| - returned-IP ledger      |
+-------------+-------------+
              |
              v
+---------------------------+
| 2. Browser Extension      |
| - full URL                |
| - opener/popup context    |
| - actual browser IP       |
| - copy-command events     |
| - interstitial UI         |
+-------------+-------------+
              |
              v
+---------------------------+
| 3. Verdict API            |
| - normalization           |
| - wrapper unwrap          |
| - connection identity     |
| - feature extraction      |
+-------------+-------------+
              |
              v
+---------------------------+
| 4. Evidence Engines       |
| - feeds/vendor DNS        |
| - domain/cert/ASN         |
| - org graph               |
| - trust score             |
| - risk score              |
| - sandbox/visual/sink     |
+-------------+-------------+
              |
              v
+---------------------------+
| 5. Action Policy Matrix   |
| - hard evidence first     |
| - scoped trust            |
| - weighted soft signals   |
| - mode thresholds         |
+-------------+-------------+
              |
              v
ALLOW / WARN / ISOLATE / BLOCK / REQUIRE_APPROVAL / DETONATE
```

## 3. Side-By-Side: Current vs Target

| Area | Current Pattern | Final Target |
|---|---|---|
| First line of defense | DNS exists but browser/API often dominate | DNS resolver is line 1 and records returned IPs per client/domain/TTL |
| DNS poisoning handling | backend DNS may say safe while user DNS differs | compare browser actual IP vs XGG resolver answer vs authorized CDN/ASN/TLS |
| Trust model | flat `trustreg.IsTrusted(host)` escape hatch | scoped trust: login, payment, CDN, docs, OAuth, support, app, API |
| False positive fix | add domain to trustreg too often | add corpus case + structural rule fix; user-specific relief via user allowlist |
| Hard evidence | mixed with softer rules inside policy | separate hard-evidence layer with short-circuit BLOCK |
| Soft signals | many direct WARN/BLOCK branches | soft signals emit risk deltas; final score decides |
| Positive evidence | mostly trusted identity and a few exceptions | explicit trust score from age, cert, clean history, org graph, CDN/ASN |
| Organization ownership | orggraph live (26 orgs, Phase A); brandgraph scopes pending (Phase C) | org graph is load-bearing for same-company links/sinks |
| Action model | URL path/pageclass plus scattered logic | canonical action object from URL + DOM + forms + sinks + scripts |
| Raw IP policy | public raw IP blocks unless trusted | private/local bypass; public raw IP aggressive scan; raw-IP binary hard block |
| CDN handling | risk of comparing one backend IP to one user IP | compare against authorized infrastructure set, not a single IP |
| Modes | separate rule behavior in places | hard rules constant; modes adjust thresholds and unknown-sensitive handling |
| Explainability | clear reason codes, often one dominant rule | keep reason codes plus top risk contributors, trust contributors, missing proof |
| Telemetry | incomplete | per-rule fire/override/report counters and weekly rule-health report |
| Testing | maturity/corpus exists but still growing | corpus-first PR gate + RUAT + shadow-mode old/new engine comparison |
| Release discipline | large mixed changes happened during stabilization | small PRs, one behavior change per PR, acceptance criteria required |

## 4. DNS As First Line Of Defense

DNS must be the first line, because it is fast and network-wide.

DNS resolver responsibilities:

```text
known malware/phishing/C2 block
content/category block
DNS rebinding protection
public-domain-to-private-IP detection
policy modes for devices/users
returned-IP ledger for connection identity
```

DNS should not be the only decision layer because DNS cannot see:

```text
full URL path
page DOM
forms
OAuth scopes
copied command
download hash
visual impersonation
browser opener
raw IP typed directly in the URL bar
```

The correct principle:

```text
DNS blocks known-bad early.
Browser/API verifies risky actions deeply.
```

## 5. Returned-IP Ledger

When the user uses XGG DNS, the resolver must store exactly what it returned:

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

This lets verdict-api answer:

```text
Did the user's browser connect to an IP that our resolver recently returned?
```

If yes:

```text
DNS path consistent.
```

If no:

```text
possible local DNS bypass, browser DoH, VPN DNS, hosts-file hijack,
router compromise, ISP/captive portal rewrite, or malicious resolver.
```

## 6. Connection Identity Verification

Backend DNS alone is not enough.

The backend may see:

```text
bank.example -> real safe IP
```

But the user's browser may reach:

```text
bank.example -> attacker IP
```

This can happen through:

```text
local DNS poisoning
router DNS hijack
malicious ISP resolver
compromised hosts file
browser DoH bypass
VPN/corporate DNS override
captive portal rewrite
malware-installed root CA
```

The browser extension should capture the actual remote IP when the browser
connects. In Chromium this can often be obtained from `chrome.webRequest`
events such as `onResponseStarted` / `onCompleted` via `details.ip`.

Verdict API receives:

```json
{
  "url": "https://example.com/login",
  "browser_remote_ip": "203.0.113.55"
}
```

Then verdict-api compares:

```text
browser actual IP
vs XGG resolver returned IPs for this client/domain/TTL
vs backend trusted resolver answers
vs historical domain infrastructure
vs CDN/ASN/org ownership
vs TLS certificate identity
```

## 7. CDN-Safe IP Comparison

Never compare one backend IP to one user IP.

Large sites use:

```text
CDN geolocation
anycast
EDNS client subnet
regional load balancing
IPv4/IPv6 split
short TTL rotation
multiple ASNs
```

Wrong design:

```text
backend resolver sees 142.250.1.1
user browser sees 142.251.9.10
therefore DNS poisoning
```

Correct design:

```text
user_connected_ip ∈ authorized infrastructure set
```

Authorized infrastructure set is built from:

```text
recent XGG resolver answers for that user
trusted public resolver answers
CNAME chain
known CDN ownership
expected ASN set
TLS certificate validity
certificate transparency history
org graph
historical IPs seen for the domain
```

Decision examples:

| Case | Verdict |
|---|---|
| exact browser IP matches XGG returned IP | pass connection identity |
| different IP but same CDN/ASN and valid TLS | pass or soft pass |
| different IP, unexpected ASN, valid TLS but unusual | WARN/ISOLATE |
| different IP, bad TLS or cert mismatch | BLOCK |
| public domain resolves to RFC1918/private IP | BLOCK |
| user connected IP differs from XGG resolver answer and not CDN-consistent | ISOLATE |

## 8. Connection Identity Object

Add a first-class object:

```json
{
  "domain": "example.com",
  "browser_remote_ip": "203.0.113.10",
  "xgg_resolver_ips_for_client": ["203.0.113.10", "203.0.113.11"],
  "backend_resolver_ips": ["203.0.113.12"],
  "cname_chain": ["example.com", "example.cdn.cloudflare.net"],
  "browser_remote_asn": 13335,
  "expected_asns": [13335],
  "tls_valid_for_host": true,
  "dns_path_consistent": true,
  "cdn_consistent": true,
  "connection_identity_confidence": 0.92
}
```

Reason codes:

```text
USER_DNS_PATH_MATCH              ✅ B.5a — emitted
USER_DNS_PATH_MISMATCH           ✅ B.5a — emitted
CDN_ASN_MATCH                    ⏳ B.5b — registered, not emitted
CDN_ASN_MISMATCH                 ⏳ B.5b — registered, not emitted
PUBLIC_DOMAIN_PRIVATE_IP         ✅ B.3  — hard BLOCK
TLS_IDENTITY_MISMATCH            ⏳ B.5b — registered, not emitted
EXPECTED_RESOLVER_BYPASSED       ✅ B.5a — emitted (opted-in + empty ledger)
LOCAL_RESOLVER_HIJACK_SUSPECTED  ⏳ B.5b — registered, not emitted
```

Evidence UI must show:

```text
Your browser connected to:
203.0.113.55 / AS12345 Unknown VPS

Independent resolvers expected:
142.250.190.14 / AS15169 Google

This may mean local DNS, router, VPN, ISP, hosts file, or browser DoH
redirected the domain.
```

## 9. Hard Evidence Layer

Hard evidence stays as short-circuit BLOCK. It must not be reduced by trust
score.

Examples:

```text
high-confidence URLhaus/OpenPhish/WebRisk hit
multi-provider vendor DNS consensus
known malware hash/YARA critical hit
raw IP serving botnet architecture binary
confirmed credential mirror to attacker domain
pre-submit credential exfiltration
malicious PowerShell/mshta/rundll32 command
confirmed brand impersonation + sink mismatch
public domain resolving to private IP
TLS certificate identity mismatch on sensitive action
```

Principle:

```text
Trusted sites can be compromised.
Hard malicious facts override trust.
```

## 10. Scoped Trust Layer

Flat trust is unsafe.

Bad:

```text
host trusted -> allow everything
```

Good:

```text
host trusted for login
host trusted for payment
host trusted for CDN
host trusted for docs
host trusted for OAuth redirect
host trusted for support
```

Examples:

| Host | Scope |
|---|---|
| `accounts.google.com` | login |
| `checkout.stripe.com` | payment |
| `gstatic.com` | script/CDN |
| `docs.anthropic.com` | docs/install |
| `login.microsoftonline.com` | login/OAuth |

Important:

```text
gstatic.com trusted as CDN does not mean trusted as password destination.
stripe.com trusted for payment does not mean trusted as Microsoft login.
```

## 11. Trust Registry Governance

Trust registry is allowed, but only with governance.

| Tier | Purpose | Examples |
|---|---|---|
| Tier 0 | critical global providers | Google, Microsoft, Apple, GitHub, Cloudflare, Stripe, PayPal |
| Tier 1 | curated global targets | banks, governments, universities, top SaaS, major crypto exchanges |
| Tier 2 | user-specific allowlist (per-user, `chrome.storage.local`) | personal sites, company intranet, self-hosted IPs, niche tools |
| Tier S | organization graph (`orggraph`) — same-org cross-origin counting | Disney → moviesanywhere/hulu/espn/marvel; Alphabet → google/youtube |

**Tier S is not trust.** Membership in the org graph means "for cross-origin-anchor and sink counting, treat these as the same entity." It does NOT permit credential sinks, downloads, OAuth scopes, or any other action-bearing trust. Trust comes from Tier 0/1 + scoped trust + trust score, never from orggraph membership alone.

Rule:

```text
Global trustreg is for everybody.
User allowlist is for one user.
False positives do not automatically enter global trustreg.
```

Trustreg candidate requirements:

```text
global user impact
high impersonation target
verified ownership
scoped action relationship
corpus tests added
code-owner review
```

## 12. Organization Graph

Organization graph answers:

```text
Which domains belong to the same real-world company?
```

Example:

```text
Disney:
  disney.com
  moviesanywhere.com
  hulu.com
  espn.com
  marvel.com
```

Then:

```text
moviesanywhere.com -> disney.com
```

is not treated like random cross-origin linking.

Org graph sources:

```text
manual seed for top orgs
official website links
certificate transparency clustering
known app/store publisher metadata
public documentation
operator review queue
commercial data source later if needed
```

Do not claim the org graph is complete. Start with top 30 organizations,
then expand from false positives and high-traffic telemetry.

## 13. Graphs To Build

Build multiple targeted graphs, not one blind internet crawl.

| Graph | Question Answered |
|---|---|
| Organization graph | which domains belong to same company |
| Link graph | which destinations this site normally links to |
| Redirect graph | where wrappers/shorteners actually send users |
| Sink graph | where credentials/payments/OAuth/forms go |
| Script/CDN graph | which scripts/CDNs are normal for this domain |
| Download graph | which hosts normally serve files for this brand |
| OAuth graph | client IDs, scopes, redirect URIs, publishers |

Targeted crawl priorities:

```text
top protected brands
user-reported false positives
fresh suspicious domains
known phishing kits
redirect wrappers
login/payment/OAuth pages
download/install pages
high-traffic domains
```

Avoid blind full-internet crawling. It is expensive, noisy, and creates
privacy/retention burdens.

## 14. Positive Trust Score

Trust score is positive evidence.

It should suppress weak suspicion, not override hard malicious facts.

Initial features:

```text
domain age
certificate age/history
feed cleanliness
vendor DNS cleanliness
known organization
known CDN/payment/OAuth relationship
HTTPS validity
historical clean verdicts
```

Later features:

```text
Tranco rank
ASN reputation
CDN registry
nameserver stability
certificate transparency stability
brand graph confidence
```

Correct use:

```text
old clean domain + hidden menu links -> suppress WARN
old clean domain + credential exfiltration -> BLOCK
```

Incorrect use:

```text
adjusted_risk = risk - trust
```

That can allow compromised trusted sites.

Better:

```text
trust modifies only soft signals
trust may cap severity for weak evidence
trust never suppresses hard evidence
```

## 15. Risk Score

Soft rules emit risk deltas.

Examples:

```text
hidden suspicious links: +0.10
random-looking hostname: +0.20
fresh sensitive domain: +0.25
weak visual match: +0.15
single vendor DNS hit: +0.25
weak obfuscated JS: +0.10
cross-origin hidden iframe: +0.10
unexpected ASN: +0.25
DNS divergence without TLS failure: +0.35
```

These should not directly mutate verdict unless they cross the policy
threshold after aggregation.

## 16. Action Classifier

Action is not just URL path. Build it from:

```text
URL path
page title
DOM forms
password fields
payment fields
OAuth params
download links
command blocks
button text
XHR/fetch/form destinations
opener context
```

Actions:

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

Two-phase model:

```text
cheap_action_guess     from URL/path/known wrappers
verified_action        from sandbox DOM/sinks/scripts
```

This avoids forcing Tier-2 on every page while still correcting action
classification when deep evidence is available.

## 17. Policy Matrix

Hard evidence applies before scoring.

Then action-aware thresholds apply.

Example:

```text
if hard_block:
    BLOCK

if connection_identity_fail_high:
    BLOCK

if sensitive_action and proof_missing:
    ISOLATE

if soft_risk >= mode.block_threshold:
    BLOCK

if soft_risk >= mode.warn_threshold:
    WARN

ALLOW
```

Mode thresholds:

| Mode | WARN | BLOCK | Extra Behavior |
|---|---:|---:|---|
| Normal | 0.70 | 0.95 | low friction |
| Safe | 0.55 | 0.85 | default |
| Strict | 0.45 | 0.80 | more warnings |
| Paranoid | 0.35 | 0.75 | sensitive unknown -> isolate |
| Ultra | n/a | n/a | full clearance required |

Hard blocks ignore mode.

## 18. Raw IP Policy

Raw IP handling must be aggressive but scoped.

| Case | Verdict |
|---|---|
| private/local IP (`127.0.0.1`, `10/8`, `192.168/16`, `172.16/12`) | extension bypass/local policy |
| operator-trusted IP | allow/trust-but-log |
| user allowlisted IP | bypass for that user |
| public raw IP + binary/arch path | BLOCK |
| public raw IP + login/payment/admin | ISOLATE/BLOCK |
| public raw IP generic page | deep scan; default WARN/BLOCK depending evidence |

Principle:

```text
Public raw IPs are not globally bypassed.
Malware uses raw IPs to evade DNS reputation.
```

## 19. Explainability

Weighted scoring must not destroy user clarity.

Evidence UI should show:

```text
hard block reason, if present
top 3 risk contributors
top 3 trust contributors
missing proof
connection identity
final policy action
```

Example:

```text
Verdict: WARN

Risk:
+ random-looking hostname
+ fresh certificate
+ hidden cross-origin iframe

Trust:
- domain is 8 years old
- no feed hits
- HTTPS valid

Policy:
Read-only page, no credential sink found.
Therefore WARN, not BLOCK.
```

## 20. Telemetry And Rule Health

Every reason-code emission should increment:

```text
xgg_rule_fired_total{code}            ✅ Phase A — live
xgg_rule_verdict_total{rule,verdict}  ⏳ Phase G
xgg_rule_override_total{rule}         ⏳ Phase G (needs extension telemetry endpoint)
xgg_rule_fp_report_total{rule}        ⏳ Phase G (needs portal reporting flow)
xgg_rule_latency_seconds{rule}        ⏳ Phase G
```

Weekly report:

```text
top false-positive rules
top user-overridden rules
top false-negative categories
rules that fire too often
rules that never fire
rules with rising drift
```

Telemetry privacy requirements:

```text
opt-in by default unless self-host operator enables local-only telemetry
strip query strings
hash URLs where possible
short retention
export/delete support before SaaS telemetry
```

## 21. Corpus-First SDLC

No false-positive or false-negative patch ships without a corpus case.

PR checklist:

```text
What URL failed?
What verdict was expected?
What rule caused it?
What corpus entry was added?
What structural logic changed?
What malicious cases prove protection was not weakened?
What latency impact was measured?
What evidence UI changed?
```

Definition of a real fix:

```text
fixes reported URL
fixes similar URLs
does not require per-domain override
adds regression test
does not weaken malicious detection
explains which rule changed and why
```

## 22. Shadow-Mode Rollout

Do not replace the policy engine directly.

Run both engines:

```text
current_policy_verdict
new_engine_verdict
diff_reason
latency_delta
```

For 2-3 weeks:

```text
if both agree -> normal
if new blocks but old allows -> log only
if old blocks but new allows -> log only
```

Promote new engine only when:

```text
agreement rate acceptable
no P0 false negatives
false-positive delta within budget
latency within SLO
RUAT passes
corpus passes
```

## 23. Latency Budgets

Feature extraction must be tiered.

| Path | Budget | Features |
|---|---:|---|
| Fast path | <300ms | cache, feeds, vendor DNS cache, URL shape, raw IP, trust cache |
| Medium path | <2s | RDAP cache, cert metadata, redirect unwrap, org graph |
| Deep path | 8-45s | sandbox, visual match, DOM sink, YARA, OCR, download analysis |

Never block the browser indefinitely.

Sensitive unknown pages should:

```text
allow if trusted and proof sufficient
isolate if proof unavailable
block only on hard evidence
```

## 24. Feature Cache TTLs

Different features need different TTLs:

| Feature | TTL |
|---|---:|
| feed hit | 15m-1h |
| vendor DNS answer | 15m-1h |
| XGG resolver returned-IP ledger | DNS TTL + grace window |
| domain age | 24h |
| cert metadata | 6h |
| Tranco rank | 7d |
| ASN reputation | 7d |
| trust score | 6h |
| sandbox result | 1h |
| hard block result | 24h |
| allow result | 6h |

Do not cache one giant verdict blob forever.

## 25. Implementation Roadmap

### Phase A: Stop The Bleeding ✅ SHIPPED 2026-05-29

```text
[x] freeze trustreg growth policy           — CLAUDE.md "Three-tier trust policy" + PR template
[x] add PR template with real-fix checklist — .github/PULL_REQUEST_TEMPLATE.md
[x] add rule-fired metrics                  — xgg_rule_fired_total{code} live (metrics.go)
[x] enforce corpus-first fixes              — tools/fp-bench/corpus + policy_test.go regression tests
[x] orggraph for same-org collapsing        — internal/orggraph/ (26 orgs, 6 tests)
[x] revert FP-driven trustreg suffix entries — Disney/Netflix/Spotify suffixes removed
[ ] user allowlist for individual relief    — Options-page textbox, deferred to extension milestone
```

### Phase B: DNS + Connection Identity ✅ B.5a SHIPPED 2026-05-29

```text
[x] resolver stores returned IPs per client/domain/TTL     — internal/iledger, Redis-backed
[x] extension captures browser remote IP                   — chrome.webRequest.onResponseStarted
[x] verdict-api accepts browser_remote_ip                  — checkRequest.BrowserRemoteIP
[x] PUBLIC_DOMAIN_PRIVATE_IP hard rule                     — pre-Stage-0; trust cannot suppress
[x] USER_DNS_PATH_MATCH/MISMATCH ledger compare            — connid.CompareLedger
[x] EXPECTED_RESOLVER_BYPASSED                             — opted-in client + empty ledger
[x] evidence UI                                            — blocked.html Connection-identity row
[x] RUAT: hosts hijack / router hijack / loopback / CGNAT  — make ruat-connection-identity
[ ] CDN_ASN_MATCH / CDN_ASN_MISMATCH                       — B.5b: needs ASN tables
[ ] TLS_IDENTITY_MISMATCH                                  — B.5b: needs TLS introspection
[ ] LOCAL_RESOLVER_HIJACK_SUSPECTED                        — B.5b: needs backend resolver + ASN
```

### Phase C: Scoped Trust ✅ SHIPPED 2026-05-29 (conservative)

```text
[x] seed top 30 organizations              — done in Phase A (26 seeded in orggraph)
[x] implement same-org cross-origin suppression — done in Phase A (policymap.go)
[x] brandgraph backfill from trustreg      — C.1 (preserves curated narrow scopes)
[x] replace flat trustreg calls with brandgraph.IsAnyTrust — C.2 (4 call sites)
[x] policy.Inputs scoped fields            — C.3 (Login/Payment/OAuth/Script/CDN/Docs/AnyScope)
[ ] migrate each soft rule to consult its specific scope — Phase D
[ ] delete TrustedIdentity legacy alias    — Phase D, after migration
```

### Phase D: Trust Score ✅ SHIPPED 2026-05-29 (additive)

```text
[x] build internal/trustscore                — pure function, 8 tests
[x] start with available signals only        — domain age, feeds, vendor DNS, brand/org
[x] populate on policy.Inputs                — TrustScore + TrustContributors
[x] surface trust contributors in evidence UI — blocked.html "Trust score" row
[ ] use trust to suppress soft signals       — Phase E (verdict-changing)
[ ] add cache with TTL                       — Phase D follow-up; today the
                                                underlying features already
                                                cache, so Score() is recomputed
                                                per request from cached inputs
[ ] HTTPSValid signal                        — Phase B.5b TLS introspection
[ ] HistoricalCleanCount signal              — Phase G prior-verdict reader
```

### Phase E: Soft Rule Scoring

Refactor first:

```text
HIDDEN_MALICIOUS_LINK
RANDOM_HOSTNAME
OBFUSCATED_JS_DETECTED
HIDDEN_IFRAME_CROSS_ORIGIN
SUSPICIOUS_DOWNLOAD_OFFERED
DNS_DIVERGENCE_SOFT
```

Keep hard rules untouched.

### Phase F: Shadow Engine

```text
run old and new policies together
log diffs
measure latency
review top disagreements
promote only after corpus + RUAT + SLO pass
```

### Phase G: Data Flywheel

```text
override telemetry endpoint
labeling UI or workflow
weekly rule-health report
curated training set
future ML/classifier only after enough labels
```

## 26. Release Gates

No release ships unless:

```text
make maturity-test passes
make ruat-known-bad passes
personal-100 safe-mode test passes for primary tester
no indefinite extension spinner
no OAuth login breakage
no broken evidence UI
no P0 policy regression
every FP/FN patch includes corpus entry
shadow-mode diff reviewed when policy engine changed
```

## 27. Final Standard

The mature engine is not:

```text
more whitelisted domains
more one-off thresholds
one giant ML model
blind trust in major domains
single-IP DNS comparison
```

The mature engine is:

```text
DNS-first
connection-aware
hard-evidence preserving
scoped-trust based
org-graph informed
trust-scored
risk-scored
action-aware
latency-bounded
explainable
corpus-driven
telemetry-tuned
shadow-rolled
```

This is the architecture required to move from prototype/security tool to
production-grade protection.
