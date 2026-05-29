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

### Current Mechanism In Code

Current support-scam coverage is behavior-only. The shipped path is:

```text
sandbox-render injects JS hooks
  -> counts popup_open / alert / confirm / prompt / fullscreen_req /
     beforeunload / clipboard_write / auto_download
  -> verdict-api maps counters to behavior reason codes
  -> policy.Apply blocks only the composite scareware case
```

Current reason codes:

```text
POPUP_STORM_DETECTED
ALERT_LOOP_DETECTED
FULLSCREEN_TRAP_DETECTED
BEFOREUNLOAD_ABUSE
CLIPBOARD_HIJACK_ATTEMPT
AUTO_DOWNLOAD_TRIGGER
FAKE_SUPPORT_SCAREWARE
```

Current decision behavior:

```text
popup storm alone -> WARN
clipboard hijack alone -> WARN
3+ abuse classes together -> BLOCK as FAKE_SUPPORT_SCAREWARE
```

Code references:

```text
services/sandbox-render/app/main.py
services/verdict-api/internal/httpgw/behavior.go
services/verdict-api/internal/httpgw/policymap.go
services/verdict-api/internal/policy/policy.go
services/verdict-api/internal/policy/policy_test.go
```

Estimated current detection:

| Scam Variant | Current Detection Estimate | Why |
|---|---:|---|
| loud scareware with popup storm + alerts + fullscreen | 60-75% if sandbox-render is healthy | composite behavior detector can block |
| popup-only scam | 30-40% | usually WARN, not full scam classification |
| fake support page with visible phone number only | 0-10% | no phone extraction |
| phone number embedded in screenshot/image | 0% | no OCR |
| remote-tool lure without popup storm | 0-10% | no AnyDesk/TeamViewer/RustDesk detector |
| refund/gift-card support scam | 0-10% | no gift-card/refund language detector |
| quiet fake support chat widget | 0-10% | no fake-chat/action classifier |
| same scam phone reused across domains | 0% | no phone campaign graph |

Overall category estimate today:

```text
with sandbox-render healthy: 10-20% broad support-scam coverage
with sandbox-render down: 0-5% broad support-scam coverage
```

This is an engineering estimate, not a measured SLO, because there is not yet a
labeled support-scam corpus. Building that corpus is part of this category's
first implementation milestone.

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

Research-backed scam indicators:

| Indicator | Source Basis | Detection Approach |
|---|---|---|
| pop-up or warning says to call a phone number | Microsoft and FTC both warn that real tech/security warnings should not instruct users to call a pop-up phone number | DOM text + OCR + phone extraction |
| unsolicited support contact or urgent "device infected" message | FTC/FBI/Microsoft pattern | support-action classifier + scare-language dictionary |
| request for remote access | FBI, FTC, Microsoft, AnyDesk, TeamViewer guidance | remote-tool keyword/link/download detector |
| request to install remote-control software | FBI Phantom Hacker guidance and vendor anti-scam pages | RMM/remote-tool detector + download graph |
| payment by gift card | FTC says gift-card payment demands are scam indicators | gift-card phrase detector |
| payment by wire, crypto, payment app, bank transfer | FBI/FTC support-scam and Phantom Hacker warnings | payment-method phrase detector |
| fake refund / overpayment / bank-security story | FBI Phantom Hacker pattern | refund/banking narrative classifier |
| fake brand support on non-brand domain | Microsoft/FTC impersonation pattern | brand claim + orggraph/domain mismatch |
| pressure/urgency/threat language | common scam pattern | visible text + OCR phrase scoring |
| same phone number reused across unrelated domains | campaign behavior | phone-number graph |

Key source references:

```text
Microsoft: fake support pop-ups commonly show warnings and phone numbers.
FTC: tech-support scams ask for remote access and payment; gift cards are a scam indicator.
FBI: Phantom Hacker/support scams start with fake support contact, then remote access and financial transfer pressure.
AnyDesk/TeamViewer: legitimate remote tools are abused by scammers; unsolicited remote-access requests are unsafe.
Microsoft Quick Assist guidance: remote assistance should be controlled by official/internal support channels.
```

Sources:

- Microsoft tech-support scams: <https://support.microsoft.com/en-us/security/avoid-and-report-microsoft-technical-support-scams>
- Microsoft Defender support scams: <https://learn.microsoft.com/en-us/defender-endpoint/malware/support-scams>
- FTC tech-support scams: <https://consumer.ftc.gov/features/pass-it-on/impersonator-scams/tech-support-scams>
- FTC gift-card scams: <https://consumer.ftc.gov/articles/avoiding-and-reporting-gift-card-scams>
- FBI tech-support scams: <https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-frauds-and-scams/tech-support-scams>
- FBI Phantom Hacker warning: <https://www.fbi.gov/contact-us/field-offices/phoenix/news/press-releases/the-phantom-hacker-fbi-phoenix-warns-public-of-new-financial-scam>
- AnyDesk abuse prevention: <https://anydesk.com/en/abuse-prevention>
- TeamViewer scam guidance: <https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-remote/security/teamviewer-and-scamming/>
- Microsoft Quick Assist admin guidance: <https://learn.microsoft.com/en-us/windows/client-management/quick-assist>

### Aggressive Tech-Support Page Mode

If a page is classified as tech-support-like from URL, DOM text, OCR text,
visual claim, phone number, or support/action wording, run the full support
scam checklist. Do not wait for popup behavior.

Trigger support mode when any of these are true:

```text
URL path/title/text contains support/help/defender/security/virus/locked/error
OCR text contains support/help/virus/infected/locked/call/toll-free
phone number appears with security/support/error language
brand claim appears with support language
remote-tool name/link/download appears
refund/bank/security/payment story appears
page uses fullscreen/popup/beforeunload/alert behavior
```

When support mode triggers, collect:

```text
phone_numbers_dom[]
phone_numbers_ocr[]
tel_links[]
support_brand_claims[]
official_brand_support_domains[]
remote_tool_mentions[]
remote_tool_links[]
remote_tool_downloads[]
gift_card_phrases[]
wire_crypto_payment_phrases[]
refund_or_bank_security_phrases[]
urgency_threat_phrases[]
scareware_behavior_counters
official_channel_match
phone_reputation
same_template_or_screenshot_campaign
```

Phone-number verification should be automated:

```text
normalize to E.164 when possible
extract surrounding text window
search local campaign graph
check if number appears on official brand support pages already curated
check if number appears across unrelated domains
check if number is toll-free/VoIP/high-risk pattern
never trust a phone number just because it is local-looking
```

Official-channel verification:

```text
claimed brand -> known official support domains
claimed brand -> known official app/help portal
phone number shown on official brand domain -> weak positive
phone number shown only on current unknown domain -> risk
page says "Microsoft/Apple/Google support" outside official orggraph -> risk
```

Remote-tool detector dictionary:

```text
AnyDesk
TeamViewer
RustDesk
UltraViewer
Supremo
LogMeIn / GoToAssist / GoTo Resolve
ConnectWise ScreenConnect
Splashtop
Zoho Assist
Chrome Remote Desktop
Microsoft Quick Assist
Microsoft Remote Help
VNC / UltraVNC / TightVNC
RDP / Remote Desktop
NinjaOne / Atera / Syncro / Tactical RMM / MeshCentral
```

Gift-card/payment detector dictionary:

```text
gift card
Apple card
Google Play
Steam card
Target card
Walmart card
prepaid card
scratch code
activation code
wire transfer
bank transfer
crypto
Bitcoin
USDT
wallet address
payment app
refund fee
security deposit
software support fee
```

Scare/urgency phrase detector:

```text
your computer is infected
windows locked
defender alert
trojan detected
do not close this window
call immediately
toll free
your IP is compromised
bank account compromised
hackers detected
unauthorized transaction
refund pending
security department
do not tell anyone
stay on the line
```

### Support Scam Score

Use composite scoring. No single weak phrase should block a page, but the
combination becomes very strong.

| Signal | Weight | Notes |
|---|---:|---|
| phone number + security/support warning | +0.35 | strongest common web signal |
| phone number from OCR, not DOM | +0.40 | attackers hide phone in images |
| brand claim + non-brand domain | +0.30 | impersonation context |
| remote-tool mention/link/download | +0.35 | FBI/FTC/vendor-backed scam pattern |
| gift-card/wire/crypto payment phrase | +0.45 | very high scam signal |
| refund/bank-security/Phantom Hacker story | +0.35 | high-risk narrative |
| fullscreen/popup/alert/beforeunload composite | +0.60 | current hard behavioral pattern |
| same phone across unrelated domains | +0.50 | campaign evidence |
| official support-domain/phone match | -0.35 | weak trust, never clears hard behavior |
| known trusted support host with no risky action | -0.40 | suppress noisy support wording |

Verdict thresholds for support mode:

```text
score >= 0.85 -> BLOCK
score >= 0.55 -> WARN/ISOLATE depending user mode and action
score < 0.55 -> ALLOW unless another engine stage blocks
```

Hard-block combinations:

```text
phone number + fake brand + popup/fullscreen/alert behavior
phone number + remote-tool install instruction + unknown/non-brand domain
gift-card/wire/crypto payment request + support/refund/security context
same phone number in confirmed scam campaign
remote-tool download served from unknown/fresh/raw-IP domain
```

False-positive protections:

```text
official support domain can suppress support wording only, not hard behavior
remote-tool vendor's own official pages do not block just for naming the tool
legitimate IT docs mentioning AnyDesk/TeamViewer require no phone/payment/scare context
news/education pages discussing scams are classified informational, not scam
local business support pages with phone numbers are WARN only if scare/payment/remote-tool signals exist
```

### Out-Of-Box Elder-Protection Strategy

Important reality:

```text
some real businesses are predatory
some genuine-looking companies sell useless support
some pages are legal but still harmful for elderly users
phone caller ID can be spoofed
manual verification of every phone number is impossible
```

Therefore support-scam protection must move from "is this website fake?" to:

```text
is this page trying to make a vulnerable user take a dangerous action?
```

Dangerous actions:

```text
call this number now
install remote access software
share a remote access code
pay by gift card / wire / crypto
log into bank while on a support call
send refund/security payment
download a patch from unknown support page
disable security tools
stay on the phone / do not tell anyone
```

#### Phone Number Intelligence Layer

Phone numbers become first-class evidence objects.

```text
PhoneEvidence
  raw_text
  normalized_e164
  country
  line_type
  carrier
  voip_or_tollfree
  first_seen_by_xgg
  domains_seen_on[]
  brands_claimed_with[]
  support_context_count
  scam_context_count
  official_brand_match
  reputation_sources[]
  complaint_or_abuse_hits[]
  velocity_score
  campaign_score
```

Automated phone checks:

| Check | Why |
|---|---|
| line type: VoIP/toll-free/mobile/fixed | many scam operations use disposable VoIP/toll-free numbers |
| country mismatch | "Microsoft US support" with unrelated country pattern is risk |
| first-seen timestamp | newly observed support number is suspicious |
| domain fanout | same number on many unrelated domains is campaign evidence |
| brand fanout | same number claims Microsoft, Apple, PayPal, bank support = strong scam signal |
| official support match | number appears on curated official brand support domain = weak positive |
| reputation vendor result | commercial/crowd phone reputation as advisory evidence |
| web-search footprint | number appears in scam complaints or many spammy pages |
| page context | phone shown next to virus/security/refund/gift-card language |

Potential phone-intelligence sources:

```text
Twilio Lookup
Telesign Phone ID / Intelligence
Hiya number reputation
Truecaller-style reputation if licensed
carrier/GSMA Number Verify where available
GSMA SIM Swap / Mobile Identity APIs for account-risk contexts
internal XGG phone campaign graph
user reports and RUAT findings
official brand support registry
```

Limits:

```text
caller ID spoofing means incoming-call number is not proof
phone reputation APIs are advisory, not ground truth
new scam numbers may have no history
legitimate small businesses can use VoIP
never hard-block from phone reputation alone
```

Phone hard-block combinations:

```text
phone number + fake brand + support/security warning + non-official domain
phone number + remote-tool instruction + unknown/non-brand domain
phone number + gift-card/wire/crypto/refund story
same number reused across unrelated scam-looking domains
number previously confirmed malicious by analyst/corpus
```

#### Official Channel Verification

Instead of asking an operator to manually verify every phone number, maintain a
small high-value official-contact registry:

```text
brand
official support domains
official support portal URLs
official phone numbers where published
official app deep links
official "how to contact us" page
source URL
last verified date
review owner
```

Verification rule:

```text
If page claims Brand X support, the page must either be on Brand X's official
support domain or point the user to Brand X's official support channel.
```

Do not trust:

```text
phone number from search ads
phone number from random SEO page
phone number in pop-up warning
phone number in screenshot
phone number in unsolicited text/email
caller ID display name
```

User guidance rendered by product:

```text
Do not call this number. Open the company's official app or type the official
website yourself. Use the support number printed on your card, statement, or
official account portal.
```

#### Elder-Safe Mode

Add an optional "Elder Safe" or "Family Guardian" mode.

Behavior:

```text
support phone number on unknown page -> WARN/ISOLATE
remote access tool download after support-scam page -> BLOCK
gift-card/wire/crypto language -> BLOCK
bank login after support-scam flow -> interrupt
copying phone number from risky page -> show warning
clicking tel: link from risky page -> block/confirm
opening AnyDesk/TeamViewer/RustDesk/Quick Assist from risky flow -> block/confirm
```

High-friction interventions for vulnerable users:

```text
cooling-off timer before proceeding
"call official number instead" button
trusted-contact approval for remote-tool install or gift-card/crypto warning
large plain-language warning: "This is how support scams steal money"
printable/saveable report for family member
"Report this number" button
```

This is not only detection. It is harm reduction. Elderly users are often
scammed after the page has convinced them to leave the browser and continue by
phone. The browser must interrupt that transition.

#### Local Phone-Number Masking For Elder Safe Mode

For protected users, the browser extension may locally rewrite the rendered
page. This does not alter the third-party website or server. It only changes
what the protected user sees in their own browser session.

When a page is support-like and its phone number is unverified or suspicious:

```text
hide or mask the page's phone number
disable tel: links to that number
show an XGenGuardian warning panel near the masked number
explain exactly why the number is not trusted
offer verified official-channel alternatives when available
offer guardian/analyst review when not available
allow copy/export of the evidence report
```

Example local replacement:

```text
Original page text:
  Call Microsoft Support now: 1-800-XXX-XXXX

Rendered locally for Elder Safe user:
  [Phone number hidden by XGenGuardian]
  This support number is not verified as an official Microsoft support channel.
  Do not call it or install remote-access software.

  Safer options:
  - Open official Microsoft support
  - Ask trusted contact to review
  - View evidence
  - Report this number
```

Masking triggers:

```text
support-like page + phone number + unverified provider
phone number + fake/security/virus/refund language
phone number + remote-tool instruction
phone number + gift-card/wire/crypto language
phone number + claimed major brand but no official affiliation proof
phone number appears in known/suspected campaign graph
```

Masking must include proof:

```text
which phone number was hidden
where it appeared: DOM / OCR / tel link / image
claimed brand
domain age
official-channel match status
remote-tool/payment/scare signals found
campaign/reputation status
which rule caused masking
timestamp
```

User controls:

```text
Elder Safe: hide by default, guardian can reveal
Safe: warn with click-to-reveal
Normal: show warning only
Enterprise/Family admin: choose policy centrally
```

Do not silently replace a number with an arbitrary XGG phone number. Safer
behavior is:

```text
hide suspicious number
show verified official support URL/number only if it came from curated official registry
otherwise route to guardian/analyst review
```

Reason: replacing with the wrong number is dangerous. XGG should guide the user
to verified official channels, not become a support call center by default.

#### Cross-Channel Flow Detection

The scam may start on a website but continue outside it.

Track session flow:

```text
support-scam page seen
phone number copied/clicked
remote access tool page opened
remote tool downloaded
bank/crypto/payment page opened soon after
gift-card/crypto/wire instructions visible
```

Escalation rule:

```text
support-scam context + remote tool + bank/payment/crypto within 60 minutes
  -> high-risk elder-scam flow
  -> block/interrupt even if each individual page looks legitimate
```

This handles the hardest case: the phone number may belong to a real-looking
company, AnyDesk is a real website, and the bank is a real bank. The risk is in
the sequence.

#### Manual Intervention, But Only For High Leverage

Manual review is allowed for:

```text
new phone number seen across many users
high-traffic uncertain support domain
possible false positive against real vendor support
official-contact registry updates
confirmed scam campaign clustering
```

Manual review is not allowed for:

```text
every phone number
every local business
every one-off support page
every user override
```

Reason: manual verification does not scale. The scalable path is automated
phone evidence + official-channel registry + campaign graph + elder-safe
action interruption.

#### Verified Support Provider Registry

For pages that claim to be a technical support provider, add a voluntary
verification program. This is not a whitelist. It is evidence that can reduce
friction only when no scam behavior is present.

Default posture:

```text
all tech-support providers start as unverified
unverified does not legally mean "confirmed scam"
unverified does mean "not trusted for elderly/sensitive users"
trust is fragile and must be continuously earned
one serious inconsistency can downgrade trust
hard scam behavior overrides all documents
```

For Elder Safe mode, the product posture is intentionally stricter:

```text
unknown tech-support company = suspicious until proven
unknown tech-support company + phone number = interrupt
unknown tech-support company + remote access = block/guardian approval
unknown tech-support company + payment request = block
unknown tech-support company claiming Microsoft/Apple/Google/bank support =
  block/isolate until affiliation is verified from the claimed brand's source
```

Provider must prove:

```text
legal business identity
domain ownership
phone number ownership
support portal ownership
physical/legal jurisdiction
owner/officer identity where available
official brand affiliation if they claim one
privacy/refund/contact policy
no history of confirmed scam reports in XGG corpus
```

Multi-level trust checks:

| Layer | Question | Suspicious If |
|---|---|---|
| domain age | how long has the support domain existed? | very new domain, recent ownership change, short-lived pattern |
| company age | how long has the legal entity existed? | newly formed company claiming major-brand support |
| registry footprint | does the business exist in official registries? | no registry match, dissolved entity, mismatched name |
| address consistency | does address match registry/site/documents? | virtual mailbox only, mismatched country/state, fake-looking address |
| phone consistency | does number match official business records/site? | number appears on unrelated domains or mismatched company |
| domain ownership | can provider prove DNS control? | no DNS TXT proof, free email used for support identity |
| affiliation proof | does claimed brand confirm relation? | "Microsoft support" claim with no Microsoft-controlled proof |
| web history | does the business have stable historical presence? | only recent SEO pages, no long-term footprint |
| complaint footprint | are there scam/abuse reports? | complaints, repeated chargeback/refund complaints, campaign reuse |
| behavior | does page ask for risky actions? | remote access, gift cards, crypto, wire, bank login, secrecy |
| transparency | are terms/refund/privacy/contact clear? | hidden fees, vague company identity, no legal contact |

Trust scoring should be fragile:

```text
old domain alone is not enough
business registration alone is not enough
phone ownership alone is not enough
uploaded certificates alone are not enough
brand affiliation claim is ignored until verified from brand-controlled source
any hard-risk behavior immediately downgrades trust
```

Trust downgrade examples:

```text
company says it is Microsoft-certified but Microsoft source cannot confirm
registry address differs from website address
domain registered last week but claims years of support history
support phone appears across many unrelated brands
provider refuses basic identity verification while requesting remote access
provider asks for gift cards, crypto, wire transfer, seed phrase, or bank login
```

Classification states:

| State | Meaning | Elder Safe Behavior |
|---|---|---|
| unverified | no proof reviewed | warn/isolate support contact; block risky actions |
| suspicious-unverified | weak/inconsistent identity or risky context | block support phone/remote/payment flow |
| verification-pending | provider submitted evidence, not reviewed | still untrusted |
| verified-identity | business/domain/phone verified | lower friction only for normal support |
| verified-affiliation | claimed brand confirmed by official source | scoped trust for that brand/support action |
| verified-but-risky | identity real, behavior risky | warn/block by behavior |
| confirmed malicious | fake proof, scam campaign, hard evidence | block + report package |

Evidence accepted:

| Evidence | Verification Method |
|---|---|
| business registration | OpenCorporates/state registry/company registry lookup |
| D-U-N-S or business identifier | Dun & Bradstreet lookup where applicable |
| domain ownership | DNS TXT challenge on claimed domain |
| support email ownership | email challenge to same-domain address, not Gmail/Outlook free mailbox |
| phone number control | one-time code to business phone line, rate-limited |
| brand affiliation | official partner directory/API check, never just uploaded PDF |
| Microsoft affiliation | Microsoft Partner Center/PartnerID or public partner directory evidence |
| refund/contact policy | policy URL on owned domain |
| support tool usage | declared RMM/remote tool list and customer-consent flow |

Uploaded documents are evidence leads, not final proof. Analyst must verify
them against official sources:

```text
company registry
brand partner directory
public partner profile
domain DNS challenge
phone challenge
official email/domain challenge
government/state registry
business database where available
```

Sources for verification concepts:

- Microsoft Partner Center verification: <https://learn.microsoft.com/en-us/partner-center/enroll/verification-responses>
- Microsoft PartnerID verification API: <https://learn.microsoft.com/en-us/partner-center/developer/get-partner-by-mpn-id>
- Microsoft Find a Partner: <https://partner.microsoft.com/en-us/membership/find-a-partner>
- D-U-N-S lookup: <https://www.dnb.com/en-us/smb/duns/duns-lookup.html>
- OpenCorporates API: <https://api.opencorporates.com/>

Affiliation rule:

```text
If a provider claims "Microsoft support", "Apple support", "Google support",
"PayPal support", "bank support", or similar, they must prove affiliation from
the claimed brand's official channel. A document uploaded by the provider is
not enough.
```

Verification states:

| State | Meaning | Policy Effect |
|---|---|---|
| unverified | no provider proof | no trust benefit |
| domain verified | provider controls domain | weak trust only |
| business verified | legal entity confirmed | weak trust only |
| phone verified | provider controls number | weak trust only |
| affiliation verified | official partner/support affiliation confirmed | stronger trust for that brand/scope |
| reviewed approved | analyst reviewed supporting evidence | scoped trust, still overridden by hard evidence |
| revoked | failed review or later abuse | strong risk signal |

Failure handling:

```text
fake details -> confirmed malicious candidate
inconsistent details -> suspicious-unverified
refusal to verify + no risky behavior -> unverified, not confirmed scam
refusal to verify + risky support behavior -> suspicious-unverified / block in Elder Safe
verified identity + scam behavior -> verified-but-risky, behavior wins
```

Never allow verification to suppress:

```text
gift-card/wire/crypto payment requests
seed phrase requests
unauthorized credential sinks
public-domain-private-IP
malware downloads
remote access without clear consent language
confirmed scam phone campaign reuse
```

#### Verification Workflow

User reports or engine flags a provider:

```text
1. Provider page detected as support-like.
2. Engine extracts company name, domain, phone, claimed brand, support flow.
3. If high-risk, user sees warning immediately.
4. Provider may submit verification through XGG portal.
5. Automated checks run first.
6. Analyst reviews only high-impact or affiliation-claiming providers.
7. Approved providers get scoped trust, not global allow.
8. Any later hard evidence revokes trust automatically.
```

Automated checks:

```text
OpenCorporates/company registry search
D-U-N-S lookup where available
DNS TXT domain challenge
same-domain email challenge
phone OTP challenge
official partner directory lookup
official support-domain cross-check
sanctions/abuse/report corpus check
website age / RDAP / CT / ASN stability check
```

Analyst review checklist:

```text
Does legal entity exist?
Does domain belong to the entity?
Does phone number belong to the entity?
Does the website clearly disclose business identity?
Does the page falsely imply brand affiliation?
Does the provider ask for gift cards/wire/crypto?
Does the provider use remote tools with clear consent and session disclosure?
Are refund/fees/support terms visible?
Is there complaint/campaign evidence?
```

#### Automated Outreach Guardrails

Do not build a system that automatically calls or emails every suspected
provider. That can become abuse, spam, or legal risk.

Allowed outreach:

```text
verification email only after provider initiates verification
phone OTP only after provider enters the phone number in verification portal
brand affiliation check only through official APIs/directories or analyst review
high-risk report sent to internal analyst queue, not to random third parties
```

Not allowed:

```text
auto-calling support numbers from suspicious sites
mass-emailing companies demanding documents
accepting uploaded certificates as proof without official-source verification
letting one analyst approval override hard scam behavior
```

#### Reporting Pipeline

For confirmed scams:

```text
create XGG campaign record
store phone/domain/wallet/remote-tool evidence
add corpus entry
add reason-code regression test
mark provider/phone as confirmed malicious
optionally export report package for FTC/FBI/brand abuse portal/operator
```

Report package should contain:

```text
URL
phone number
screenshots
OCR text
DOM text
remote-tool/payment indicators
redirect chain
domain age
business identity claims
official-channel mismatch
evidence timestamp
analyst notes
```

#### Elder-Safe Verified Provider Rule

In Elder Safe mode:

```text
unverified support provider + phone number -> WARN/ISOLATE
unverified support provider + remote tool -> BLOCK/guardian approval
unverified support provider + payment request -> BLOCK
verified provider + normal support contact -> ALLOW/WARN by evidence
verified provider + gift-card/crypto/wire/seed phrase -> BLOCK anyway
```

This solves the "real company that still scams" problem better than website
reputation. A real company can still behave dangerously; behavior and action
always outrank paperwork.

#### Support-Specific Trust Evidence Model

For tech-support pages, trust must be evaluated across identity layers. A page
is not trusted because it is online, has HTTPS, or calls itself "certified".

Support trust evidence:

| Source | How It Helps | How It Can Fail |
|---|---|---|
| domain | proves where the support page is hosted | new domain, brand-like domain without affiliation, unstable DNS |
| email | proves support contact belongs to a domain | free mailbox, reply-to mismatch, no DMARC alignment |
| phone | proves support contact route | reused across unrelated brands, VoIP/toll-free with scam context |
| legal company | proves entity exists | new/dissolved/mismatched company, fake address |
| owner/operator | creates accountability | anonymous operator for sensitive support service |
| brand affiliation | proves right to claim Microsoft/Apple/Google/etc. support | uploaded badge/PDF with no official brand source |
| payment identity | proves who receives money | recipient does not match company, crypto/gift-card/wire |
| support channel | proves official support flow | pop-up number, random SEO support page |
| remote-tool flow | proves whether remote access is controlled/consented | AnyDesk/TeamViewer/Quick Assist pushed from risky page |
| software/download | proves publisher/source of any tool | unsigned/raw-IP/fresh-domain download |
| social/marketplace profile | supporting footprint only | fresh/stolen profile, no domain linkback |

Support-page trust scoring:

```text
start from unverified
add weak trust for stable domain/company/phone/email consistency
add stronger trust only for official brand-controlled affiliation proof
subtract for contradictions
hard-block for dangerous support behavior
```

Positive support evidence:

```text
domain is old and stable
company registry is active and consistent
support phone appears on verified official domain
same-domain support email with SPF/DKIM/DMARC alignment
business/payment identity matches domain/company
claimed brand affiliation confirmed by official brand source
remote-support consent flow is explicit and non-deceptive
refund/contact/privacy policy is clear
```

Negative support evidence:

```text
new domain claiming years of support history
Microsoft/Apple/Google/bank support claim without official affiliation proof
phone appears on unrelated support domains
phone number appears only in OCR/image/popup
free email used for business support identity
company registry absent/dissolved/mismatched
payment recipient differs from company
remote access requested before identity proof
gift-card/wire/crypto requested
user told not to tell anyone
```

Support-specific action policy:

| Action Asked From User | Required Trust | Elder Safe Behavior If Not Proven |
|---|---|---|
| read support article | low | allow/warn by content |
| call support number | verified support channel | mask number + warn/isolate |
| install remote tool | verified support + explicit consent + guardian mode | block/guardian approval |
| share remote access code | verified support + active consent | block/guardian approval |
| enter password/account | verified identity + safe sink | isolate/block |
| log into bank during support flow | strong official proof + safe context | interrupt strongly |
| pay support fee | verified company/payment identity | warn/isolate |
| gift-card/wire/crypto payment | never trusted | block |
| seed phrase/security code | never trusted | block |
| disable security software | enterprise-admin only | block |

Support trust states:

```text
unknown
unverified
suspicious-unverified
verification-pending
verified identity
verified affiliation
verified support channel
verified-but-risky
confirmed malicious
revoked
```

Support trust examples:

```text
official Microsoft support page on microsoft.com -> verified support channel
local repair shop with old domain + registry + consistent phone -> verified identity, not Microsoft affiliation
new domain "microsoft-help-center" + phone + AnyDesk -> block/isolate
registered company + gift-card payment request -> block anyway
TeamViewer official docs -> allow, because remote-tool mention is informational
random blog explaining support scams -> allow, because action is educational not support contact
```

Trust-engine principle for this category:

```text
The engine does not ask only "is this support website real?"
It asks "is this identity verified for the exact support action it is asking
an elderly user to take?"
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

For this category, use the most aggressive verification level. Money movement
requires stronger proof than ordinary browsing.

### Aggressive Payment Trust Mode

Trigger aggressive payment mode when any page contains:

```text
crypto wallet address
wallet connect button
seed phrase / recovery phrase input
approve / permit / sign transaction flow
gift-card / prepaid-card wording
wire transfer / bank transfer instructions
refund / overpayment / tax / support fee language
invoice/payment request
checkout/payment form
support page requesting money
QR code containing payment or wallet payload
```

Collect a complete payment-risk dossier:

```text
domain evidence
TLS/certificate evidence
DNS/connection identity
company/legal identity
merchant/payment identity
wallet/address identity
on-chain risk
review/forum/search footprint
support/contact identity
brand affiliation
page action
payment method
user-risk context
```

### Deep Website And Business Verification

Payment pages should be checked more strictly than read-only pages.

| Layer | Check | Suspicious If |
|---|---|---|
| domain age | RDAP/first-seen/CT first-seen | new domain asking for payment/crypto |
| DNS | authoritative NS, TTL, CNAME, returned-IP ledger | unstable, fast-flux, private IP, unexpected ASN |
| TLS | valid cert, issuer, SAN, CT history | cert just issued for new payment site, mismatch |
| company registry | legal entity active, age, address | absent, new, dissolved, mismatched |
| merchant identity | payment recipient/merchant name | does not match legal/site identity |
| phone/email | support contact consistency | free email, unverified phone, reused support number |
| reviews/forums | search/reputation footprint | scam complaints, fake review pattern, no footprint |
| brand affiliation | official partner/protocol/project proof | unsupported claim, fake badge, copied logo |
| refund policy | clear terms and legal contact | vague/no refund policy for paid service |
| payment method | appropriate method | gift-card/wire/crypto for support/refund/tax |

Search/review/forum signals are advisory only, but useful:

```text
search snippets for domain/company/phone/wallet
Reddit/forum scam mentions
Trustpilot/BBB/ScamAdviser-style reviews when available
app-store/extension-store reviews when relevant
GitHub/project/community footprint for crypto projects
social profile age and bidirectional domain link
complaint databases and prior XGG reports
```

Governance:

```text
reviews alone never hard-block
fake-looking positive reviews do not create trust
scam complaints + payment action + weak identity raise risk sharply
no search footprint for a new payment/crypto provider is suspicious, not proof
```

### Crypto And Wallet Intelligence

For wallet/crypto pages, extract and screen:

```text
wallet addresses
contract addresses
token addresses
spender addresses
approval targets
transaction payloads where observable
chain/network
QR payment payloads
exchange/deposit addresses
```

External/on-chain sources:

| Source | Use |
|---|---|
| Chainabuse API | community and verified scam reports; confidence-scored abuse evidence |
| Chainalysis Address Screening / Rapid | commercial address risk, exposure, counterparties, continuous monitoring |
| TRONSCAN security APIs | Tron URL/address/token/transaction risk checks |
| Etherscan labels/name tags | address labels and public interest tags as advisory evidence |
| block explorer APIs | contract age, deployer, transaction history, token metadata |
| sanctions screening APIs | sanctioned wallet/entity screening where licensed |
| internal XGG wallet graph | repeated wallet across scam pages/campaigns |

Sources:

- Chainabuse API: <https://docs.chainabuse.com/>
- Chainabuse source/confidence model: <https://docs.chainabuse.com/docs/source-of-information>
- Chainalysis Address Screening: <https://www.chainalysis.com/product/address-screening/>
- Chainalysis Rapid triage: <https://www.chainalysis.com/product/rapid/>
- TRONSCAN security services: <https://docs.tronscan.org/en/api/security-service-api>
- TRONSCAN scam reporting: <https://support.tronscan.org/hc/en-us/articles/21841611138585-How-to-report-a-scam>
- Etherscan labels/name tags: <https://info.etherscan.com/public-name-tags-labels>

Crypto hard-risk signals:

```text
wallet address reported on Chainabuse with high confidence
wallet/contract flagged by TRONSCAN/security service
sanctioned wallet/entity hit
wallet reused across unrelated scam-looking domains
approval target is known risky spender
seed phrase requested
connect wallet on fresh/impersonating domain
fake airdrop + wallet connect + unknown contract
QR code decodes to wallet/payment on suspicious page
```

### Gift Card / Wire / Crypto Payment Rules

Some payment methods are nearly never legitimate in support/refund/security
contexts.

Hard block in support/refund/security context:

```text
gift card
Apple/Google/Steam/Target/Walmart prepaid card
scratch code / activation code
wire transfer
crypto transfer
Bitcoin/USDT/ETH wallet payment
bank transfer under urgency
"security deposit" to protect account
"refund fee" before refund
```

Warn/isolate in commerce context:

```text
crypto-only payment on new merchant
bank transfer to mismatched recipient
invoice from unverified company
payment page with no legal/refund/contact identity
```

### Wallet-Drainer Detection

Detect dangerous wallet actions:

```text
connect wallet
approve unlimited token allowance
permit / permit2 signatures
setApprovalForAll
eth_sign / personal_sign for opaque message
transaction to new/unverified contract
request to import seed phrase
fake airdrop/mint/claim language
urgency countdown tied to wallet action
```

Hard block:

```text
seed phrase request on webpage
wallet connect + impersonated brand/project
wallet approve/unlimited allowance to unknown contract
known drainer script/library/signature pattern
contract/wallet flagged by on-chain source
```

False-positive controls:

```text
official wallet/exchange domains can request wallet actions within verified scope
DeFi docs discussing approvals are informational unless requesting live action
testnet/dev pages require clear testnet markers
open-source dapp with verified domain/repo/contract gets lower risk, not blind trust
```

### Payment Identity Object

Add a reusable object:

```text
PaymentEvidence
  payment_method
  amount
  currency
  recipient_name
  recipient_account_or_wallet
  merchant_processor
  merchant_id_hash
  legal_entity_match
  domain_match
  phone_email_match
  wallet_chain
  wallet_reputation
  refund_policy_url
  risk_sources[]
  contradictions[]
```

Policy question:

```text
Does the recipient match the identity that earned the user's trust?
```

Examples:

```text
verified company + Stripe merchant matching company -> trust contributor
support site + crypto wallet -> block
invoice from company A but payment to person B -> high risk
QR payment to wallet on unknown domain -> isolate/block
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

Zero-day phishing cannot depend on reputation feeds. The page must earn trust
from live evidence.

Core question:

```text
Can this exact page, on this exact domain and connection, safely ask the user
for this exact sensitive action?
```

If the page asks for a sensitive action and the engine cannot prove identity,
sink, and infrastructure, it should isolate rather than silently allow.

### Zero-Day Evidence Dossier

Collect:

```text
claimed brand
brand evidence source: title, text, logo, favicon, OCR, OpenGraph
requested action: login, payment, OAuth, download, support, wallet, command
form fields and form actions
JS network sinks: fetch/XHR/beacon/WebSocket/postMessage
redirect chain
iframe/script/download graph
domain age and first-seen time
TLS certificate and CT history
ASN/CDN/hosting identity
browser actual IP vs resolver ledger
external reputation source disagreement
visual brand match
favicon/pHash/CLIP matches
hidden elements and overlays
anti-analysis behavior
```

### Action-Proof Gates

| Action | Required Proof | Missing Proof Result |
|---|---|---|
| login/password | domain/org identity + safe credential sink + TLS + no hard evidence | ISOLATE |
| payment/checkout | merchant/company identity + safe payment sink + refund/legal contact | ISOLATE |
| OAuth consent | provider + client reputation + scope severity + redirect URI relation | WARN/ISOLATE/BLOCK |
| download/install | official source + file reputation/hash + no raw-IP/fresh-domain lure | WARN/ISOLATE/BLOCK |
| support call | verified support channel + phone evidence | WARN/ISOLATE |
| wallet/crypto | wallet/contract risk + verified project/domain | ISOLATE/BLOCK |
| command copy | official command registry or safe low-risk command | WARN/BLOCK |

### Brand Claim Extraction

Extract claimed identity from:

```text
page title
meta/OpenGraph tags
visible text
logo/visual match
favicon hash
login form placeholder text
OAuth app name
support text
email/wrapper context
download filename/signature
```

Brand claim risk:

```text
brand claim + unrelated domain -> risk
brand claim + visual match + sensitive action -> high risk
brand claim + same orggraph relation -> lower risk
brand claim in news/article context -> informational, not phishing
```

### Infrastructure Trust For Zero-Day

Reputation feeds may be clean because the site is new. Use infrastructure
evidence:

```text
domain registered recently
certificate first seen recently
nameservers recently changed
unexpected ASN/hosting for claimed brand
browser IP not authorized for domain
shared hosting tenant with brand claim
fast redirect chain to sensitive action
free hosting / free subdomain / newly created SaaS tenant
```

Rules:

```text
fresh domain + sensitive action -> isolate unless strong proof exists
fresh domain + claimed major brand -> high risk
fresh domain + credential sink to unrelated host -> block
old domain + new suspicious path/script/sink -> inspect path-level evidence
```

### Page Graph For Zero-Day

A landing page may look harmless while a child node is malicious.

Build graph:

```text
landing page
redirect hops
forms
iframes
scripts
downloads
QR targets
OAuth destinations
wallet/contract targets
postMessage targets
network beacons
```

Graph rules:

```text
child node asks for credentials/payment/wallet action -> child gets full scan
parent inherits worst sensitive child verdict
same-org edges reduce risk
unknown third-party sensitive sinks increase risk
hidden sensitive child nodes increase risk sharply
```

### Degraded-Mode Policy

Zero-day protection depends on sandbox, visual, and sink extraction. If a
required detector is down, the verdict must show missing proof.

| Missing Layer | Page Type | Policy |
|---|---|---|
| sandbox unavailable | read-only low-risk page | ALLOW/WARN by Tier-1 |
| sandbox unavailable | login/payment/OAuth/download/support/wallet | ISOLATE |
| visual-match unavailable | claimed brand + sensitive action | ISOLATE/WARN depending other proof |
| RDAP unavailable | fresh-domain unknown | do not count as old/trusted |
| external source timeout | any | source missing, not clean |
| browser IP missing | sensitive page | connection identity missing; require other proof |

### Search And External Context

For zero-day pages, optional T2/T4 context helps:

```text
search results for domain/company/phone
recent web mentions
social/project profile age
GitHub/org/project relation
app-store/package-registry publisher relation
community scam reports
CT log burst for similar domains
similar-domain registration clusters
```

This evidence is advisory. It improves confidence but does not replace direct
page/action/sink proof.

### Zero-Day Score Model

High-risk contributors:

| Signal | Weight |
|---|---:|
| sensitive action on fresh domain | +0.35 |
| claimed major brand on unrelated domain | +0.35 |
| credential/payment sink to unrelated host | +0.60 |
| visual brand match + identity mismatch | +0.55 |
| hidden iframe/form/action | +0.30 |
| unexpected ASN/cert/CDN identity | +0.25 |
| QR/wrapper/shortener hides sensitive target | +0.25 |
| anti-analysis / delayed payload | +0.30 |
| official orggraph/domain/sink proof | -0.40 |
| old stable domain with no sensitive action | -0.25 |

Hard-block combinations:

```text
credential sink mismatch + brand claim
visual brand match + credential action + identity mismatch
fresh domain + payment/wallet action + bad sink
OAuth high-risk scopes + unknown client + suspicious redirect
download executable from raw IP/fresh domain with lure
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

### 23.0 Trust Verification Framework

XGenGuardian should build a reusable trust-verification framework, not only a
URL scanner. The core rule:

```text
online presence is not trust
website exists is not trust
HTTPS is not trust
email address exists is not trust
phone number answers is not trust
company claims are not trust
uploaded certificate is not trust
trust requires independent corroboration across identity layers
```

This framework should verify:

```text
domain
email
phone number
legal company
owner/operator
brand affiliation
payment identity
support identity
app/OAuth identity
download/software publisher
social profile / marketplace profile
```

The output is an identity dossier:

```text
IdentityDossier
  subject_type
  subject_value
  claimed_identity
  proof_layers[]
  contradictions[]
  trust_score
  risk_score
  verification_state
  allowed_actions[]
  forbidden_actions[]
  evidence_links[]
```

#### Trust Layers

| Layer | What To Verify | Good Evidence | Bad / Suspicious Evidence |
|---|---|---|---|
| domain | ownership, age, DNS, CT, nameservers | old stable domain, DNS TXT proof, stable CT history | new domain, hidden ownership, sudden NS/ASN change |
| email | domain relation, mailbox control, SPF/DKIM/DMARC | same-domain email, DMARC aligned, verified mailbox | free mailbox for company support, spoofed sender, no DMARC |
| phone | control, line type, campaign reuse, official registry match | verified phone challenge, appears on official domain | VoIP/toll-free reused across unrelated brands |
| company | legal registration, age, address, officer data | official registry match, consistent address | dissolved/new entity, mismatched address/name |
| owner/operator | human/business accountability | verified officer/contact path | anonymous operator for sensitive service |
| brand affiliation | official partner/channel proof | brand-controlled partner directory/API | uploaded PDF only, unverifiable certificate |
| payment identity | merchant/account relation | processor merchant identity matches company | payment to unrelated person/wallet |
| support identity | official support domain/channel | support portal controlled by verified company | pop-up phone number, remote tool demand |
| software publisher | signing cert, download domain, package registry | code signing matches vendor | unsigned binary, raw-IP download |
| social/marketplace | account age, verification, linkback | official profile links back to domain | fresh profile, no domain proof |

#### Verification States

```text
unknown
unverified
weakly verified
verified identity
verified affiliation
verified for specific action
suspicious
confirmed malicious
revoked
```

Trust is scoped:

```text
verified for email does not mean verified for payment
verified company does not mean authorized Microsoft support
verified domain does not mean safe remote-access behavior
verified app does not mean safe OAuth scopes
```

#### Proof Rules

```text
1. Every identity claim must point to an independent proof source.
2. Proof from the claimant is a lead, not final proof.
3. Brand affiliation must be verified from the brand's official source.
4. Business identity must be verified from registry/business databases where possible.
5. Domain ownership must be verified by DNS or official site control.
6. Phone ownership must be verified by challenge or official source.
7. Email identity must be domain-aligned and authenticated.
8. Payment identity must match the legal/support identity.
9. Trust decays over time and can be revoked.
10. Dangerous behavior overrides identity proof.
```

#### Email Trust Checks

```text
SPF pass
DKIM pass
DMARC pass/aligned
From domain matches claimed organization
reply-to mismatch
sender domain age
sender domain reputation
display-name brand impersonation
link destination mismatch
attachment/download risk
email authentication result from headers when available
```

Email verdict examples:

```text
DMARC aligned + official domain + safe links -> stronger trust
display name Microsoft + random sender domain -> risk
reply-to free mailbox for company invoice -> risk
authenticated email but link points to unrelated support domain -> inspect destination
```

#### Phone Trust Checks

```text
E.164 normalization
line type
carrier
country/region
first seen
domains seen on
brands claimed with
official registry/domain match
campaign graph reuse
complaint/reputation source hits
```

Phone verdict examples:

```text
official domain publishes number -> weak positive
number appears on 20 unrelated support pages -> strong risk
number claims Microsoft and PayPal support on different domains -> strong risk
phone + gift-card/remote-tool context -> block in Elder Safe
```

#### Company Trust Checks

```text
registered legal entity
registration date
active/dissolved state
registered address
directors/officers where public
business identifiers: D-U-N-S, VAT, tax ID where appropriate
domain ownership relation
phone/email relation
brand affiliation relation
complaint/reputation history
```

Company verdict examples:

```text
old company + matching domain + official support portal -> trust contributor
new company + major-brand support claim + no partner proof -> suspicious
registered company + gift-card payment request -> block anyway
```

#### Action Trust Matrix

The framework should answer:

```text
what is this identity allowed to safely ask the user to do?
```

| Action | Required Trust |
|---|---|
| read article | low |
| collect email newsletter signup | low/medium |
| ask for password | strong domain + identity + sink proof |
| ask for bank/payment info | strong company/payment proof |
| ask user to call support number | verified support channel |
| ask user to install remote tool | verified support + explicit consent + guardian mode |
| ask for gift card / crypto / wire | never trusted in support context |
| ask for seed phrase | never trusted |
| ask to disable security | never trusted unless enterprise-admin policy |

#### Trust Decay And Revocation

```text
trust expires
registry checks refresh
phone/domain ownership changes downgrade trust
new scam reports trigger review
hard evidence revokes trust immediately
verified-but-risky state can exist
```

#### Product Name Idea

This can become a standalone XGenGuardian pillar:

```text
XGG TrustGraph
XGG IdentityDossier
XGG Verified Support Registry
XGG ElderSafe Trust Firewall
```

The important product promise:

```text
Nothing is trusted because it exists online.
Trust is earned, scoped, evidenced, and revocable.
```

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
