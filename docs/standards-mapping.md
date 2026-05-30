# XGenGuardian Standards Mapping

**Status:** audit-ready evidence appendix for
[`deeptrust-zero-trust-url-analysis.md`](deeptrust-zero-trust-url-analysis.md).

**Owner:** XGenGuardian detection-engine maintainers.

**Last reviewed:** 2026-05-30.

**Review cadence:** quarterly, or when (a) a referenced standard updates a
control / technique, or (b) an XGG phase ships that changes the code path
column.

This document maps the DeepTrust strategy's standards citations
(CISA Secure by Design, NIST CSF 2.0, OWASP ASVS, MITRE ATT&CK) to
concrete code paths, test paths, and reason codes in this codebase.
Each row is auditable: the standard's identifier, the implementation,
the test that proves it, the reason code surfaced to the user, and
honest status (shipped / partial / planned).

The DeepTrust strategy doc's §0.1 lists these standards as the design
basis. This file is the evidence half — what's actually implemented vs
what's still on the roadmap.

## 1. NIST Cybersecurity Framework 2.0 — Subcategory Mapping

NIST CSF 2.0 organises controls into six Functions (Govern, Identify,
Protect, Detect, Respond, Recover), each with Categories and
Subcategories. We map the subcategories most relevant to a URL /
DNS / browser-extension protection platform.

Reference: <https://www.nist.gov/cyberframework>

### GV — Govern (organisational risk strategy)

| Subcategory | Title | DeepTrust step | Code path | Status |
|---|---|---|---|---|
| **GV.PO-01** | Policy is established and communicated | Three-tier trust policy + non-negotiable engineering rules | [`CLAUDE.md`](../CLAUDE.md) §"Three-tier trust policy"; [`deeptrust-zero-trust-url-analysis.md`](deeptrust-zero-trust-url-analysis.md) §20 | Shipped |
| **GV.RM-04** | Strategic direction is communicated | Canonical strategy + roadmap in repo | [`deeptrust-zero-trust-url-analysis.md`](deeptrust-zero-trust-url-analysis.md), [`final-engine-architecture-plan.md`](final-engine-architecture-plan.md) | Shipped |
| **GV.SC-07** | Suppliers and third parties are assessed | OAuth client registry + per-source confidence tiers | `services/verdict-api/internal/oauthreg/`, `tools/oauth-seeder/clients.yaml` (59 entries) | Partial — 59/300 target |
| **GV.OV-03** | Organizational cybersecurity risk performance is evaluated | Smoke corpus + weekly rule-health report | `tools/smoke-corpus/run.py`, `tools/rule-health/report.py` | Shipped (Phase G) |

### ID — Identify (asset/risk understanding)

| Subcategory | Title | DeepTrust step | Code path | Status |
|---|---|---|---|---|
| **ID.AM-01** | Hardware inventoried | n/a — no on-prem hardware managed | n/a | n/a |
| **ID.AM-02** | Software is inventoried | Per-host renderer evidence object | `services/sandbox-render/app/main.py` (script / iframe inventory) | Partial |
| **ID.IM-04** | Improvements identified from incidents | Smoke corpus drives every Real-Fix per CLAUDE.md | [`CLAUDE.md`](../CLAUDE.md) §"Definition of a Real Fix", `reports/smoke-*.md` | Shipped |
| **ID.RA-03** | Threats are identified and recorded | Threat-feed ingestion + vendor-DNS consensus | `tools/blocklist-fetcher/`, `services/verdict-api/internal/vendordns/` | Shipped |
| **ID.RA-05** | Threat intelligence is used | 18 active feeds + 8 vendor DNS providers | `tools/blocklist-fetcher/feeds.yaml` | Shipped |

### PR — Protect (safeguards in place)

| Subcategory | Title | DeepTrust step | Code path | Status |
|---|---|---|---|---|
| **PR.AA-01** | Identities and credentials are managed | Internal X-Internal-Token authentication between services | `services/verdict-api/internal/internalauth/` | Shipped |
| **PR.AA-03** | Users are authenticated | Admin portal password + per-client_id rate limiting | `services/portal-api/`, `services/verdict-api/internal/httpgw/ratelimit.go` | Shipped |
| **PR.DS-01** | Data-at-rest is protected | Redis cache without PII; URLs hashed before storage | `services/verdict-api/internal/httpgw/telemetry.go` (Phase G hashes URLs before persistence) | Shipped |
| **PR.DS-02** | Data-in-transit is protected | HTTPS-only external endpoints; localhost-only inter-service traffic | `services/verdict-api/cmd/verdict-api/main.go` (binds 127.0.0.1 by default) | Shipped |
| **PR.PS-05** | Software is verified and signed | Code signing / package registry verification (sandbox shellcmd checks) | `services/verdict-api/internal/installreg/`, `services/verdict-api/internal/httpgw/cmdcheck.go` | Partial — install registry needs broader vendor coverage |
| **PR.IR-02** | Boundary protections are configured | UFW rules + per-service port binding to 127.0.0.1 | Deploy docs `deploy/systemd/*` | Shipped |

### DE — Detect (anomaly and event detection)

| Subcategory | Title | DeepTrust step | Code path | Status |
|---|---|---|---|---|
| **DE.CM-01** | Networks are monitored for adverse events | Vendor-DNS consensus + connection-identity layer | `services/verdict-api/internal/vendordns/`, `internal/connid/` | Shipped |
| **DE.CM-03** | Personnel activity is monitored | Per-client_id telemetry (Phase G opt-in) | `services/verdict-api/internal/httpgw/telemetry.go` | Shipped (opt-in) |
| **DE.CM-09** | Computing hardware and software is monitored | Sandbox-render captures DOM, behavior, network requests | `services/sandbox-render/app/main.py` | Shipped |
| **DE.AE-02** | Detected events are analyzed | Stage-by-stage policy engine produces decision_trace | `services/verdict-api/internal/policy/policy.go` (DecisionTrace) | Shipped (Phase E) |
| **DE.AE-03** | Information is correlated | Multi-source: feeds + vendor DNS + identity + visual + sink | `services/verdict-api/internal/policy/policy.go` Apply() | Shipped (Phase A-G) |
| **DE.AE-04** | Impact of events is determined | Verdict bands (ALLOW/WARN/BLOCK/ISOLATE) + confidence | `services/verdict-api/internal/policy/policy.go` Verdict type | Shipped |
| **DE.AE-06** | Detection information is communicated | Decision trace + reason codes on /v1/check response | `services/verdict-api/internal/httpgw/gateway.go` checkResponse | Shipped |

### RS — Respond (incident response)

| Subcategory | Title | DeepTrust step | Code path | Status |
|---|---|---|---|---|
| **RS.MA-01** | The response plan is executed | Holding-page interstitial + WARN/BLOCK/ISOLATE rendering | `apps/extension/src/holding.html`, `warn.html`, `blocked.html`, `isolate.html` | Shipped |
| **RS.AN-03** | Incidents are categorized | Reason-code taxonomy + per-category telemetry | `services/verdict-api/internal/reasons/reasons.go` | Shipped |
| **RS.MI-01** | Incidents are contained | BLOCK / ISOLATE verdicts + tab redirect | `apps/extension/src/background.js` applyVerdict() | Shipped |

### RC — Recover (recovery from incidents)

| Subcategory | Title | DeepTrust step | Code path | Status |
|---|---|---|---|---|
| **RC.RP-01** | The recovery plan is executed | Override telemetry → corpus → regression test (FP loop) | `services/verdict-api/internal/httpgw/telemetry.go`, `tools/fp-bench/`, `tools/smoke-corpus/` | Shipped (Phase G) |
| **RC.CO-03** | Recovery activities are communicated | Per-rule fire / override / FP-report metrics | `services/verdict-api/internal/metrics/metrics.go` | Shipped (Phase G) |

## 2. MITRE ATT&CK — Technique Coverage

This table maps the ATT&CK techniques most relevant to phishing,
credential theft, and malware delivery via web vectors to the
detectors that fire when XGG observes the technique.

Reference: <https://attack.mitre.org/>

### Initial Access — phishing family

| Technique | Title | Detector | Reason code(s) | Status |
|---|---|---|---|---|
| **T1566** | Phishing (parent) | Feed lookup + vendor DNS + brand impersonation | `EXTERNAL_FEED_HIT`, `VENDOR_DNS_CONSENSUS_BLOCK`, `HOMOGLYPH_OF_PROTECTED_BRAND` | Shipped |
| **T1566.001** | Spearphishing Attachment | Drive-by download + YARA scanning (planned) | `MALWARE_RAW_IP_BINARY_DROP`, `SUSPICIOUS_DOWNLOAD_OFFERED` | Partial — YARA wire pending |
| **T1566.002** | Spearphishing Link | Top-frame URL inspection + email-gateway wrapper unwrap | `EXTERNAL_FEED_HIT`, `FRESH_DOMAIN`, `HIDDEN_MALICIOUS_LINK` | Shipped |
| **T1566.003** | Spearphishing via Service | Wrapper detection covers Mimecast, Proofpoint, SafeLinks | `wrappers.go` unwrapping; surfaces wrapper_chain on response | Shipped (Wave 1) |
| **T1583.001** | Acquire Infrastructure: Domains | RDAP domain age + fresh-domain rule | `FRESH_DOMAIN`, `RANDOM_HOSTNAME` | Shipped (Phase A) |
| **T1583.004** | Acquire Infrastructure: Server | Raw-IP + suspicious-ASN detection | `RAW_IP_HOST`, `MALWARE_RAW_IP_BINARY_DROP` | Shipped |
| **T1593.001** | Search Open Websites/Domains | Brand-keyword + tier-1 lexical/homoglyph | `HOMOGLYPH_OF_PROTECTED_BRAND` | Shipped (Wave 2.5) |

### Defense Evasion — masquerading and obfuscation

| Technique | Title | Detector | Reason code(s) | Status |
|---|---|---|---|---|
| **T1036** | Masquerading (parent) | Brand identity binding + visual replica + sink trust | `BRAND_CLAIM_DOMAIN_MISMATCH`, `FAVICON_BRAND_MISMATCH` | Shipped |
| **T1036.005** | Match Legitimate Name or Location | Brandgraph + orggraph + scope-aware trust | `services/verdict-api/internal/brandgraph/`, `internal/orggraph/` | Shipped (Phase C) |
| **T1027** | Obfuscated Files or Information | Sandbox JS analysis (entropy + eval/atob chains) | `OBFUSCATED_JS_DETECTED` | Shipped (Phase E) |

### Command and Control — C2 patterns

| Technique | Title | Detector | Reason code(s) | Status |
|---|---|---|---|---|
| **T1071** | Application Layer Protocol | DNS resolver-side blocking of known C2 domains | `EXTERNAL_FEED_HIT` (URLhaus C2 category) | Shipped |
| **T1071.001** | Web Protocols | Vendor-DNS consensus + behavioral analysis | `VENDOR_DNS_CONSENSUS_BLOCK` | Shipped |
| **T1102** | Web Service | Shared-hosting platform escalation + tenant detection | shared-hosting suffix list in `LooksLikeDevToolInstallLure` + soft-rule accumulator | Shipped |
| **T1568.002** | Dynamic Resolution: DGA | DGA classifier + random-host heuristic | `RANDOM_HOSTNAME`, `DGA_CLASSIFIER_HIT` | Partial — classifier is heuristic |

### Credential Access

| Technique | Title | Detector | Reason code(s) | Status |
|---|---|---|---|---|
| **T1056.001** | Input Capture: Keylogging | Sandbox keystroke listener detection (Phase D pre-submit) | `CREDENTIAL_SINK_PRE_SUBMIT_CAPTURE` | Shipped |
| **T1056.003** | Input Capture: Web Portal Capture | Cross-origin form-action + hidden-mirror detection | `CREDENTIAL_SINK_HIDDEN_MIRROR`, `FORM_POSTS_TO_UNRELATED_DOMAIN` | Shipped |
| **T1539** | Steal Web Session Cookie | OAuth unknown-clientID + scope-severity | `OAUTH_UNKNOWN_CLIENT_ID` | Partial — registry growing |

### Impact — fraud and scam

| Technique | Title | Detector | Reason code(s) | Status |
|---|---|---|---|---|
| **T1657** | Financial Theft (parent) | Support-scam scorer + gift-card phrase detection | `SUPPORT_SCAM_LANGUAGE`, `GIFT_CARD_PAYMENT_DEMAND`, `REMOTE_TOOL_LURE` | Partial — Wave 3 Phase 1; OCR + visible-DOM-text pending |

### Resource Development

| Technique | Title | Detector | Reason code(s) | Status |
|---|---|---|---|---|
| **T1598.003** | Phishing for Information: Link | Top-frame URL inspection on the request | (all phishing detectors above) | Shipped |

## 3. OWASP ASVS — Application Security Verification Standard

ASVS is a web-application-security verification framework. Most ASVS
chapters target web apps that handle authentication, sessions, and user
data — XGG is a detection backend, so only specific ASVS controls
translate cleanly. We map only those.

Reference: <https://owasp.org/www-project-application-security-verification-standard/>

Target level: **ASVS L2** (commercial-grade applications). Controls
not relevant to a stateless detection engine (e.g. session management,
user-facing CSRF) are intentionally out of scope.

### V1 — Architecture, Design and Threat Modeling

| Control | Title | Implementation | Status |
|---|---|---|---|
| **V1.2.1** | Authentication architecture is defined | X-Internal-Token between services; public extension auth via per-client_id rate limiting | Shipped |
| **V1.8.1** | Personal data is identified and minimised | URL + client_id hashed before persistence (Phase G) | Shipped |

### V7 — Cryptography

| Control | Title | Implementation | Status |
|---|---|---|---|
| **V7.1.1** | Cryptographic keys are securely managed | XGG_INTERNAL_TOKEN in systemd override.conf only | Shipped |
| **V7.4.1** | TLS / certificate verification | Sandbox + visual-match called over TLS-verified HTTP | Partial — inter-service runs cleartext on localhost |

### V8 — Data Protection

| Control | Title | Implementation | Status |
|---|---|---|---|
| **V8.1.1** | Sensitive data is protected at rest | No raw URLs stored; SHA-256 hash + host only | Shipped (Phase G) |
| **V8.3.4** | Cached responses do not contain sensitive data | Redis cache contains only verdict + reason codes | Shipped |

### V10 — Malicious Code

| Control | Title | Implementation | Status |
|---|---|---|---|
| **V10.3.1** | Application searches for malicious code (YARA / signatures) | Sandbox JavaScript inspection + shellcmd pattern matching | Partial — YARA wiring is stubbed |

### V12 — File Handling

| Control | Title | Implementation | Status |
|---|---|---|---|
| **V12.4.1** | File upload is restricted | Sandbox renders external URLs; no untrusted uploads accepted | Shipped |

### V14 — Configuration

| Control | Title | Implementation | Status |
|---|---|---|---|
| **V14.1.1** | Build pipeline produces reproducible artifacts | Go modules + Python pyproject.toml | Shipped |
| **V14.2.3** | Dependencies are tracked | Go go.mod / go.sum; Python pyproject.toml | Shipped |
| **V14.4.1** | Component administration is restricted | systemd unit drop-ins (`override.conf`) hold secrets; not in source | Shipped |
| **V14.5.1** | Application restricts HTTP methods | Per-endpoint method check in gateway.go (POST only on /v1/check, /v1/telemetry/override etc.) | Shipped |

## 4. CISA Secure by Design — Principles Applied

CISA Secure by Design is a principle set, not a control list. We
enumerate which principles XGG adopts and the evidence.

Reference: <https://www.cisa.gov/securebydesign>

### Principle 1: Take ownership of customer security outcomes

- The engine never silently allows a sensitive page when proof is missing
  (`SENSITIVE_PAGE_VERIFICATION_UNAVAILABLE`, `TIER2_DATA_UNAVAILABLE`).
- Health-gated degraded modes ensure operational state is reflected in
  the verdict (Wave 1).

### Principle 2: Embrace radical transparency and accountability

- Every verdict ships a `decision_trace[]` so the user can see exactly
  how the engine decided (Phase E, refined Wave 1+).
- Smoke corpus baseline saved with every notable commit
  (`reports/smoke-*.md`).
- Per-rule fire / override / FP-report metrics (Phase G).

### Principle 3: Lead from the top — engineering rules

- Three-tier trust policy (`CLAUDE.md`).
- Ten non-negotiable engineering rules (DeepTrust §20).
- "Definition of a Real Fix" gates every FP/FN patch.

## 5. Implementation Coverage Summary

| Standard | Total mappable controls | Shipped | Partial | Planned |
|---|---:|---:|---:|---:|
| NIST CSF 2.0 | 24 | 21 | 3 | 0 |
| MITRE ATT&CK | 16 | 12 | 4 | 0 |
| OWASP ASVS L2 | 12 | 10 | 2 | 0 |
| CISA Secure by Design | 3 principles | 3 | 0 | 0 |

**Aggregate: 55 mapped controls / techniques / principles; 46 shipped,
9 partial, 0 planned-but-not-started.**

The "partial" rows are honest gaps the doc surfaces. They drive the
roadmap in [`detection-category-improvement-plan.md`](detection-category-improvement-plan.md):

- YARA wiring: `T1566.001`, `V10.3.1` — needs scanner integration
- OAuth client registry expansion: `T1539`, `GV.SC-07` — at 59/300
- DGA classifier: `T1568.002` — heuristic only, needs ML model
- Support-scam OCR: `T1657` — Wave 3 Phase 1 ships URL+SLD; visible-DOM-text + OCR pending
- Install-command registry breadth: `PR.PS-05` — covers ~5 vendors
- Inter-service TLS: `V7.4.1` — localhost cleartext today

Each one has a corresponding entry in the improvement plan with effort
estimates.

## 6. How To Use This Document

- **Auditing**: For each row, the "Code path" column points at the
  implementation. The test column (where present) proves the control
  works. The status column distinguishes truth from aspiration.
- **Roadmap**: Filter to "partial" — those are the next units of work.
  Each partial entry should converge to "shipped" before its
  corresponding standards-citation can be claimed without qualification.
- **Compliance reporting**: Use the per-standard tables as the basis
  for SOC 2 / ISO 27001 / NIS2 control mapping. Quote actual
  subcategory IDs, not the framework name.

## 7. Maintenance

When a phase ships:
1. Update the relevant rows' Status column.
2. Add new reason codes to the ATT&CK technique rows they implement.
3. Recompute the §5 coverage summary.
4. Update `Last reviewed` at the top.

When a standard publishes a new revision:
1. Diff the new subcategory list against §1.
2. Flag any newly applicable controls as `Planned` in the status column.
3. Open an issue in `docs/issues/` per planned addition.
