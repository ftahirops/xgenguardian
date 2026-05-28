# Comprehensive DNS + URL Security Platform
### Full Architecture, Threat Model, Market Analysis, and Extended Feature Set

---

## Table of Contents
1. Threat Model
2. Architectural Principles
3. Full System Architecture
4. Layer-by-Layer Specification (L0–L6)
5. Brand Protection Registry
6. Continuous Intelligence Plane
7. Transparency Portal (User-Facing Scan Results)
8. Latency Budget & UX
9. Deployment Surfaces
10. Tech Stack
11. Build Sequence
12. Why This Reaches ~99.999%
13. Critical Market Analysis — Who Already Does This?
14. Extended / Out-of-the-Box Feature Set
15. Site Registry Database — Schema and Lifecycle
16. Strategic Implications
17. Master Feature Catalog (Priority-Locked)
18. Threat → Feature Coverage Map
19. Deployment Model — DNS vs Proxy vs Hybrid (How to Use the System)
20. Recommended Reference Architecture
21. Resource Footprint & Cost Profile
22. User Acceptance & Onboarding
23. Proxy Variants Deep-Dive (Cloudflare-Style Model)
24. POC Plan — Minimal Client, Maximum Demo Value
25. Effort Estimation — Every Deployment Variant
26. Endpoint Client (AV-Class) — Windows + Linux Full Traffic Visibility
27. Concise Feature Index (Effectiveness Per Feature)
28. DNS-Level Timing & User Flow (Tier-1/2/3 Strategy)
29. User Dashboard, Admin Console & SaaS Multi-Tenancy
30. Industry-Standard Detection Methods (Quad9, NextDNS, Umbrella, et al.)
31. Coverage Boundaries & Out-of-Scope Positioning
32. XGenGuardian — Positioning, Differentiation & Sales Pitch
33. Implementation Plan — Phased Feature Build
34. **Phase 0/1 Starter Repo Structure**
35. **Phase 1 Week-1 Backlog (Ticket-Level)**
36. **Brand Registry Seed List (Phase 1 — 50 Brands)**

---

## 1. Threat Model

### 1.1 DNS-Layer Threats

| Category | Attack | Description |
|---|---|---|
| Resolution | DNS spoofing / cache poisoning | Forged DNS records injected into resolver cache |
| | DNS hijacking | Router/ISP/resolver compromised to redirect lookups |
| | Rogue DHCP → rogue DNS | LAN attacker hands out malicious resolver |
| | DNS rebinding | Site changes its IP after load to attack internal hosts |
| | NXDOMAIN hijacking | ISP serves ad-page IP instead of NXDOMAIN |
| Tunneling | DNS tunneling (C2, exfil) | TXT/A queries encode data over port 53 |
| | DoH abuse | Malware uses public DoH to bypass filtering |
| | Fast-flux / domain-flux / DGA | Rotating IPs & algorithmic domains for C2 |
| Identity | Typosquatting | `g00gle.com`, `paypa1.com` |
| | Homograph / IDN | `аpple.com` (Cyrillic а), `xn--` Punycode |
| | Combosquatting | `paypal-secure-login.com` |
| | Bitsquatting | Single-bit-flip neighbor domains |
| | Subdomain takeover | Dangling CNAME claimed by attacker |
| | Newly Registered Domains | <30-day-old domains for one-shot phishing |
| Infra | BGP hijack | Attacker advertises route for legit IP space |
| | TLS downgrade / SSL strip | Force HTTP, intercept |
| | Rogue / mis-issued certs | CA compromise, fraudulent issuance |
| | Resolver DDoS | Force fallback to attacker resolver |
| | Lame delegation / orphan NS | Hijack abandoned nameservers |

### 1.2 URL / Content-Layer Threats

| Category | Attack |
|---|---|
| Phishing | Credential capture, OAuth consent phishing, MFA-relay (Evilginx/Modlishka), browser-in-the-browser (BITB), QR-code phishing (quishing) |
| Malware | Drive-by downloads, malvertising, watering-hole compromise, fake updates, ClickFix paste-to-run, HTML smuggling |
| Code exec | Browser zero-days, plugin exploits, malicious WASM, supply-chain JS (CDN/npm compromise) |
| Cryptojacking | In-browser miners |
| Scams | Tech-support, fake stores, romance/investment, AI deepfake video sites |
| Evasion | Cloaking (clean to scanners, payload to victims), time-bombs, geo-fencing, captcha walls, redirect chains, open-redirect abuse |
| Zero-day | New phishing kits (<6h old), AI-generated lookalike pages, polymorphic landing pages, LLM-crafted lures, deepfake-supported sites |

### 1.3 "Zero-Day" Categories
- **Zero-day phishing** — domain + kit never seen; no blocklist hit.
- **Zero-day exploit** — browser/OS vuln, no patch.
- **Zero-day malware** — unique binary, no AV signature.
- **AI-generated content** — fresh HTML/copy/images that defeat hash/template detection.

Defense must rely on **behavior + visual + semantic + infrastructure correlation**, not signatures.

---

## 2. Architectural Principles

1. **Defense in depth** — never trust one signal; fuse many.
2. **Identity mismatch is the universal phishing tell** — looks like Brand X but doesn't match Brand X's known infrastructure.
3. **Resolve-time enforcement** — block before TCP handshake when possible.
4. **Render-time enforcement** — for unknowns, render in a sandbox you control.
5. **Latency budget tiers** — fast path for 99% known-good, deep analysis for the 1% unknown.
6. **Transparency** — every verdict has a complete, viewable evidence bundle.
7. **Continuous learning** — every verdict, user report, and CT log entry feeds retraining.
8. **Fail-closed for high-risk** — unknown + suspicious infra → block until analyzed.

---

## 3. Full System Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │            CLIENT TIER                        │
                     │  Browser Ext · OS DNS Proxy · Mobile VPN     │
                     │  Endpoint Agent · Email Gateway · SWG Proxy  │
                     └──────────────────┬───────────────────────────┘
                                        │  (DoH/DoT + URL submission)
                     ┌──────────────────▼───────────────────────────┐
                     │           EDGE / INGRESS                      │
                     │  Anycast DoH/DoT · gRPC URL API              │
                     │  DDoS shield · TLS · auth                    │
                     └──────────────────┬───────────────────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
┌───────────────┐              ┌───────────────┐              ┌────────────────┐
│  L0 DNS CORE  │              │ L1 FAST PATH  │              │ TRANSPARENCY   │
│ DNSSEC, DoH,  │              │ Cache · Bloom │              │  Portal & API  │
│ DoT, QNAME    │              │ Allow/Block   │              │ (per-URL       │
│ min, 0x20,    │              │ Recent verdict│              │  evidence)     │
│ NRD filter    │              └──────┬────────┘              └────────────────┘
└───────┬───────┘                     │ unknown
        │                             ▼
        ▼                  ┌─────────────────────┐
   Client                  │ L2  INFRA + LEXICAL │
                           │ WHOIS·RDAP·ASN·DNS  │
                           │ TLS·CT·Homoglyph    │
                           │ Domain age·DGA ML   │
                           └─────────┬───────────┘
                                     │ suspicious / unknown
                                     ▼
                           ┌─────────────────────┐
                           │ L3 CONTENT FETCH    │
                           │ Headless render in  │
                           │ Firecracker microVM │
                           │ Multi-egress diff   │
                           └─────────┬───────────┘
                                     ▼
                           ┌─────────────────────┐
                           │ L4 VISUAL+SEMANTIC  │
                           │ CLIP · pHash · DOM  │
                           │ logo CV · OCR · LLM │
                           │ vs. Brand Registry  │
                           └─────────┬───────────┘
                                     ▼
                           ┌─────────────────────┐
                           │ L5 BEHAVIORAL       │
                           │ JS sandbox · API    │
                           │ hooks · canary      │
                           │ creds · redirects · │
                           │ DNS rebinding test  │
                           └─────────┬───────────┘
                                     ▼
                           ┌─────────────────────┐
                           │ L6 FUSION + LLM     │
                           │ XGBoost · LLM ·     │
                           │ Policy engine       │
                           └─────────┬───────────┘
                                     ▼
                       Allow / Warn / Block / Quarantine
                                     │
                                     ▼
                       ┌──────────────────────────┐
                       │  EVIDENCE STORE          │
                       │  Screenshot · DOM · PCAP │
                       │  → Transparency Portal   │
                       └──────────────────────────┘

       ┌──────────────────────────────────────────────────────────┐
       │                  CONTINUOUS INTEL PLANE                   │
       │  CT firehose · NRD feeds · PhishTank/OpenPhish ·          │
       │  VT/GSB/SmartScreen · honeypots · user reports ·          │
       │  passive DNS · BGP monitor · STIX/TAXII feeds             │
       └────────────────────┬─────────────────────────────────────┘
                            ▼
       ┌──────────────────────────────────────────────────────────┐
       │       MODEL & REGISTRY TRAINING PIPELINE                  │
       │  Feature store · PyTorch · LightGBM · vector DB          │
       │  Nightly retrain · drift detection · A/B shadow eval     │
       └──────────────────────────────────────────────────────────┘
```

---

## 4. Layer-by-Layer Specification

### L0 — Hardened DNS Core
- **DNSSEC validation**; reject bogus / insecure delegations for sensitive TLDs.
- **DoH + DoT only**; reject plaintext port-53 from clients.
- **QNAME minimization** (RFC 7816).
- **DNS 0x20 case randomization** to defeat off-path poisoning.
- **Aggressive NSEC caching**.
- **NRD filter** — auto-block all domains <24h old (configurable). Catches >70% of phishing.
- **DGA classifier** — entropy + n-gram model flags algorithmically-generated domains.
- **DNS tunneling detector** — flag abnormal query rate/size/entropy; block TXT-flood.
- **Public DoH-bypass control** — block client connections to 1.1.1.1, dns.google, etc.; force all DoH through your resolver.
- **Sinkhole infrastructure** — bad domains resolve to a logging sinkhole.
- **Response Policy Zones (RPZ)** — dynamic policy zones from intel.
- **Anycast deployment** — multi-region for latency + DDoS resilience.

### L1 — Fast Path (≤50 ms)
- Redis: recent verdicts keyed by URL hash + domain.
- Tranco top 1M allowlist (Bloom filter).
- Org-defined allow/block lists.
- Aggregated blocklist (PhishTank + OpenPhish + URLhaus + GSB + SmartScreen + custom).
- TTL by risk: bad = 30 d, allow = 24 h, unknown = 0.

### L2 — Infrastructure + Lexical (≤200 ms)
- **Lexical** — length, entropy, digit ratio, subdomain depth, suspicious keywords (`login`, `verify`, `secure-`, `wallet`, `mfa`), hyphens, TLD reputation.
- **Homoglyph & typo** — Damerau-Levenshtein + Jaro-Winkler vs. brand registry; Unicode confusable normalization; Punycode unwrap; bit-flip neighbors.
- **WHOIS/RDAP** — registrar reputation, age, privacy-proxy.
- **DNS records** — NS, MX, SOA, TXT, SPF/DMARC.
- **ASN/hosting** — reputation per ASN/CIDR.
- **TLS** — cert age, issuer, SANs, OCSP.
- **Certificate Transparency** — preemptive flagging of brand-lookalike issuance.
- **Passive DNS history** — first-seen, resolution churn (fast-flux).
- **BGP** — origin AS vs. historical legitimate AS.

### L3 — Content Fetch & Sandbox Render (≤2 s)
- **Firecracker microVM** per fetch — single-use, destroyed after.
- **Headless Chromium** via Playwright with realistic fingerprint.
- **Multi-egress fetch** — residential + datacenter + mobile + Tor + Googlebot UA. Diff responses → cloaking detection.
- **Geo-rotated** — fetch from 3+ regions.
- **Capture** — HTML, DOM, subresources, HAR, JS source (de-obfuscated), screenshots, console, cookies.
- **Static analysis** — form action targets, password/CC fields, hidden fields, JS AST for phishing-kit signatures, obfuscation density, eval/atob chains, WebSocket exfil.
- **HTML smuggling detector** — blob URLs assembled in-JS.

### L4 — Visual & Semantic Similarity (≤3 s)
**The layer that catches `w1thineartht.com`.**

- **Screenshot CNN embedding** (CLIP / Siamese) → cosine vs. Brand Registry vector DB.
- **Perceptual hash** (pHash/dHash/wHash) fast first-pass.
- **Favicon hash** (MMH3 + pHash).
- **DOM-tree edit distance** vs. brand fingerprints.
- **Logo object detection** (YOLO).
- **OCR + text classifier** — extract rendered text, run brand-name + intent classifier.
- **LLM page-understanding** — multimodal model: "What brand is this page trying to be?"

**Universal phishing rule:**
```
visual_or_semantic_similarity(page, brand_X) ≥ τ
AND domain ∉ brand_X.canonical_domains
AND (domain_age < 90 d OR ASN ∉ brand_X.legit_ASNs OR cert ∉ brand_X.legit_issuers)
  → phishing
```

### L5 — Behavioral Sandbox (≤10 s, async OK)
- **Instrumented browser hooks** — clipboard, credential autofill, crypto.subtle, WebRTC IP leak, WebSocket targets, Service Worker, push permission.
- **Canary credentials** — submit fake creds; observe POST destination → maps phishing infra.
- **Redirect chain** — follow N hops; flag open-redirect abuse, shortener chains, meta-refresh, JS-driven redirects.
- **DNS rebinding test** — re-resolve repeatedly; flag short-TTL flips to RFC1918.
- **Anti-analysis detection** — replay with simulated mouse, delay, devtools-closed.
- **Network behavior** — TI-flagged IPs, Tor, anomalous geo.
- **File downloads** — detonate in separate file-sandbox tier (CAPE/Cuckoo).

### L6 — Fusion, Policy & LLM Reasoner
- **LightGBM/XGBoost** on ~200 features → calibrated 0–1 risk score.
- **LLM reasoner** consumes evidence → human-readable verdict + top-3 signals.
- **Policy engine** (OPA/Rego) maps (score, category, user-group, time) → action.
- Actions: **Allow / Warn / Block / Quarantine**.
- Fail-closed on unknown+high-risk-infra; fail-open on known-good cache hits.

---

## 5. Brand Protection Registry

| Field | Purpose |
|---|---|
| Canonical domains + subdomains | Allowlist |
| Legitimate ASNs / IP CIDRs | Infra match |
| Legitimate cert issuers + thumbprints | Cert match |
| Screenshot embeddings (per critical page) | Visual match |
| DOM fingerprints | Structural match |
| Favicon hashes | Fast visual match |
| Logo image embeddings | CV match |
| Brand keywords, product names, exec names | Text match |
| Email infra (SPF/DKIM/DMARC) | Cross-channel |
| Mobile app bundle IDs | Mobile vectors |

Auto-populated from Tranco top-N + CT logs. A new URL is judged **against** this registry, not in isolation.

---

## 6. Continuous Intelligence Plane

- **CT log firehose** (Certstream) → real-time cert issuance → preemptive scoring.
- **Newly Registered Domain feeds** (WhoisDS, DomainTools).
- **Passive DNS** (Farsight DNSDB, SecurityTrails).
- **Public threat feeds** — PhishTank, OpenPhish, URLhaus, abuse.ch, Spamhaus, MalwareBazaar, GSB, SmartScreen, VT.
- **STIX/TAXII** ingest for commercial TI.
- **Honeypots** — bait emails harvest phishing URLs.
- **User report button** → analyst queue → training data.
- **BGP monitoring** (RIPE RIS, BGPmon).
- **Tor/dark-web monitoring** — phishing kits sold pre-deployment.

---

## 7. Transparency Portal — User-Facing Scan Results

A user can paste any URL or click "Why was this blocked?" and see:

```
URL: https://w1thineartht.com/login
Verdict: BLOCKED — High-confidence phishing (0.97)

╔════════════════════════════════════════════════════════╗
║  SCREENSHOT (sandboxed)                                ║
║  [thumbnail with red border]                           ║
╚════════════════════════════════════════════════════════╝

EVIDENCE
─────────────────────────────────────────────────────────
■ Lookalike domain — edit distance 1 from "withinearth.com"
  Homoglyph: '1' substitutes 'i'; extra 't' appended
■ Domain age — Registered 4 days ago via Namecheap
  Privacy-proxy WHOIS
■ TLS — Issued 2 days ago by Let's Encrypt; no cert history
■ Hosting — ASN 12345 (BulletproofVPS-LLC), 847 phishing
  domains in 30 days. Not a known withinearth.com ASN.
■ Visual — screenshot similarity 0.96; favicon SHA matches;
  "withinearth" wordmark detected (CV 0.99)
■ Behavior — credentials POST to collect.evil-c2.tk/api;
  blank to datacenter IPs (cloaking); push permission in 2s

LLM EXPLANATION
─────────────────────────────────────────────────────────
This page visually impersonates withinearth.com's login
screen with 96% similarity, but the domain is not one of
withinearth.com's canonical domains. The domain is 4 days
old on infrastructure unrelated to the real brand. Submitted
credentials are exfiltrated to a third-party domain. This
is a credential-harvesting phishing page.

ARTIFACTS
─────────────────────────────────────────────────────────
[Download HAR]  [Download DOM]  [Screenshots]
[JS analysis]   [Network graph]

Disagree? [Report false positive]
```

---

## 8. Latency Budget & UX

| Scenario | Path | Latency |
|---|---|---|
| Known good | L1 cache | <20 ms |
| Known bad | L1 blocklist | <20 ms |
| Unknown, low-risk | L1+L2 | <250 ms |
| Unknown, suspicious | L1–L4 | ~3 s (interstitial) |
| Unknown, high-risk | L1–L5 | ~10 s (full interstitial w/ progress) |

Browser ext shows non-blocking "Verifying…" for tier-3+. Email rewriting scans at receive time so users never wait.

---

## 9. Deployment Surfaces

1. Anycast DoH/DoT resolver
2. Browser extension (Chrome/Firefox/Edge/Safari)
3. Mobile VPN profile (iOS/Android)
4. Endpoint agent (Win/Mac/Linux)
5. Email gateway w/ URL rewriting (time-of-click)
6. Forward proxy / SWG with MITM TLS
7. API for SaaS partners (Slack/Teams/Discord)

---

## 10. Tech Stack

| Component | Choice |
|---|---|
| DNS resolver | Unbound or Knot Resolver + RPZ/Lua |
| DoH/DoT termination | Envoy / NGINX |
| Edge | Anycast (BGP) or Cloudflare Spectrum |
| Sandboxes | Firecracker microVMs on Kubernetes + Kata |
| Headless | Playwright Chromium pool |
| File detonation | CAPE Sandbox / Cuckoo |
| Stream | Kafka |
| Cache | Redis Cluster + RocksDB Bloom |
| Vector DB | Qdrant / Milvus |
| Feature store | Feast |
| ML | PyTorch (CLIP, YOLO, Siamese), LightGBM |
| LLM | Hosted Claude/GPT or local Llama |
| Orchestration | Temporal |
| Policy | OPA (Rego) |
| Evidence | S3 + signed URLs |
| Observability | OTel → Prometheus + Grafana + Loki |
| SIEM | Splunk / Elastic / Chronicle |

---

## 11. Build Sequence

| Phase | Weeks | Deliverable |
|---|---|---|
| 1 | 1–3 | Hardened DoH/DoT resolver + DNSSEC + NRD + RPZ + sinkhole |
| 2 | 4–6 | L1+L2: cache, lexical, homoglyph, WHOIS, TLS, CT monitor |
| 3 | 7–9 | Brand registry + favicon/screenshot hashing |
| 4 | 10–13 | L3 sandbox fetch (Firecracker + Playwright + multi-egress) |
| 5 | 14–17 | L4 visual similarity (CLIP + vector DB + logo CV) |
| 6 | 18–21 | L5 behavioral sandbox + canary creds + cloaking diff |
| 7 | 22–24 | L6 fusion + LLM reasoner + policy |
| 8 | 25–28 | Transparency portal + browser ext + email gateway |
| 9 | 29+ | Mobile VPN, endpoint agent, partner API, scale |

---

## 12. Why This Reaches ~99.999%

- Most attacks fail at **L0** (NRD/DGA/CT) before resolution succeeds.
- Lookalikes that pass L0 fail at **L2** (homoglyph + cert age + ASN mismatch).
- Novel kits and AI-generated pages fail at **L4** (visual/semantic match without infra match).
- Cloaked pages fail at **L5** (multi-egress diff).
- Compromised legit sites with injected payloads fail at **L5** (JS behavior + canary).
- Browser zero-days are mitigated because the **payload renders in your sandbox, not the user's browser**.

### What still gets through
- Brand-new brand the registry has never heard of.
- Compromised CDN serving malicious JS only briefly between scans.
- Pure scam pages that impersonate no brand.
- In-person/voice phishing referring users to a *legit* site they then misuse.

These are caught later by feedback loop + analyst triage + endpoint behavior anomalies.

---

## 13. Critical Market Analysis

**No single product matches this spec.** Closest combinations:

| Capability | Our design | Cloudflare One | Zscaler | SlashNext | Bolster | Cisco Umbrella |
|---|---|---|---|---|---|---|
| Hardened DoH/DoT | ✅ | ✅ | ✅ | ➖ | ❌ | ✅ |
| DNSSEC + QNAME min + 0x20 | ✅ | ✅ | partial | ❌ | ❌ | partial |
| NRD blocking | ✅ | ✅ | ✅ | ➖ | monitor | ✅ |
| DGA/tunneling ML | ✅ | ✅ | ✅ | ➖ | ❌ | ✅ |
| Homoglyph/typo inline | ✅ | partial | partial | ✅ | ✅ | partial |
| CT-log proactive scan | ✅ | partial | ❌ | ✅ | ✅ | ❌ |
| Inline sandboxed render | ✅ | via BI | ✅ | partial | offline | ❌ |
| Multi-egress cloaking diff | ✅ | ❌ | ❌ | partial | ✅ | ❌ |
| Visual CNN brand match | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Identity-mismatch fusion | ✅ | ❌ | ❌ | partial | partial | ❌ |
| Behavioral + canary creds | ✅ | partial | ✅ | partial | partial | ❌ |
| LLM verdict explanation | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| End-user transparency portal | ✅ | ❌ | ❌ | ❌ | SOC-only | ❌ |
| Universal brand registry | ✅ | ❌ | ❌ | ❌ | per-brand-owner | ❌ |

### Genuinely Novel Aspects
1. Identity-mismatch verdict primitive deployed **inline at resolution time**.
2. **End-user transparency portal** with full evidence + LLM explanation.
3. Brand registry protecting users of **any** brand (not pay-per-brand).
4. LLM reasoner over evidence bundles, inline.
5. Hardened DNS + sandboxed render + visual brand match + LLM + transparency, as **one product**.

### Closest Competitor
**SlashNext** for the AI/visual side; **Cloudflare One** for the platform reach. Bolster is closest on identity-mismatch but offline/brand-owner-only.

---

## 14. Extended / Out-of-the-Box Feature Set

These are additional capabilities beyond the L0–L6 base.

### 14.1 Redirect Chain Forensics
- Resolve every URL through its **full redirect chain** (HTTP 30x, meta-refresh, JS `location.*`, history.pushState abuse).
- Score on:
  - Number of hops (>3 = suspicious).
  - Cross-TLD hops.
  - Shortener cascades (bit.ly → t.co → unknown.tk).
  - Open-redirect abuse on legit domains (`google.com/url?q=...`, `linkedin.com/redir/...`).
  - Hop-jurisdiction diff (US → RU → SC).
- Render the **final destination**, not the entry URL, for L3–L5.

### 14.2 Download / File Verdict (Even From "Genuine" Sites)
Every binary, archive, document, or installer offered by any page passes through:
- **Multi-AV** scan (≥30 engines via MetaDefender/VT-style aggregation).
- **YARA rules** for known kit signatures.
- **CAPE/Cuckoo dynamic detonation** — observe process spawn, registry, network, persistence.
- **Code signing** check — Authenticode/Apple notarization; flag missing or revoked signers.
- **PE entropy + packer detection** (UPX, Themida, custom).
- **Macro + LOLBin** scan for Office/PDF.
- **Reputation by hash** vs. global file registry.
- **Verdict per file**, surfaced inline before download completes (proxy holds the bytes).

### 14.3 "Even Genuine Site" Compromise Detection
A site can be legitimate and still serving malicious content (compromised CMS, malvertising, supply-chain JS). Detection:
- Compare current DOM/JS hash to historical baseline for known-good sites — drift alerts.
- **Subresource Integrity** verification on script tags.
- **Third-party script provenance** — has this CDN been compromised in last 24 h?
- **Ad/iframe scanning** — render and analyze each iframe origin separately.
- **JS supply-chain** — match loaded scripts to npm/CDN packages; flag known-bad versions.

### 14.4 Score-Based Chained External Scanning
When internal score is borderline (0.4–0.7), automatically fan out to external scanners and aggregate:
- Google Safe Browsing API
- Microsoft SmartScreen
- VirusTotal URL + file
- urlscan.io
- PhishTank, OpenPhish
- AlienVault OTX
- IBM X-Force Exchange
- AbuseIPDB
- Cisco Talos
- Quad9 PDNS

Logic: if ≥N external scanners flag, raise verdict; if all clean, lower but don't allowlist (zero-day blind spot).

### 14.5 Deeper-Chain Analysis Pipeline
For high-suspicion-but-not-conclusive URLs:
1. Re-scan from **different country exits**.
2. Re-scan at **+1h, +6h, +24h** — phishing kits often "warm up" their payload.
3. **Wayback Machine** + Common Crawl historical diff — page changed dramatically vs. last year?
4. **Whois history** (DomainTools Iris) — registrant changed recently?
5. **Related-domain pivot** — cluster by ASN/registrant/TLS-fingerprint; if any sibling is malicious, raise this one.
6. **Infrastructure graph** — build node graph (domain, IP, ASN, registrant, certificate, name-server); guilt-by-association scoring.

### 14.6 User-Behavior & Identity Layer
- **Credential exposure check** — page asks for credentials matching a corporate domain? Apply stricter rules.
- **Browser autofill protection** — disable autofill on unverified pages by policy.
- **Just-in-time MFA prompt** — for low-confidence-but-allowed sites, force step-up auth.
- **Per-user risk score** — users who click more get tighter policies.
- **Honeytoken creds** — seeded into endpoints; tripwire if submitted anywhere.

### 14.7 QR-Code / Image-Embedded URL Defense
- OCR every QR seen via mobile/email/PDF clients; resolve URL through the same pipeline.
- Block QR-only payloads (image with QR, no surrounding text) when from unknown sender.

### 14.8 Voice / SMS / Messenger Vectors
- Same URL pipeline available via API to:
  - SMS gateways (filter smishing links).
  - Slack/Teams/Discord webhooks (every posted link).
  - WhatsApp/Telegram bots.
- LLM analyzes the **message text + URL together** — context catches social-engineering tone even if the URL alone is borderline.

### 14.9 Decentralized Reputation / Federated Intel
- Opt-in **anonymous telemetry sharing** between deployments — a phishing URL caught at customer A's site is immediately blocked at customer B's.
- Cryptographically signed verdicts shareable as a public feed.

### 14.10 Active Disruption (Carefully Scoped, Authorized Only)
- Submit **canary creds** to detected phishing pages to dilute attacker datasets.
- Automate **takedown notices** to registrars and hosting providers.
- File **NetCraft / APWG / CERT** reports automatically.

### 14.11 AI Anomaly Layer
- Train an **autoencoder** on legitimate page features; high reconstruction error = anomaly.
- **GNN over the infrastructure graph** — detect tightly-knit malicious clusters.
- **LLM red-team adversary** — periodically generates synthetic phishing variants; if your detector misses them, those become training samples.

### 14.12 Privacy-Preserving Querying
- **Oblivious DNS over HTTPS (ODoH)** so the resolver can't link queries to users.
- Hashed/blinded URL lookups via OPRF — clients can ask "is this URL bad?" without revealing it in clear.

### 14.13 Post-Click Forensics & Rollback (Endpoint Agent)
- Record process tree, file writes, registry changes for the 60 s after a click.
- If a verdict flips to malicious post-hoc, **auto-rollback** writes (via VSS/APFS snapshots).
- Quarantine the host from network until cleared.

### 14.14 Mobile-Specific
- App-link inspection (Universal Links / App Links).
- TestFlight / sideload app fingerprinting.
- Detect in-app browser vs. system browser; flag in-app browser credential prompts.

### 14.15 Browser Isolation Fallback
- For unresolved-suspicion URLs, render in a **remote isolated browser** and stream pixels — user can interact safely; no JS or DOM ever reaches their device.

---

## 15. Site Registry Database — Schema and Lifecycle

A persistent, continuously-updated database of every domain/URL the system has ever seen, with its full verdict history.

### 15.1 Core Schema

```
Table: domains
  domain                TEXT PRIMARY KEY
  first_seen            TIMESTAMP
  last_seen             TIMESTAMP
  registrar             TEXT
  registrant            TEXT (or 'privacy')
  registered_at         TIMESTAMP
  expires_at            TIMESTAMP
  current_asn           INTEGER
  current_ip            INET[]
  current_cert_sha256   TEXT
  category              TEXT[]         -- e.g. {finance, login, ecommerce}
  brand_match           TEXT NULL      -- matched brand if any
  brand_canonical       BOOL           -- is it a real brand domain?
  reputation_score      REAL           -- 0..1 rolling
  verdict               TEXT           -- clean | suspicious | malicious | unknown
  verdict_confidence    REAL
  last_scanned_at       TIMESTAMP
  next_rescan_at        TIMESTAMP
  flags                 TEXT[]         -- {nrd, dga, homoglyph, fastflux, ...}

Table: urls
  url_hash              BYTEA PRIMARY KEY  -- SHA256 of normalized URL
  url                   TEXT
  domain                TEXT REFERENCES domains(domain)
  first_seen            TIMESTAMP
  last_seen             TIMESTAMP
  redirect_chain        TEXT[]
  final_url             TEXT
  verdict               TEXT
  verdict_confidence    REAL
  evidence_id           UUID
  last_scanned_at       TIMESTAMP

Table: scan_history          -- append-only, full audit trail
  id                    UUID PRIMARY KEY
  url_hash              BYTEA
  scanned_at            TIMESTAMP
  l2_score              REAL
  l3_evidence_id        UUID
  l4_visual_top_brand   TEXT
  l4_visual_score       REAL
  l5_behavior_flags     TEXT[]
  l6_final_score        REAL
  verdict               TEXT
  reasoner_explanation  TEXT
  external_verdicts     JSONB        -- {gsb: clean, vt: 3/70, urlscan: malicious}

Table: evidence
  evidence_id           UUID PRIMARY KEY
  screenshot_path       TEXT
  dom_path              TEXT
  har_path              TEXT
  pcap_path             TEXT
  js_analysis_path      TEXT
  retention_until       TIMESTAMP

Table: brand_registry
  brand_id              UUID PRIMARY KEY
  brand_name            TEXT
  canonical_domains     TEXT[]
  legitimate_asns       INTEGER[]
  legitimate_issuers    TEXT[]
  screenshot_vectors    VECTOR(512)[]
  favicon_hashes        TEXT[]
  logo_embeddings       VECTOR(512)[]
  brand_keywords        TEXT[]
  spf_dmarc_dkim        JSONB
  app_bundle_ids        TEXT[]

Table: file_registry
  sha256                BYTEA PRIMARY KEY
  first_seen            TIMESTAMP
  signer                TEXT
  signer_valid          BOOL
  av_verdicts           JSONB
  yara_hits             TEXT[]
  sandbox_verdict       TEXT
  reputation_score      REAL

Table: infra_graph         -- node + edge data for guilt-by-association
  node_id               TEXT
  node_type             TEXT      -- domain | ip | asn | cert | registrant | ns
  attributes            JSONB

Table: infra_edges
  src_node              TEXT
  dst_node              TEXT
  edge_type             TEXT
  observed_at           TIMESTAMP
```

### 15.2 Verdict Lifecycle

Each domain transitions through states:

```
   unknown ──► scanning ──► clean ─┐
       │            │              │
       ▼            ▼              ▼
   suspicious ──► malicious     re-scan loop
       │            │              │
       └────────────┴──────────────┘
                    │
                    ▼
                 dormant
```

- **Re-scan cadence by verdict**:
  - clean (Tranco top 10k): every 7 days
  - clean (other): every 24 h
  - suspicious: every 6 h
  - malicious: every 24 h (to detect cleanup/sinkholing)
  - dormant (no traffic 90 d): every 30 d

- **State change triggers**:
  - CT log: new cert → immediate re-scan
  - WHOIS change → immediate re-scan
  - IP / ASN change → re-scan
  - User report → priority queue
  - Sibling-domain becomes malicious → re-evaluate
  - Drift from baseline DOM/JS hash → re-scan

### 15.3 Keeping the Database Clean & Trustworthy

- **Verdict TTL** — verdicts older than their cadence are stale; treated as `unknown` until re-scanned.
- **Confidence decay** — confidence drops linearly with time-since-scan.
- **Multi-source corroboration** — a verdict becomes "high confidence" only when internal score + ≥2 external scanners agree.
- **False-positive feedback** — analyst-confirmed FPs added to a separate `false_positive_history` table; model features include "ever-FP'd" so the system is biased toward not re-flagging.
- **False-negative recapture** — when a site that was previously "clean" turns malicious, all users who visited in the past N hours get notified (post-hoc warning) and endpoint agent reviews their session.
- **GDPR retention policy** — evidence purged on configurable schedule; verdict metadata retained longer (no PII).
- **Cryptographic verdict signing** — every verdict signed by the engine that produced it; the registry is auditable.

### 15.4 Why a Persistent Registry Matters

- Massive speedup — most queries become cache hits.
- Historical context — "this domain was clean for 3 years, suddenly malicious yesterday" is itself a signal (compromise).
- Graph mining — find new bad sites by their relationship to known bad sites.
- Continuous training data — every labeled row feeds the ML pipeline.
- Sharing/federation — registry slices can be exchanged with partners under signed verdicts.

---

## 16. Strategic Implications

1. **Don't compete on DNS resolver scale** — use anycast hosting providers or partner.
2. **Compete on the visual+identity-mismatch ML and the transparency UX** — that's the moat.
3. **Position as complementary to SASE** — sell the "anti-phishing brain" plugged into existing gateways via ICAP/API.
4. **Open-source the brand-registry schema + CT watcher** — community contribution is the only realistic path to scale brand coverage against paid-feed incumbents.
5. **Lead with transparency** — being the only product that shows users *why* something was blocked, with full evidence and an LLM explanation, is both a security feature and a trust/marketing wedge.

---

---

## 17. Master Feature Catalog (Priority-Locked)

Every feature in the system, ranked by how essential each is to stopping real attacks. Removing P0 leaves holes; removing P1 drops you below ~99%.

**Tiers**
- **P0 — Core**: without it the system fundamentally doesn't work (<90%).
- **P1 — Critical**: required for ~99% and zero-day defense.
- **P2 — Important**: pushes 99% → 99.9%; closes evasion vectors.
- **P3 — Enhancement**: coverage, UX, privacy, scale.

### 17.1 P0 — Core (17 features)

| # | Feature | Stops |
|---|---|---|
| 1 | Hardened recursive resolver (DoH + DoT only) | MITM DNS, ISP injection, plaintext sniffing |
| 2 | DNSSEC validation | Cache poisoning, off-path spoofing, forged records |
| 3 | Multi-source threat-intel blocklist ingest (PhishTank, OpenPhish, URLhaus, GSB, SmartScreen, abuse.ch, Spamhaus) | All known phishing/malware/C2 |
| 4 | Newly Registered Domain (NRD) filter | One-shot phishing, fresh malware C2 |
| 5 | Domain age / WHOIS + RDAP | Sketchy registrars, NRD-class attacks |
| 6 | TLS certificate inspection (issuer, age, SAN, OCSP) | Phishing on fresh LE certs, mis-issued certs |
| 7 | Certificate Transparency log monitoring | Zero-day phishing **before first visitor** |
| 8 | Homoglyph / Punycode / typosquat detection vs. brand registry | Lookalike attacks (`g00gle`, `pаypal`, `paypa1`) |
| 9 | Allowlist / Bloom filter for Tranco top 1M | Latency, false positives on big sites |
| 10 | Sandboxed headless render for unknown URLs | Drive-by, exploit kits, malicious JS |
| 11 | Visual brand-impersonation detection (CNN + favicon + logo CV) | Zero-day phishing lookalikes |
| 12 | Brand Protection Registry | Identity-mismatch attacks of every kind |
| 13 | Identity-mismatch fusion rule | All convincing visual phishing |
| 14 | Persistent site registry / verdict DB with TTL & re-scan | Stale verdicts, repeat attacks, drift |
| 15 | Redis cache fast path | Latency, cost, DoS via re-scan storms |
| 16 | Block-page interstitial with verdict reason | User confusion, shadow-IT bypass |
| 17 | Public-DoH bypass control (block 1.1.1.1, dns.google) | Malware/browsers bypassing the resolver |

### 17.2 P1 — Critical (23 features)

| # | Feature | Stops |
|---|---|---|
| 18 | Multi-egress fetch + cloaking diff | Cloaked phishing |
| 19 | Redirect chain resolution & forensics | Shortener chains, open-redirect abuse, JS cloaks |
| 20 | Behavioral sandbox (clipboard/cred/crypto/WebRTC/WebSocket hooks) | Credential stealers, MFA-relay, miners, exfil |
| 21 | Canary credential submission | Maps phishing infra; highest-confidence verdict |
| 22 | Form-action analysis | Credential stealing of every kind |
| 23 | Multi-AV + YARA file scanning (≥30 engines) | Known malware via any vector |
| 24 | Dynamic file detonation (CAPE/Cuckoo) | Zero-day, packed, obfuscated malware |
| 25 | Score-based chained external scanning (GSB/VT/urlscan/OTX/Talos) | Borderline scores; FP & FN reduction |
| 26 | DGA classifier | Malware C2 channels |
| 27 | DNS tunneling detector | Data exfil / covert C2 over DNS |
| 28 | JS deobfuscation + AST analysis | Skimmers (Magecart), keyloggers, exploit kit landings |
| 29 | Code-signing verification (Authenticode, Apple notarization, revocation) | Fake installers, unsigned malware |
| 30 | ASN / hosting reputation | Bulletproof hosting, abuse-friendly providers |
| 31 | DOM-tree similarity to brand fingerprints | Visually-tweaked but structurally-cloned kits |
| 32 | LLM page-understanding (multimodal) | AI-generated novel phishing pages |
| 33 | LLM reasoner over evidence bundle | FPs, opaque blocks, slow triage |
| 34 | DNS rebinding detection | Attacks on internal/RFC1918 networks |
| 35 | Subdomain takeover detection (dangling CNAME) | Hijack of trusted subdomains |
| 36 | Bit-flip (bitsquatting) check | RAM-error exploitation, edge typo variants |
| 37 | Per-URL evidence storage + Transparency Portal | Distrust, audit failure, slow analyst work |
| 38 | Continuous model retraining + feedback loop | Drift, novel kits |
| 39 | Passive DNS history (Farsight / SecurityTrails) | Fast-flux, churn, infra pivoting |
| 40 | Email URL rewriting + time-of-click scan | Email-borne phishing (the #1 delivery vector) |

**P0 + P1 (40 features) = ~99% accuracy across phishing, malware, credential-stealing, fraud.**

### 17.3 P2 — Important (pushes to 99.9%+)

| # | Feature |
|---|---|
| 41 | Geo-rotated fetch (3+ regions) |
| 42 | Time-delayed re-scan (+1h/+6h/+24h) |
| 43 | Wayback / Common Crawl historical diff |
| 44 | WHOIS history |
| 45 | Related-domain pivot via ASN/registrant/TLS-fingerprint |
| 46 | Infrastructure graph (GNN over domain/IP/ASN/cert/NS) |
| 47 | BGP hijack monitoring (RIPE RIS) |
| 48 | DOM/JS hash drift on known-good sites |
| 49 | Subresource Integrity verification |
| 50 | Third-party script provenance |
| 51 | Iframe origin analysis |
| 52 | Tor / dark-web phishing-kit monitoring |
| 53 | Honeypots (bait emails harvesting URLs) |
| 54 | QR-code OCR + URL pipeline (quishing) |
| 55 | SMS / messenger / Slack/Teams URL API (smishing) |
| 56 | OAuth consent-screen abuse detection |
| 57 | Browser-in-the-browser (BITB) detector |
| 58 | Anti-analysis detection (mouse sim, devtools-closed, delay) |
| 59 | Push-notification permission abuse detection |
| 60 | Macro / LOLBin scan for Office/PDF |
| 61 | PE entropy + packer detection |
| 62 | Per-user risk score |
| 63 | Honeytoken / canary creds seeded to endpoints |
| 64 | Browser autofill protection on unverified pages |
| 65 | Just-in-time MFA prompts on low-confidence pages |
| 66 | False-positive feedback table + analyst loop |
| 67 | Post-hoc notification on "clean → malicious" flip |
| 68 | Endpoint post-click forensics (process tree, file writes) |
| 69 | Endpoint rollback via VSS / APFS snapshots |
| 70 | Tracker / fingerprint blocklist (EasyPrivacy, DDG Tracker Radar) |
| 71 | Third-party cookie + storage partitioning enforcement |
| 72 | Browser fingerprint randomization in extension |
| 73 | CNAME-cloaking tracker detection |
| 74 | Active disruption (automated takedown notices) |
| 75 | Federated / decentralized intel sharing between deployments |

**P0 + P1 + P2 ≈ 99.9%.** Tracking protection (#70–73) addresses the "no surveillance / no tracking" goal.

### 17.4 P3 — Enhancement

| # | Feature |
|---|---|
| 76 | Oblivious DoH (ODoH) |
| 77 | OPRF / blinded URL lookups |
| 78 | Browser isolation fallback (remote pixel stream) |
| 79 | Mobile VPN profile (iOS/Android) |
| 80 | Endpoint agent for non-browser processes |
| 81 | TestFlight / sideload mobile-app fingerprinting |
| 82 | In-app browser detection on mobile |
| 83 | Per-tenant policy engine (OPA/Rego) |
| 84 | Cryptographically signed verdicts (auditable trail) |
| 85 | GDPR-aware retention on evidence |
| 86 | SIEM integration |
| 87 | ICAP/API integration into existing SASE/SWG |
| 88 | LLM red-team adversary generating synthetic phish |
| 89 | Autoencoder anomaly detection on page features |
| 90 | Reputation API for SaaS partners |
| 91 | Anycast multi-region resolver |
| 92 | DDoS protection on resolver |
| 93 | "Report phishing" user button → analyst queue |
| 94 | Analyst workbench UI |
| 95 | Compliance dashboards |

### 17.5 Disproportionately Powerful — Do Not Cut

1. **#7 CT log monitoring** — flags phishing infra before the first victim.
2. **#11 + #12 Visual brand match + Brand Registry** — catches zero-day lookalikes.
3. **#13 Identity-mismatch fusion** — the verdict rule that makes #11 actionable.
4. **#18 Multi-egress cloaking diff** — defeats cloaking, which defeats every other layer.
5. **#20 + #21 Behavioral sandbox + canary creds** — highest-confidence phishing verdict possible.
6. **#32 + #33 LLM page-understanding + reasoner** — the only durable defense against attacker AI.
7. **#14 Persistent registry with TTL** — without long-term memory the system relearns daily.

---

## 18. Threat → Feature Coverage Map

| Threat Class | Primary Features | Supporting |
|---|---|---|
| Known phishing | 3, 4, 5, 9, 14 | 25, 39 |
| Zero-day phishing (lookalikes) | **7, 8, 10, 11, 12, 13, 19, 21, 22, 31, 32** | 18, 30, 41–46, 57 |
| AI-generated phishing | **11, 12, 13, 32, 33** | 88, 89 |
| Credential stealing | 11, 13, 20, 21, 22, 63 | 64, 65 |
| OAuth / consent phishing | 22, 56 | 57 |
| MFA-relay (Evilginx) | 20, 21, 22 | 65 |
| Known malware | 23, 24, 29 | 25, 60, 61 |
| Zero-day malware | 20, 24, 28, 60, 61 | 68, 69 |
| Drive-by exploits | 10, 20, 28 | 78 |
| Cryptojacking | 20, 28 | – |
| Malvertising | 10, 20, 51 | 78 |
| Watering-hole / compromised legit site | 48, 49, 50 | 24, 28 |
| Supply-chain JS / CDN compromise | 48, 49, 50, 52 | – |
| HTML smuggling | 24, 28 | 23 |
| ClickFix paste-to-run | 20, 32, 33 | 68 |
| DNS spoofing / poisoning | 1, 2 | – |
| DNS hijacking / rogue resolver | 1, 2, 17 | 76 |
| DNS rebinding | 34 | 20 |
| DNS tunneling / C2 exfil | 27 | 26 |
| DGA C2 | 26 | 30, 39 |
| Fast-flux / domain-flux | 26, 30, 39, 45 | 46 |
| NRD-class attacks | 4, 5, 6, 7 | – |
| Typosquatting | 8 | 36 |
| Homograph / IDN | 8 | – |
| Combosquatting | 8 | – |
| Bitsquatting | 36 | 8 |
| BGP hijack | 47 | 30 |
| Mis-issued certs | 6, 7 | – |
| Subdomain takeover | 35 | – |
| Cloaking | 18, 41 | 58 |
| Geo-fenced payloads | 41 | 18 |
| Redirect chain abuse | 19 | – |
| Open-redirect abuse | 19 | – |
| Browser-in-the-browser (BITB) | 57 | 32, 33 |
| QR phishing (quishing) | 54 | – |
| Smishing (SMS) | 55 | – |
| Push-notification scams | 59 | – |
| Tech-support / pure scams (no brand) | 32, 33, 89 | 18 |
| Trackers / surveillance | **70, 71, 72, 73** | 76, 77 |
| Fingerprinting | 72 | 71, 73 |
| Repeat / drifted attackers | 14, 38, 45, 46 | 67 |

---

## 19. Deployment Model — DNS vs Proxy vs Hybrid (How to Use the System)

The single biggest deployment decision. Each model has hard trade-offs.

### 19.1 The Three Options

#### Option A — Pure DNS (resolver only, like Quad9/NextDNS/Umbrella)

```
User device → DoH/DoT → Your resolver → answer (NXDOMAIN or sinkhole if bad)
```

**What you can do:** Block at the domain layer. Everything in L0, parts of L1/L2.
**What you cannot do:** See URL paths, content, redirects, forms, files, page visuals. So you cannot run L3–L5 against the *actual user traffic*. You can still pre-scan domains via CT/NRD pipelines, but you decide before content is fetched.
**Strengths:** Trivial to deploy (one DNS setting), encrypts metadata, zero performance overhead, works on every device, every OS, every app.
**Weaknesses:** Path-level phishing (`legit-site.com/evil-page`) invisible. Cannot inspect file downloads. Cannot kill cloaking. Cannot do visual brand match against the page the user actually sees.
**Best 99.999% achievable:** ~92–95%.

#### Option B — Pure Proxy / SWG (like Cloudflare Gateway, Zscaler, Netskope)

```
User → Forward proxy (TLS-intercepted) → Filters → Internet
```

**What you can do:** Everything — full URL, full content, full file, redirects, behavior. Every layer L0–L5 applies inline.
**Strengths:** Maximum protection. Full visibility into what the user actually receives.
**Weaknesses:**
- Requires **TLS interception** (MITM with your CA cert installed on every device). Painful to deploy, breaks pinning (banks, mobile apps, IoT, dev tools).
- Higher latency (every byte through your infra).
- Heavyweight: needs proxy CPU + bandwidth proportional to *all user traffic*, not just metadata.
- User backlash if poorly explained (privacy concerns; "my company is seeing all my HTTPS").
**Best 99.999% achievable:** ~99.9%.

#### Option C — Hybrid (DNS as gate + on-demand proxy/render only for unknowns) ← **RECOMMENDED**

```
User device → DoH/DoT → Resolver
                          │
                          ├── Known good → answer directly (95%+ of queries)
                          ├── Known bad  → sinkhole/NXDOMAIN
                          └── Unknown    → answer with a special CNAME / lightweight
                                            interstitial that routes the user's
                                            FIRST request to the analysis proxy.
                                            After verdict, normal direct connection.
```

Plus a **lightweight browser extension** that:
- Sends URL hashes + redirect chain to the verdict API
- Renders block-page interstitial with evidence
- Reports user-clicked "report phishing"
- Enforces tracking blocklists & cookie partitioning locally

**Why this wins:** DNS handles 95%+ of traffic at near-zero cost. Proxy/sandbox is invoked only for the 1–5% of traffic that's unknown or suspicious — the only traffic that *needs* deep analysis. You get the visibility of a proxy without paying its full bandwidth/latency bill, and without forcing TLS interception on every flow.

### 19.2 Side-by-Side

| Aspect | DNS-only | Proxy/SWG | **Hybrid (recommended)** |
|---|---|---|---|
| Deployment effort | Trivial (1 DNS setting) | Heavy (root CA install on every device) | Light (DNS + optional extension) |
| TLS interception required | No | Yes | **No for most traffic; only for explicit deep-scan opt-in** |
| URL path visibility | No | Yes | Yes (via extension or selective proxy) |
| File scanning | No | Yes | Yes (via extension reporting or proxy hop) |
| Visual brand match | Only via pre-scan | Inline | **Pre-scan + inline for unknowns** |
| Cloaking defeat | Partial | Full | Full |
| Latency overhead | Negligible | 20–100 ms per request | <10 ms typical; ~1 s on first unknown |
| Resource cost | Low | High (bandwidth + CPU) | **Moderate** |
| Works on mobile / IoT / non-browser apps | Yes | Painful | Yes (DNS layer) |
| Privacy posture | Strong (no content seen) | Weak (sees all HTTPS) | Strong (content only sandboxed-fetched by us, not user traffic mirrored) |
| User acceptance | High | Low–Medium | **High** |
| Max accuracy | 92–95% | 99.9% | **99.9%** |

### 19.3 The Verdict

**Use Hybrid.**
- **DNS resolver** is the always-on gate. Every user, every device, zero install pain.
- **Browser extension** (Chrome/Firefox/Edge/Safari) is the optional power layer for users who want path-level + visual analysis + tracking protection.
- **Sandbox farm** in your cloud handles the deep analysis — never on the user's device.
- **Email/SMS/messenger APIs** cover the channels DNS can't see.
- **TLS-intercepting proxy** is offered only for enterprises that explicitly want it (corporate SWG mode).

This matches how Cloudflare 1.1.1.1, NextDNS, and Pi-hole already get adopted — but with the deep-analysis brain that those products lack.

---

## 20. Recommended Reference Architecture

### 20.1 Three Concentric Rings

```
                       ┌─────────────────────────────────────┐
                       │   RING 3 — Analysis Cloud            │
                       │   (Sandbox farm, ML models,         │
                       │   Brand Registry, Site Registry,    │
                       │   CT firehose, Intel Plane)         │
                       └──────────────────┬──────────────────┘
                                          │ verdict API (gRPC/HTTPS)
                       ┌──────────────────▼──────────────────┐
                       │   RING 2 — Edge                      │
                       │   Anycast DoH/DoT resolver           │
                       │   + URL verdict API                  │
                       │   + block-page server                │
                       └──────────────────┬──────────────────┘
                                          │  DoH/DoT  +  HTTPS API
                       ┌──────────────────▼──────────────────┐
                       │   RING 1 — Client                    │
                       │   OS DNS setting (mandatory)         │
                       │   Browser extension (optional but    │
                       │     strongly recommended)            │
                       │   Mobile VPN profile (optional)      │
                       └─────────────────────────────────────┘
```

### 20.2 Per-Ring Responsibilities

| Ring | Owns | Resource profile |
|---|---|---|
| Ring 1 — Client | DNS pointer, extension UI, block-page rendering, local tracker blocklist, fingerprint randomization, send URL hashes/redirect-chain to Ring 2 | Tiny: extension <20 MB RAM, no perceptible CPU |
| Ring 2 — Edge | Anycast resolver, fast-path cache, blocklists, NRD/DGA filter, URL verdict API entry point | Modest: each PoP = a few cores + 8–32 GB RAM for cache |
| Ring 3 — Analysis Cloud | Sandbox renders, file detonation, ML scoring, LLM reasoner, registries, training | Heavy but **only triggered for unknowns** (1–5% of traffic) |

### 20.3 Data Flow for a Single Visit

1. Browser asks for `withinearth.com` → Ring 2 resolver. Cache hit → answer in <10 ms.
2. Browser asks for `w1thineartht.com` → Ring 2 resolver. Cache miss.
3. Ring 2 runs L1+L2 inline (lexical, homoglyph, WHOIS, cert). Score crosses threshold.
4. Ring 2 returns a temporary CNAME pointing to a holding page **while** queueing Ring 3 deep scan.
5. Ring 3 spins up a Firecracker microVM, renders the page from 3 egress points, runs L3–L5, fuses, asks LLM for an explanation.
6. Verdict cached in Site Registry; pushed to Ring 2 caches; browser extension shows full interstitial.
7. Next user gets a <10 ms answer.

### 20.4 Where Each Feature Runs

- **Ring 1 (client):** #16 block-page, #19 redirect-chain reporting, #70–73 tracking, #54 QR scan, #93 report button.
- **Ring 2 (edge):** #1, #2, #3, #4, #5, #6, #7, #8, #9, #15, #17, #25, #26, #27, #36, #39, #91, #92.
- **Ring 3 (cloud):** #10, #11, #12, #13, #14, #18, #20, #21, #22, #23, #24, #28, #29, #30, #31, #32, #33, #34, #35, #37, #38, #40, plus all P2/P3 deep analysis.

---

## 21. Resource Footprint & Cost Profile

### 21.1 Client (Ring 1)
- DNS change: 0 resources.
- Browser extension: 15–30 MB RAM, <0.5% CPU sustained, negligible bandwidth (URL hashes only).
- Mobile VPN profile: ~20 MB RAM, normal battery cost of a VPN client.

### 21.2 Edge (Ring 2) — per PoP
- A small PoP (10 k req/s sustained): 4–8 vCPUs, 16–32 GB RAM, 50 GB SSD.
- Anycast across 5 regions for global coverage.
- Bandwidth dominated by DNS, which is tiny (~100 bytes per query).
- Estimated infra cost: **$300–$1,000 / PoP / month** depending on cloud provider.

### 21.3 Analysis Cloud (Ring 3)
- Cost driver: number of **unknown** URLs scanned per day, not total traffic.
- Each L3–L5 deep scan: ~5–15 s of one CPU core + ~1 GB peak RAM in a microVM.
- A 1 M-user deployment generates ~50 k–200 k deep scans/day after caching.
- Steady-state pool: ~50–200 vCPUs of sandbox capacity, autoscaling.
- ML inference (CLIP embedding, LLM reasoner): GPU pool, 4–8 mid-tier GPUs sufficient for 1 M users.
- Object storage for evidence: ~5–20 TB rolling (with 30-day retention).
- Estimated infra cost at 1 M users: **$8 k–$25 k / month**.

### 21.4 What Keeps It Lightweight
- 95%+ of queries answered from edge cache.
- Deep analysis runs *once* per unknown URL; result is shared across all users globally via Site Registry.
- Pre-scanning via CT firehose & NRD feeds means most "first-time" URLs already have verdicts.
- Sandbox VMs are single-shot and small (Firecracker boot <125 ms).

This is materially lighter than a TLS-intercepting SWG, which must process **every byte** of user traffic, not just unknowns.

---

## 22. User Acceptance & Onboarding

### 22.1 Why Users Accept It

| Concern | Mitigation |
|---|---|
| "Will it slow my internet?" | DNS-only mode has zero perceptible latency. Cache hits <10 ms. |
| "Will you see all my traffic?" | No. Default is DNS + URL hash. Page content is fetched **independently** by your sandbox, not mirrored from user traffic. ODoH option for full privacy. |
| "Will it break sites?" | Allowlist for Tranco top 1M + fail-open for known-good. Visible "Report false positive" button. |
| "Why was this blocked?" | Transparency portal with screenshot, evidence, LLM explanation — unique to this product. |
| "Do I need IT skills?" | One DNS change in OS or router. Browser extension is one-click install. |

### 22.2 Onboarding Paths

**Consumer (individual user):**
1. Set DoH endpoint in OS/browser: `https://dns.yoursys.io/dns-query` (one setting).
2. Optionally install browser extension for path-level + tracker protection.
3. Optionally install mobile VPN profile for on-the-go protection.

**Family / small business:**
1. Set DoH on the home router → protects every device including IoT.
2. Plus per-device extensions for path-level protection.

**Enterprise:**
1. Point corporate DNS forwarder at your anycast resolver.
2. Deploy browser extension via MDM/Group Policy.
3. Optionally enable SWG mode (TLS interception) for managed devices.
4. Email gateway integration via SMTP/API.
5. SIEM hook for alerts.

### 22.3 What the User Sees in Normal Use
- Nothing 99% of the time. Sites load normally.
- On block: full-screen interstitial with screenshot of the malicious page, plain-language reason, "go back" + "report false positive" buttons, expandable evidence drawer.
- On warn (medium-risk): yellow banner at top of page with "Verify this site" prompt.
- On unknown-suspicious (deep scan in progress): brief "Verifying safety…" interstitial for up to ~3 s.

### 22.4 Trust Posture
- Publish quarterly transparency report: blocks per category, FP rate, FN rate, retention policies.
- Open-source the client extension and a reference resolver config.
- Independent audits of the verdict pipeline.
- Cryptographically signed verdicts users can verify.

---

---

## 23. Proxy Variants Deep-Dive (Cloudflare-Style Model)

### 23.1 What a Proxy Actually Is
A proxy sits between the user and the internet. Every HTTP(S) request flows through it. The proxy inspects the request/response, decides allow/block/scan, then forwards or denies.

DNS sees: "user asked for `example.com` IP".
Proxy sees: "user is fetching `https://example.com/login?token=abc`, here's the full HTML, here is the file being downloaded."

### 23.2 Three Architectural Variants

**Variant B1 — Cloud Forward Proxy (Cloudflare WARP / Zscaler ZIA model)**
```
User device ──► YOUR cloud proxy ──► Internet
              (encrypted tunnel)     (TLS to real site)
```
- Client app on device tunnels all traffic to your cloud (WireGuard / IPsec / PAC).
- Real site sees your proxy's IP, not the user's.
- This is the user-protection product Cloudflare One.

**Variant B2 — On-Device / On-Router Proxy**
```
Device ──► localhost proxy ──► Internet
       (Pi-hole / mitmproxy / Squid on router or PC)
```

**Variant B3 — Reverse Proxy (Cloudflare CDN/WAF)**
- Protects website owners, not visitors. NOT applicable here — phishing sites won't put themselves behind your edge.

### 23.3 TLS Interception (MITM) — The Critical Mechanism
99%+ of traffic is HTTPS. A proxy cannot read it without **TLS interception**:

1. Generate a private root CA ("YourSys Root CA").
2. Install this CA on every protected device (Win, macOS, iOS, Android, Linux, Firefox separately, Java/Python/Go separately).
3. Proxy mints fake per-domain certs signed by YourSys CA on the fly.
4. Browser trusts the fake cert because OS trusts the CA → proxy reads everything.

**What it breaks:** Cert-pinned apps (banking, Slack, Teams, Dropbox), HSTS-strict sites, mobile payment apps, dev tools, IoT, anything that ships its own CA store. Enterprise-only in practice.

### 23.4 "Copy of Cloudflare WARP" Component Breakdown
| Component | Effort |
|---|---|
| Native client (Win/Mac/Linux) — WireGuard tunnel + CA installer + tray UI | 2–3 months |
| Mobile client (iOS NetworkExtension / Android VpnService) | 2–3 months |
| WireGuard concentrators at edge PoPs | 2–4 weeks per PoP |
| TLS-intercepting proxy (Envoy + custom CA, or mitmproxy-based) | 1–2 months |
| Anycast IP plan (BGP / ASN / Equinix) | Ongoing infra |
| DNS resolver at edge (Knot/Unbound) | 1 month |
| Verdict API + Redis cache | 1–2 months |
| Analysis cloud (Ring 3 — sandbox farm) | 3–4 months |
| Account / billing / device enrollment | 2–3 months |
| Admin dashboard | 1–2 months |
| Block-page + transparency portal | 2–4 weeks |
| **MVP total** | **~12–18 engineer-months** |

What Cloudflare has that you can't quickly copy: 300+ city anycast, decade of stack optimization, CDN-subsidized free tier. **But the differentiation is the brain (visual brand match + identity mismatch + LLM), not the proxy plumbing.**

### 23.5 The Browser-Extension Insight (Why It's the Sweet Spot)
A browser extension sees everything the user's browser sees, **after TLS decryption**, **without** needing a root CA, **without** tunneling traffic, **without** breaking pinned apps.

| Capability | DoH/DNS only | Browser extension | Cloud forward proxy (WARP) |
|---|---|---|---|
| Sees URL path | No | Yes | Yes |
| Sees rendered DOM | No | Yes | Yes |
| Sees form submissions | No | Yes | Yes |
| Sees download URLs | No | Yes | Yes |
| Sees file contents | No | Partially | Yes |
| Sees non-browser app traffic | No | No | Yes |
| Requires CA install | No | No | Yes |
| Tunnels user traffic | No | No | Yes |
| Breaks pinned apps | No | No | Some |
| User effort | 1 setting | 1-click install | App install + CA trust |

**Recommendation:** DoH resolver + browser extension covers ~95% of phishing/malware (browser-delivered) with zero CA pain. Native VPN client is only added later for non-browser coverage.

### 23.6 Comparison Against Cloudflare One
| Aspect | Cloudflare One | This system (Hybrid) |
|---|---|---|
| Onboarding | Install WARP + sign in | Set DoH or install extension |
| TLS interception | Yes (CA installed) | No (extension reads post-TLS in browser) |
| Non-browser app coverage | Yes | Optional native client |
| Phishing brain | Reputation + Area 1 (email) | Visual brand match + identity mismatch + LLM |
| Transparency | Minimal block page | Full evidence portal + LLM explanation |
| Mobile | WARP app | DoH profile, optional VPN |
| Device resource cost | Always-on tunnel client | 20 MB extension, optional |
| Apps broken | Some pinned apps | None |
| Cost to build | $$$$ (global anycast) | $$ (DoH + extension + analysis cloud) |
| User trust posture | "We see all your HTTPS" | "Only URL hashes + your own browser DOM" |

---

## 24. POC Plan — Minimal Client, Maximum Demo Value

Goal: a public-demoable proof of concept that visibly catches a zero-day lookalike phishing site (e.g., `w1thineartht.com` impersonating `withinearth.com`), with the smallest possible client-side footprint.

### 24.1 POC Scope (What's IN)
The bare minimum to demonstrate the **identity-mismatch + visual brand match** advantage that no current product offers.

| POC Component | P0/P1 Mapping | Why in POC |
|---|---|---|
| Public DoH/DoT resolver endpoint | #1, #2 | Zero-install user onboarding |
| Aggregated blocklist ingest (PhishTank + OpenPhish + URLhaus) | #3 | Baseline — catches knowns |
| NRD filter (block domains <24h) | #4 | Single biggest signal, trivial to add |
| WHOIS/RDAP age check | #5 | Cheap, supports verdict |
| TLS cert age + issuer check | #6 | Cheap, supports verdict |
| Homoglyph + Levenshtein vs. mini brand list (50 brands) | #8 | The "lookalike" hook |
| Tranco top 1M allowlist (Bloom) | #9 | No false positives on big sites |
| Headless render in sandbox (Playwright in Docker) | #10 | Required to demo visual layer |
| Screenshot CNN embedding (CLIP) + favicon hash vs. 50-brand registry | #11, #12 | **The wow moment** |
| Identity-mismatch rule (visual match + non-canonical domain + young age) | #13 | The verdict that shocks demo viewers |
| Form-action analysis (creds POST to different origin) | #22 | Easy add, strong signal |
| Verdict cache + small Postgres registry | #14, #15 | Memory + reproducibility |
| Transparency Portal (single web page per verdict) | #37 | **The demo deliverable** |
| Optional: tiny browser extension (just sends URL + shows block page) | – | Adds path-level demo, but optional |

### 24.2 POC Scope (What's OUT — defer to v2)
- Multi-egress cloaking diff
- Behavioral sandbox + canary creds
- LLM reasoner (use a static template instead)
- File scanning / detonation
- DGA / tunneling / rebinding detection
- Mobile clients, native apps, enterprise modes
- TLS interception of any kind
- Global anycast — single region is fine
- Email gateway, SMS, messenger integrations
- Federation, active disruption, full intel plane

### 24.3 POC Architecture (One Diagram, Stripped Down)

```
              ┌─────────────────────────────────┐
              │  USER (zero install)             │
              │  - Sets DoH endpoint in browser  │
              │    OR clicks "Check this URL"    │
              │    on a public webpage           │
              └──────────────┬──────────────────┘
                             │
                             ▼
              ┌─────────────────────────────────┐
              │  POC API (single VM or 2-3 VMs) │
              │  - DoH endpoint (CoreDNS/Knot)  │
              │  - URL check HTTP API           │
              │  - Verdict cache (Redis)        │
              │  - Postgres (site registry)     │
              └──────────────┬──────────────────┘
                             │ unknown
                             ▼
              ┌─────────────────────────────────┐
              │  ANALYSIS WORKER (1 GPU box)    │
              │  - Playwright headless render   │
              │  - WHOIS/RDAP, cert fetch       │
              │  - CLIP embedding via OpenCLIP  │
              │  - Favicon pHash                │
              │  - Form-action parser           │
              │  - Verdict fusion (rules + LR)  │
              └──────────────┬──────────────────┘
                             │
                             ▼
              ┌─────────────────────────────────┐
              │  TRANSPARENCY PORTAL (static    │
              │  Next.js + S3 evidence bucket)  │
              │  Public URL: report.yoursys.io  │
              │  /report/<verdict-id>           │
              └─────────────────────────────────┘
```

### 24.4 POC Tech Stack (Cheap, Open-Source)

| Layer | Tech |
|---|---|
| DNS resolver | CoreDNS or Knot Resolver with a custom plugin/Lua hook |
| API | FastAPI (Python) or Fastify (Node) |
| Cache | Redis |
| Registry DB | Postgres + pgvector (for CLIP embeddings) |
| Headless render | Playwright in a Docker container |
| Screenshot embedding | OpenCLIP (`ViT-B/32`) — CPU works, GPU faster |
| Favicon hash | `imagehash` (Python) |
| WHOIS | `python-whois` + RDAP HTTP calls |
| Cert check | OpenSSL / `cryptography` lib |
| Transparency portal | Next.js static + Vercel/Cloudflare Pages |
| Evidence storage | Cloudflare R2 or AWS S3 |
| Optional extension | MV3 Chrome extension, ~100 lines of JS |
| Hosting | 1 small VPS for API (4 vCPU / 8 GB), 1 GPU box optional (or CPU works) |

**POC infra cost: ~$50–150/month.**

### 24.5 Client-Side Options (Pick the Leanest)

In order from leanest to most invasive — POC should pick **Option 1 + Option 2**:

| Option | What user does | Effort | Demo strength |
|---|---|---|---|
| **1. Public "Check this URL" portal** | Paste URL, get verdict + evidence | 0 install | Best for press / Twitter / HN demos |
| **2. Public DoH endpoint** | Set one DNS-over-HTTPS URL in browser/OS | 30-sec setting | Live in-browser blocking demo |
| 3. Tiny browser extension (optional v1.1) | One-click install | 1 minute | Shows interstitial on real navigation |
| 4. Native client / VPN | Skip for POC | – | Out of POC scope |

Option 1 gets you a viral demoable artifact (like urlscan.io but with **visual brand match + identity mismatch**). Option 2 gives you the "I set my DNS to this and watched it block a real phishing site live" tweet/video.

### 24.6 The Demo Script

This is the moment you show the world the product matters. Step-by-step:

1. Open the Transparency Portal in a browser.
2. Paste a real, live, never-before-seen phishing URL (use a today's-PhishTank entry that impersonates a popular brand — domain registered yesterday).
3. Live results appear in ~3 seconds:
   - Screenshot of the phishing page (rendered in sandbox, not user's browser).
   - "Visual similarity to **paypal.com**: 0.96"
   - "Domain age: 23 hours"
   - "Cert: Let's Encrypt, issued 6 hours ago"
   - "Domain not in PayPal canonical domain list"
   - "Login form posts credentials to: `evil-collect.tk/api`"
   - Verdict: **PHISHING (0.98 confidence)**
   - Plain-English explanation paragraph.
4. Click a button to compare side-by-side: real paypal.com screenshot vs. phishing screenshot — visually indistinguishable.
5. Run the same URL through Google Safe Browsing / VirusTotal live — show they **still say clean** because it's <24 hours old.

That side-by-side is the entire pitch.

### 24.7 POC Build Sequence — 8 Weeks

| Week | Deliverable |
|---|---|
| 1 | Spin up VPS, CoreDNS with blocklist plugin (PhishTank + OpenPhish + URLhaus), Redis cache. Working DoH endpoint. |
| 2 | URL check HTTP API skeleton; WHOIS/RDAP/cert/NRD/Tranco-allowlist features; rule-based verdict; Postgres registry. |
| 3 | Playwright headless render service in Docker; screenshot + DOM + favicon + form-action extraction. |
| 4 | Build mini Brand Registry: scrape 50 most-impersonated brands' login pages → CLIP embeddings → pgvector. |
| 5 | Wire visual similarity + favicon hash into verdict fusion. Tune thresholds on PhishTank labeled set. |
| 6 | Transparency Portal (Next.js): paste-URL form, verdict page, evidence display, side-by-side comparison. |
| 7 | Optional: tiny Chrome MV3 extension that sends URLs to API and shows interstitial. CT-log monitor side-process to pre-scan freshly-issued certs matching the 50 brands. |
| 8 | Hardening, rate limiting, public launch on HN / Product Hunt / X. Capture metrics. |

### 24.8 Success Metrics for POC
- Catches ≥50% of last 100 PhishTank submissions while they are still <24 h old.
- Catches ≥10 phishing URLs that GSB + SmartScreen + VirusTotal **all** say clean at scan time.
- Median verdict time <5 s for unknown URLs, <100 ms for cached.
- Public Transparency Portal handles 1000 URL submissions/day on a single $40/month VPS.
- One side-by-side demo video that visibly shows the lookalike attack being blocked.

### 24.9 What the POC Proves
- The **visual + identity-mismatch** approach is technically real and demoable.
- It catches what blocklist-based incumbents miss.
- It can run lean (one VPS, one GPU optional).
- Zero-install user onboarding works via DoH.
- The Transparency Portal is itself a viral artifact — every blocked URL becomes a shareable evidence page.

### 24.10 What the POC Does NOT Prove (and That's OK)
- Mass scale (defer to v2 with anycast PoPs).
- Coverage of every threat class (defer to P1 features in v2).
- Enterprise SWG integration (defer to v3).
- Mobile and non-browser coverage (defer to v2 with optional client).

### 24.11 Post-POC Roadmap (Brief)
- **v1.0 (after POC)**: Add behavioral sandbox + canary creds + multi-egress cloaking diff + LLM reasoner. Expand brand registry to top 1000 brands via CT-driven auto-population.
- **v1.5**: Browser extension full release, mobile DoH profile, anycast across 3 regions.
- **v2.0**: Optional native VPN client, email gateway integration, federated intel sharing.
- **v3.0**: Enterprise SWG mode with TLS interception via MDM, partner API, SIEM hooks.

---

---

## 25. Effort Estimation — Every Deployment Variant

Engineer-months for one full-time experienced engineer. Team of 3 → multiply by ~0.6 for parallelizable work.

### 25.1 Backend (Shared)

| Component | Build | Maint/mo |
|---|---|---|
| DoH/DoT resolver + custom plugins | 1.0 | 0.2 |
| Blocklist ingest pipeline | 0.5 | 0.1 |
| NRD + WHOIS/RDAP + cert checker | 0.5 | 0.1 |
| CT log firehose + brand-match alerter | 0.75 | 0.15 |
| Homoglyph + typosquat detector | 0.5 | 0.05 |
| URL Verdict API (gRPC + Redis cache) | 1.0 | 0.2 |
| Site Registry DB + lifecycle scheduler | 1.5 | 0.3 |
| Brand Protection Registry seeder | 1.0 | 0.5 |
| Headless render service | 1.5 | 0.3 |
| Multi-egress fetch + cloaking diff | 1.5 | 0.4 |
| Visual similarity engine (CLIP + pgvector) | 1.5 | 0.3 |
| DOM similarity + favicon + logo CV | 1.0 | 0.2 |
| Behavioral sandbox + canary creds | 2.5 | 0.5 |
| File scanning + CAPE detonation | 2.0 | 0.5 |
| DGA / DNS tunneling ML | 1.0 | 0.2 |
| Fusion model + LLM reasoner | 1.5 | 0.3 |
| Policy engine (OPA) | 0.5 | 0.1 |
| Evidence store | 0.5 | 0.05 |
| Transparency Portal | 1.5 | 0.2 |
| Continuous training pipeline | 2.0 | 0.5 |
| Observability + SIEM | 0.75 | 0.15 |
| Account / auth / billing | 2.0 | 0.5 |
| Admin dashboard | 1.5 | 0.3 |
| **Full v1 backend** | **~28** | **~5.5** |
| **POC backend (subset)** | **~5–6** | **~1** |

### 25.2 Client Variants

| Variant | Build | Maint/mo |
|---|---|---|
| **A. Public DoH endpoint only** | 1.25 | 0.2 |
| **B. Browser extension (Chrome + FF + Edge + Safari)** | 5.5 | 0.5 |
| Browser extension (Chrome-only POC) | 1.5 | 0.2 |
| **C. Native desktop app (no MITM) — Win + macOS + Linux** | 8.5 | 1.6 |
| Native desktop app (Win + macOS only) | 6.5 | 1.2 |
| **D. Full TLS-intercepting cloud proxy (WARP clone, all platforms)** | 30 | 6+ |
| Full proxy (Win + macOS desktop only) | 16–18 | 3 |
| **E. Mobile DoH/DoT profile only** | 0.5 | 0.05 |
| Mobile native app w/ on-device DNS proxy | 3.75 | 0.7 |
| **F. Router / Pi-hole-style appliance (software)** | 2.25 | 0.3 |

### 25.3 Shapes — Pick One

| Shape | Backend | Client | Total | Calendar (team of 3) |
|---|---|---|---|---|
| 1. DNS-only public service | 5–6 | 1.25 | **~7** | ~3 mo |
| 2. **Hybrid (DoH + extension)** — recommended POC | 5–6 | 2.75 | **~9** | ~3.5 mo |
| 3. Hybrid v1 (full P0+P1 backend + ext + mobile DoH) | 22 | 3.25 | **~25** | ~9 mo |
| 4. Shape 3 + native desktop (no MITM, Win+Mac) | 22 | 9.75 | **~32** | ~12 mo |
| 5. **Full Cloudflare WARP clone** | 26 | 36 | **~62** | ~20 mo |

### 25.4 Trust / Adoption Friction by Variant

| Variant | User action | Friction | Trust ask | Mass adoption |
|---|---|---|---|---|
| DoH endpoint | Change 1 setting | Very low | Low | Tech-aware; mass-market needs guided installer |
| DoH config profile (iOS/Android) | Tap to install profile | Very low | Low | Easy via QR code |
| Browser extension | 1-click install | Low | Medium | Mass-market friendly |
| Native desktop app (no MITM) | Installer + admin prompt | Medium | Medium | Mainstream; ~10–20% of DNS users convert |
| TLS-MITM client (WARP-style) | Installer + CA install + "we see your HTTPS" | High | High | Enterprise via MDM; hard consumer sell |
| Router-level | Replace/config router | High | Medium | Hobbyist + SMB only |

### 25.5 Maintenance Reality

| Shape | Ongoing engineers |
|---|---|
| DNS-only | ~0.7 |
| Hybrid (DoH + extension) | ~1.5 |
| Hybrid + native desktop | ~2.5 |
| Full WARP clone | ~5–7 (pinned-app maintenance is ~1 FTE alone) |

Plus 1–2 person ML / threat-intel team regardless of shape.

---

## 26. Endpoint Client (AV-Class) — Windows + Linux Full Traffic Visibility

How Kaspersky / Bitdefender / ESET / Norton see "all traffic". Same architecture, modernized with your cloud brain.

### 26.1 The Six Visibility Mechanisms

| # | Mechanism | Sees | OS |
|---|---|---|---|
| 1 | Local DNS interception | Every domain lookup from every app | All |
| 2 | Network filter driver | Every TCP/UDP packet + source PID | Win (WFP), Linux (nf/eBPF), macOS (NE) |
| 3 | Local HTTPS-intercepting proxy with **per-install** CA | Full URL + headers + body for HTTPS | All |
| 4 | Browser extension companion | Browser DOM context | Browsers |
| 5 | File-system filter | Every file write/read; quarantine before exec | Win (minifilter), Linux (fanotify) |
| 6 | Process / behavior monitor (ETW / eBPF) | Process spawn, DLL load, registry, sockets | All |

Real AV products use **all six together**, correlated by PID.

### 26.2 Local TLS Interception (Why It's Trust-Friendly)
- CA generated **on the user's machine**, private key **never leaves**.
- Decryption happens locally — your servers never see plaintext HTTPS.
- Trust posture is dramatically better than cloud SWG MITM.
- This is why AV products install on hundreds of millions of consumer machines while Zscaler does not.

### 26.3 Endpoint Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ USER MACHINE — YourSys Endpoint Client                        │
│  KERNEL LAYER                                                 │
│   • Network filter (WFP / eBPF)                               │
│   • File-system filter (minifilter / fanotify)                │
│   • Process+behavior monitor (ETW / eBPF)                     │
│   • DNS hook → DoH client to your cloud                       │
│  USER-SPACE SERVICE                                           │
│   • Local HTTPS-intercepting proxy (per-install CA)           │
│   • Pinned-app bypass list                                    │
│   • Local verdict engine (cache + cloud API)                  │
│   • Quarantine + VSS rollback                                 │
│   • Updater + telemetry + tray UI                             │
└─────────────────────────┬────────────────────────────────────┘
                          │ HTTPS
                          ▼
                ┌──────────────────────┐
                │ YOUR ANALYSIS CLOUD  │
                │ (Ring 3 brain)       │
                └──────────────────────┘
```

### 26.4 Build Effort

| Component | Effort |
|---|---|
| **Windows endpoint** (WFP driver + minifilter + ETW consumer + local proxy + CA installer + DNS hook + service + UI + updater) | **~12 mo** |
| **Linux endpoint** (eBPF + nftables + fanotify + local proxy + CA into multiple trust stores + DoH client + daemon + multi-distro packaging) | **~9 mo** |
| Shared cross-platform core (Rust/Go) | 2 mo |
| **TOTAL Win + Linux endpoint** | **~23 mo** |
| Combined with POC backend | ~28 mo |
| Combined with v1 full backend | ~45 mo |

### 26.5 Hard Parts To Plan For
- **EV code-signing cert** (~$300–$600/yr); Windows WHQL/attestation submission per driver build.
- **Pinned apps will break** without bypass list — banks, Slack, Teams, Dropbox, iCloud, Signal, WhatsApp, all dev tools. Permanent ~1 FTE of maintenance.
- **AV conflicts** — Defender / Norton / Kaspersky coexistence; register as Defender ATP partner.
- **Kernel BSOD risk** — staged rollouts, fast rollback, crash telemetry are mandatory.
- **SmartScreen reputation** — fresh installers get blocked; takes months of clean downloads.
- **Trust friction** — UAC prompt + kernel driver warning + CA install warning + "we see all HTTPS" privacy ask.
- **Resource footprint** — 150–400 MB RAM, 1–3% CPU sustained. AV-class, not extension-class.

### 26.6 Endpoint MVP (Windows-only, ~6 months)
1. DoH client + DNS hook (1 mo)
2. Local HTTPS-intercepting proxy + CA + top-50 pinned-app bypass (2 mo)
3. URL verdict call to cloud (0.5 mo)
4. File hash lookup vs. cloud + cached known-bad (1 mo)
5. ETW-based process monitor (alert-only, no kernel driver yet) (0.5 mo)
6. Tray UI + installer + updater (1 mo)
7. Skip for MVP: kernel network driver (use WinDivert userspace), minifilter (use ETW + post-write scan), behavior blocking.

### 26.7 Strategic Recommendation
**Endpoint client first is the wrong move unless enterprise-only.**

Correct sequence:
- **Stage 1 (3 mo)**: POC — DoH endpoint + Transparency Portal.
- **Stage 2 (+2 mo)**: Hybrid v1 — Chrome/Firefox extension + mobile DoH profile.
- **Stage 3 (+2 mo)**: Native desktop wrapper (no MITM — just DoH management + tray).
- **Stage 4 (+7 mo)**: AV-class Win + Linux endpoint with local MITM and behavior monitor.
- **Stage 5 (+4 mo)**: macOS, mobile native, enterprise SWG mode.

Ship Stage 1+2 to the world in 5 months; the endpoint is Stage 4, not Stage 1.

---

## 27. Concise Feature Index (Effectiveness Per Feature)

One feature per line. Format:
**#N · Tier · Name** — what it does. *Effectiveness: stops [threat class] / contribution to total accuracy.*

### Core (P0)
- **#1 · P0 · Hardened DoH/DoT resolver** — Encrypted DNS only, rejects plaintext. *Stops MITM DNS, ISP injection, sniffing. Foundation; +5–10% baseline.*
- **#2 · P0 · DNSSEC validation** — Cryptographic proof DNS answers are authentic. *Stops cache poisoning, forged records. Eliminates a whole spoofing class.*
- **#3 · P0 · Multi-source threat-intel blocklist ingest** — Aggregates PhishTank, OpenPhish, URLhaus, GSB, SmartScreen, abuse.ch, Spamhaus. *Catches 60–80% of known phishing/malware/C2 instantly.*
- **#4 · P0 · NRD filter (<24h domains)** — Blocks all freshly registered domains. *Single highest-yield signal; ~70% of phishing domains are <30 days old.*
- **#5 · P0 · WHOIS/RDAP age lookup** — Domain age & registrar reputation. *Strong lexical feature for borderline domains; raises confidence on NRD.*
- **#6 · P0 · TLS cert inspection** — Issuer, age, SAN, OCSP status. *Fresh LE cert + brand-lookalike = near-certain phishing.*
- **#7 · P0 · CT log monitoring (Certstream)** — Watches new cert issuance in real time. *Catches zero-day phishing infra **before first victim**. Disproportionately powerful.*
- **#8 · P0 · Homoglyph / Punycode / typo detection** — Edit-distance + Unicode-confusable match vs. brand registry. *Stops the entire lookalike class (g00gle, pаypal, paypa1).*
- **#9 · P0 · Tranco top 1M allowlist (Bloom)** — Skip deep scan for big known-good sites. *Eliminates false positives + cuts latency on 99% of traffic.*
- **#10 · P0 · Sandboxed headless render for unknowns** — Firecracker microVM + Playwright; user's browser is never first to load unknowns. *Stops drive-by, exploit kits, zero-day browser exploits from reaching user.*
- **#11 · P0 · Visual brand-impersonation detection** — CLIP screenshot embedding + favicon hash + logo CV vs. brand registry. *THE feature that catches zero-day visual phishing; no incumbent has it.*
- **#12 · P0 · Brand Protection Registry** — Canonical domains, ASNs, certs, screenshots, favicons, logos per brand. *The data asset that makes #11 actionable.*
- **#13 · P0 · Identity-mismatch fusion rule** — Looks like Brand X + isn't Brand X's infra → phishing. *Universal phishing verdict; covers all convincing visual phishing.*
- **#14 · P0 · Persistent Site Registry + TTL + re-scan** — Long-term verdict memory. *Speeds queries, catches drift, enables guilt-by-association.*
- **#15 · P0 · Redis fast-path cache** — Sub-50ms answers on cache hits. *Operational requirement; 95%+ of queries answered here.*
- **#16 · P0 · Block-page interstitial with reason** — Verdict + screenshot + evidence shown to user. *Prevents shadow-IT bypass; builds trust.*
- **#17 · P0 · Public-DoH bypass control** — Blocks client connections to 1.1.1.1, dns.google. *Prevents malware/browser routing around your resolver.*

### Critical (P1)
- **#18 · P1 · Multi-egress fetch + cloaking diff** — Fetch from residential + datacenter + mobile + Tor; diff responses. *Defeats cloaking; without this, every other scanner can be tricked.*
- **#19 · P1 · Redirect chain forensics** — Resolves 30x + meta-refresh + JS-driven redirects to true destination. *Stops shortener chains, open-redirect abuse on legit domains.*
- **#20 · P1 · Behavioral sandbox** — Hooks clipboard, credential autofill, crypto, WebRTC, WebSocket, Service Worker. *Catches credential stealers, MFA-relay, in-browser miners, exfil channels.*
- **#21 · P1 · Canary credential submission** — Submit fake creds to detected forms; observe POST target. *Highest-confidence phishing verdict possible; maps phishing infra.*
- **#22 · P1 · Form-action analysis** — Detects password/CC fields posting to a different origin. *Cheapest reliable credential-stealing detector.*
- **#23 · P1 · Multi-AV + YARA file scanning (≥30 engines)** — Aggregated AV verdict on every downloadable artifact. *Stops known malware via any delivery vector.*
- **#24 · P1 · Dynamic file detonation (CAPE/Cuckoo)** — Runs files in instrumented VM; observes behavior. *Stops zero-day, packed, polymorphic malware.*
- **#25 · P1 · Chained external scanning on borderline scores** — Fans out to GSB, VT, urlscan, OTX, Talos. *Reduces FP & FN in the uncertain middle.*
- **#26 · P1 · DGA classifier** — Entropy + n-gram ML on domain names. *Stops algorithmic C2 channels that blocklists can't keep up with.*
- **#27 · P1 · DNS tunneling detector** — Per-client query rate/size/entropy anomaly. *Stops covert C2 and data exfil over DNS.*
- **#28 · P1 · JS deobfuscation + AST analysis** — Unpacks and statically analyzes JavaScript. *Catches skimmers (Magecart), keyloggers, exploit-kit landings.*
- **#29 · P1 · Code-signing verification** — Authenticode + Apple notarization + revocation. *Stops fake installers and unsigned malware.*
- **#30 · P1 · ASN / hosting reputation** — Per-ASN abuse rate scoring. *Catches bulletproof hosts and abuse-friendly providers.*
- **#31 · P1 · DOM-tree similarity** — Tree edit distance vs. brand DOM fingerprints. *Catches kits even when CSS is tweaked to defeat screenshot match.*
- **#32 · P1 · LLM page-understanding (multimodal)** — "What brand is this page trying to be?" *Only durable defense against attacker-AI-generated novel phishing.*
- **#33 · P1 · LLM reasoner over evidence** — Human-readable verdict explanations. *Reduces FPs, accelerates analyst triage, drives user trust.*
- **#34 · P1 · DNS rebinding detection** — Re-resolve repeatedly; flag short-TTL flips to RFC1918. *Stops attacks against internal networks from public sites.*
- **#35 · P1 · Subdomain takeover detection** — Scans for dangling CNAMEs. *Stops hijack of trusted subdomains.*
- **#36 · P1 · Bit-flip (bitsquatting) check** — Single-bit-flip neighbor domain detection. *Stops RAM-error exploitation + edge typo variants.*
- **#37 · P1 · Per-URL evidence storage + Transparency Portal** — Every verdict has a public evidence page. *Trust differentiator; required for audit + analyst use.*
- **#38 · P1 · Continuous model retraining + feedback loop** — Nightly retrain on new labels. *Prevents accuracy decay from drift and novel kits.*
- **#39 · P1 · Passive DNS history** — Historical resolution & ownership data. *Detects fast-flux, churn, infra pivoting.*
- **#40 · P1 · Email URL rewriting + time-of-click scan** — Rewrite all email links; scan at click. *Stops email-borne phishing (the #1 delivery vector).*

### Important (P2)
- **#41 · P2 · Geo-rotated fetch (3+ regions)** — Detects geo-fenced payloads.
- **#42 · P2 · Time-delayed re-scan (+1h/+6h/+24h)** — Catches kits that "warm up" payload after initial scan.
- **#43 · P2 · Wayback / Common Crawl diff** — Detects compromised legitimate sites by historical drift.
- **#44 · P2 · WHOIS history (DomainTools)** — Registrant changes flag takeovers.
- **#45 · P2 · Related-domain pivot (ASN/registrant/TLS fingerprint)** — Guilt-by-association scoring.
- **#46 · P2 · Infrastructure graph + GNN** — Detects malicious clusters before individual nodes are flagged.
- **#47 · P2 · BGP hijack monitoring (RIPE RIS)** — Stops IP-space hijack of legitimate brands.
- **#48 · P2 · DOM/JS hash drift on known-good sites** — Detects CMS compromise.
- **#49 · P2 · Subresource Integrity verification** — Detects CDN compromise.
- **#50 · P2 · Third-party script provenance** — Detects npm/CDN supply-chain compromise.
- **#51 · P2 · Iframe origin analysis** — Stops malvertising and hidden phishing iframes.
- **#52 · P2 · Tor / dark-web phishing-kit monitoring** — Detects kits before deployment.
- **#53 · P2 · Honeypots (bait emails)** — Harvest phishing URLs for sample acquisition.
- **#54 · P2 · QR-code OCR + URL pipeline** — Stops quishing (QR phishing).
- **#55 · P2 · SMS / messenger URL API** — Stops smishing and in-app phishing.
- **#56 · P2 · OAuth consent-screen abuse detection** — Stops token-theft consent phishing.
- **#57 · P2 · Browser-in-the-browser (BITB) detector** — Stops fake popup-window phishing.
- **#58 · P2 · Anti-analysis detection** — Defeats sandbox-evading kits (mouse-sim, devtools-closed).
- **#59 · P2 · Push-notification abuse detection** — Stops browser-push scam funnels.
- **#60 · P2 · Macro / LOLBin scan (Office/PDF)** — Stops document-borne malware.
- **#61 · P2 · PE entropy + packer detection** — Flags packed/obfuscated binaries.
- **#62 · P2 · Per-user risk score** — High-click-rate users get tighter policies.
- **#63 · P2 · Honeytoken / canary creds on endpoints** — Tripwire if creds submitted anywhere.
- **#64 · P2 · Browser autofill protection on unverified pages** — Reduces credential leak surface.
- **#65 · P2 · Just-in-time MFA prompts** — Step-up auth on low-confidence-but-allowed pages.
- **#66 · P2 · False-positive feedback table + analyst loop** — Long-term FP control.
- **#67 · P2 · Post-hoc notification on clean→malicious flip** — Warns users who visited during clean window.
- **#68 · P2 · Endpoint post-click forensics** — Process tree + file writes for 60s after click; containment of successful attacks.
- **#69 · P2 · Endpoint rollback (VSS/APFS snapshots)** — Reverses malware execution.
- **#70 · P2 · Tracker / fingerprint blocklist** — Stops trackers, ad-tech surveillance, fingerprinting.
- **#71 · P2 · Third-party cookie + storage partitioning** — Stops cross-site tracking.
- **#72 · P2 · Browser fingerprint randomization** — Defeats fingerprint-based tracking.
- **#73 · P2 · CNAME-cloaking tracker detection** — Stops first-party-disguised trackers.
- **#74 · P2 · Active disruption (automated takedown notices)** — Shortens real-world dwell time of malicious sites.
- **#75 · P2 · Federated intel sharing between deployments** — Zero-day caught at one tenant blocked at all others in seconds.

### Enhancement (P3)
- **#76 · P3 · Oblivious DoH (ODoH)** — Resolver cannot link queries to users.
- **#77 · P3 · OPRF / blinded URL lookups** — Check URL safety without revealing it in clear.
- **#78 · P3 · Browser isolation fallback** — Remote pixel-stream rendering for unresolved-suspicion URLs.
- **#79 · P3 · Mobile VPN profile (iOS/Android)** — On-device DNS protection without an app.
- **#80 · P3 · Endpoint agent for non-browser processes** — Covers Slack desktop, mail clients, dev tools.
- **#81 · P3 · TestFlight / sideload mobile-app fingerprinting** — Detects rogue mobile apps.
- **#82 · P3 · In-app browser detection (mobile)** — Flags credential prompts inside in-app browsers.
- **#83 · P3 · Per-tenant policy engine (OPA/Rego)** — Custom policies per org/family/user-group.
- **#84 · P3 · Cryptographically signed verdicts** — Auditable, tamper-evident verdict trail.
- **#85 · P3 · GDPR-aware evidence retention** — Compliance with privacy law.
- **#86 · P3 · SIEM integration** — Splunk/Elastic/Chronicle pipes.
- **#87 · P3 · ICAP / API into existing SASE/SWG** — Plug brain into existing gateways.
- **#88 · P3 · LLM red-team adversary generating synthetic phish** — Self-training against attacker AI.
- **#89 · P3 · Autoencoder anomaly detection** — High reconstruction-error pages flagged.
- **#90 · P3 · Reputation API for SaaS partners** — Slack/Teams/Discord can call your verdict API on every link.
- **#91 · P3 · Anycast multi-region resolver** — Latency + DDoS resilience.
- **#92 · P3 · DDoS protection on resolver** — Keeps service up under attack.
- **#93 · P3 · User "Report phishing" button** — Crowdsourced labels feeding training.
- **#94 · P3 · Analyst workbench UI** — Triage + verdict-override interface.
- **#95 · P3 · Compliance dashboards** — Per-tenant security posture reports.

### Effectiveness Summary
- **P0 alone** → ~92–95% accuracy (signature + lookalike + visual baseline).
- **P0 + P1** → ~99% (zero-day phishing, MFA-relay, file-borne malware closed).
- **P0 + P1 + P2** → ~99.9% (evasion defeated, tracking closed, modern phishing techniques closed).
- **+ P3** → coverage breadth, privacy, scale, partner reach.

### The Seven Disproportionately Powerful Features (Do Not Cut)
1. **#7** CT log monitoring — pre-visit detection.
2. **#11 + #12** Visual brand match + Brand Registry — zero-day lookalike defense.
3. **#13** Identity-mismatch fusion — universal phishing verdict.
4. **#18** Multi-egress cloaking diff — defeats cloaking that defeats other layers.
5. **#20 + #21** Behavioral sandbox + canary creds — highest-confidence verdict possible.
6. **#32 + #33** LLM page-understanding + reasoner — only durable defense vs. attacker AI.
7. **#14** Persistent Site Registry — long-term memory and guilt-by-association.

---

---

## 28. DNS-Level Timing & User Flow (Tier-1/2/3 Strategy)

### 28.1 The Fundamental Constraint
DNS must answer in milliseconds or the browser times out (DNS_PROBE_FINISHED_NXDOMAIN). You cannot hold a query for 5 seconds while sandboxes render. The solution is a **3-tier response strategy**.

### 28.2 The Three Verdict States on Query Arrival

| State | Meaning | Latency | Returned |
|---|---|---|---|
| A. Cached verdict | Already scanned within TTL | <50 ms | Real IP (allow) / sinkhole (block) |
| B. Pre-scanned via CT/NRD | Scanned before any user visited | <50 ms | Same as A |
| C. Truly unknown | First time queried | Can't answer in 50 ms with full depth | 3-tier flow below |

System goal: keep state C ≤1% via aggressive CT-driven pre-scanning.

### 28.3 Tier-1 / Tier-2 / Tier-3 Strategy

**Tier 1 — Quick verdict in ≤250 ms (synchronous):**
Run parallel cheap checks — blocklist, NRD, WHOIS age, cert age, homoglyph, lexical, allowlist.
- Clear allow → return real IP.
- Clear block → return sinkhole.
- Uncertain → escalate to Tier 2.
Resolves ~80–90% of "unknown" queries.

**Tier 2 — Holding interstitial (≤5 s):**
Return a sinkhole IP that points to your "Analyzing…" page. Browser loads `scan.yoursys.io/?target=<domain>`. Page shows progress + early facts (registration age, ASN, cert). Sandbox renders the actual site in parallel. JS polls verdict API.
- Verdict clean → auto-redirect to real site.
- Verdict warn → yellow banner + Continue button.
- Verdict block → full-screen evidence page.

**Tier 3 — Async deep scan (no user wait):**
For low-suspicion ambiguous: allow + run deeper scan in background. If verdict flips to malicious, propagate cache and notify users via extension/agent post-hoc.

### 28.4 Latency Budget

| Stage | Time |
|---|---|
| DNS arrival + cache hit | <10 ms |
| Tier-1 checks (WHOIS + cert + DNS + lexical + feeds, parallel) | 150–250 ms |
| Sandbox cold start (Firecracker) | 100–200 ms |
| Headless render | 1.0–2.5 s |
| Visual embedding + brand match | 200–500 ms |
| Behavioral hooks + form analysis | 500–1500 ms |
| Multi-egress cloaking diff (parallel) | 1–2 s |
| LLM reasoner | 500–1500 ms |
| Fusion + verdict | <50 ms |
| **Tier 2 total** | **3–6 s** |

### 28.5 User Flow Diagram

```
User clicks https://unknown-site.tk/
        │
        ▼
Resolver: cache lookup → MISS
        │
        ▼
Tier 1 parallel checks (250 ms)
        │
   ┌────┼────┐
   ▼    ▼    ▼
 ALLOW BLOCK UNCERTAIN
   │    │       │
   │    │       ▼
   │    │   Sinkhole IP → scan.yoursys.io/?target=...
   │    │       │
   │    │       ▼
   │    │   "🔍 Analyzing this site for your safety…"
   │    │   Progress bar 3s · Reg 2d · AS12345 · LE cert 6h
   │    │       │
   │    │       ▼  (sandbox renders + JS polls)
   │    │   Verdict ready
   │    │       │
   │    │   ┌───┼───┐
   │    │   ▼   ▼   ▼
   │    │  CLEAN WARN BLOCK
   │    │   │   │    │
   ▼    ▼   ▼   ▼    ▼
 site  block redir banner full evidence page
       page                screenshot + LLM
```

---

## 29. User Dashboard, Admin Console & SaaS Multi-Tenancy

NextDNS-style SaaS with per-user dashboards and per-tenant admin.

### 29.1 The Personal Activity Dashboard

Every user sees their own browsing history with verdicts.

```
┌─────────────────────────────────────────────────────────────┐
│ YourSys — Your Browsing Safety History                       │
├─────────────────────────────────────────────────────────────┤
│ Last 30 days: 12,438 visits · 12,309 clean · 87 warned · 42  │
│ blocked                                                       │
├─────────────────────────────────────────────────────────────┤
│ Recently visited                                             │
├─────────────────────────────────────────────────────────────┤
│ 🟢 github.com               14:32  CLEAN  Tranco top 100    │
│ 🟢 anthropic.com            14:28  CLEAN  verified           │
│ 🟡 newsite-tech-2024.com    14:15  WARN   15d old, unknown  │
│      host    [Evidence] [Mark safe] [Report]                 │
│ 🔴 paypa1-secure.tk         13:47  BLOCKED — phishing       │
│      Visual match to paypal.com 0.97 · 2d old                │
│      [Full evidence] [I was tricked, help]                   │
│ 🟢 nytimes.com              13:42  CLEAN                     │
└─────────────────────────────────────────────────────────────┘
```

Click any row → full evidence (screenshot, redirect chain, infra facts, visual-match score, behavioral findings, LLM explanation, downloadable HAR/DOM artifacts).

### 29.2 Dashboard Features
- Per-visit verdict + evidence page link
- Time-range filters, search, export (CSV/JSON)
- "Mark safe" / "Report problem" buttons (feeds #66/#93)
- Category breakdown (work, finance, social, etc.)
- Threats blocked counter + shareable monthly report card
- Per-device, per-profile separation
- Local-first storage; cloud sync opt-in
- One-click history purge; auto-purge schedule

### 29.3 Admin Console (Multi-Tenant SaaS)

For families, SMBs, schools, enterprises. Each tenant has an admin who manages members.

```
┌──────────────────────────────────────────────────────────────┐
│  YourSys Admin — Acme Inc. (47 members, 134 devices)         │
├──────────────────────────────────────────────────────────────┤
│ Dashboard  Members  Devices  Policies  Logs  Reports  Billing│
├──────────────────────────────────────────────────────────────┤
│ This week                                                    │
│ • 2.4 M queries · 184 blocked · 38 user-reported              │
│ • Top threats: phishing 142 · malware 28 · tracker 12k        │
│ • Risk users: alice@acme (12 high-risk clicks), bob@acme (8) │
├──────────────────────────────────────────────────────────────┤
│ Members (47)                                                 │
│ ┌──────────────────────────────────────────────────────────┐│
│ │ Name        Devices  Last seen  Risk  Policy            ││
│ ├──────────────────────────────────────────────────────────┤│
│ │ alice@…     3        2m ago     HIGH  default           ││
│ │ bob@…       2        12m ago    MED   default           ││
│ │ carol@…     1        1h ago     LOW   strict-kids       ││
│ │ [+ Invite member]                                       ││
│ └──────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

### 29.4 Admin Capabilities
- **Member management**: invite, remove, group, suspend.
- **Device enrollment**: per-device DoH endpoint + token; QR-code add for mobile; auto-detect from extension/agent.
- **Policy profiles**: default, strict, kids, work, gaming — assigned per member or group.
- **Per-user policy override**: tighten or loosen.
- **Allowlist / blocklist editor**: custom per-tenant rules.
- **Real-time logs viewer**: every query + verdict (subject to retention policy).
- **Per-member risk score** (#62) with action recommendations.
- **Reports**: weekly/monthly PDF + CSV exports.
- **Notifications**: Slack/email/webhook on high-risk events.
- **API + SCIM** for enterprise IdP integration.
- **Billing**: per-seat or per-query pricing tiers.

### 29.5 Tenant Hierarchy

```
Organization (tenant)
  ├── Groups (HR, Engineering, Kids, Guests)
  │     ├── Policy assignment
  │     └── Members
  │           ├── Devices
  │           │     ├── DoH endpoint per device
  │           │     └── Per-device policy override
  │           └── Personal dashboard
  └── Admin roles (owner / admin / viewer)
```

### 29.6 Onboarding Flow
1. Admin signs up → org created.
2. Admin invites members via email/SSO.
3. Each member gets a unique DoH endpoint URL.
4. Member sets DoH on device (or scans QR for mobile profile, or installs extension).
5. Admin sees member appear in console within 1 query.
6. Default policy applied; admin can refine per member.

### 29.7 Why This Matters
- Direct revenue model (per-seat SaaS like NextDNS Plus, Cloudflare Zero Trust).
- Sticky product — admins don't switch once devices are enrolled.
- Compliance hook for SOC 2, HIPAA, GDPR via per-tenant retention/policy.
- Network effect — federated intel (#75) grows stronger with each tenant.

### 29.8 Build Effort for Dashboard + Admin
| Component | Effort |
|---|---|
| User Personal Dashboard (web + extension panel) | 1.5 mo |
| Admin Console — members, devices, policies, logs | 2.5 mo |
| Multi-tenancy schema + auth + RBAC | 1.5 mo |
| Per-tenant DoH endpoint provisioning | 0.5 mo |
| SCIM + SAML/OIDC SSO | 1.0 mo |
| Reports + exports + notifications | 0.75 mo |
| Billing integration (Stripe) | 0.5 mo |
| **TOTAL** | **~8 engineer-months** |

---

## 30. Industry-Standard Detection Methods (Quad9, NextDNS, Umbrella, et al.)

What every commercial protective-DNS provider does today. Use this as the **baseline** the system must equal or exceed.

### 30.1 The Industry Detection Toolkit

| Method | Used by | What it does |
|---|---|---|
| **Aggregated commercial + community threat feeds** | All | Blocklist match (PhishTank, OpenPhish, URLhaus, GSB, SmartScreen, abuse.ch, Spamhaus DBL, SURBL, Spamhaus DROP, IBM X-Force, Talos) |
| **Newly Registered Domain (NRD) lists** | NextDNS, DNSFilter, Umbrella, Cloudflare | Block domains <30 days |
| **Newly Seen Domain (NSD) lists** | Umbrella, DNSFilter | Block domains first observed in PDNS within last 24h |
| **Domain age (WHOIS/RDAP)** | All paid services | Age-based scoring |
| **Category-based filtering** | Umbrella, DNSFilter, NextDNS | Adult, gambling, social, etc. |
| **DGA detection (ML)** | Umbrella, Infoblox, PA Networks | Entropy + n-gram on domain strings |
| **DNS tunneling detection** | Umbrella, Infoblox, BlueCat | Per-client query rate/size/entropy anomaly |
| **Fast-flux / domain-flux detection** | Umbrella, Akamai | Resolution churn analysis |
| **Lookalike / homograph detection** | Bolster, PhishLabs (offline) | Edit-distance + Punycode unwrap |
| **Passive DNS (pDNS)** | Farsight DNSDB, SecurityTrails | Historical resolution data for correlation |
| **Certificate Transparency monitoring** | Bolster, CheckPhish, some SOCs | Pre-scan freshly issued certs matching brand patterns |
| **Reputation scoring per IP/ASN** | All | Per-IP and per-ASN abuse rates |
| **TLS fingerprinting (JA3/JA4)** | Cloudflare, Zscaler | Fingerprint malware C2 by TLS handshake characteristics |
| **JARM fingerprinting** | Cloudflare, GreyNoise | Active TLS-server fingerprinting for malicious infra identification |
| **HTTP signature matching** | Zscaler, SWGs | Match response patterns to known kit signatures |
| **Sinkhole intelligence** | Shadowserver, sinkhole partners | Track malware that calls sinkholed domains |
| **GeoIP + ASN cross-checks** | All | Flag mismatch between domain's typical geo/ASN and current resolution |
| **Sandboxing (file)** | Cloudflare, Zscaler, all enterprise SWGs | File detonation in VM |
| **Sandboxing (URL)** | urlscan.io, Joe Sandbox, Hybrid Analysis | Browser-based URL detonation |
| **HTML/JS template hashing** | Bolster, SlashNext | Match against known phishing kit templates |
| **Favicon + screenshot perceptual hash** | Bolster, SlashNext, urlscan | Visual lookalike detection |
| **DOM fingerprinting** | SlashNext, some SOCs | Structural similarity to brand DOMs |
| **TLS cert age + issuer reputation** | All | Fresh LE cert is a signal |
| **BGP monitoring** | Cloudflare, Akamai, Catchpoint | Hijack detection |
| **Subdomain takeover scanning** | Most bug-bounty + security tools | Dangling CNAME detection |
| **Honeypots + spam-trap mailboxes** | Spamhaus, all email security | Sample collection |
| **STIX/TAXII feed ingest** | Enterprise SWG | Commercial TI normalization |
| **Heuristic URL lexical features** | All paid services | Length, entropy, suspicious-keyword scoring |
| **WHOIS history (Iris)** | DomainTools customers | Registrant change detection |
| **Customer-submitted false-positive / false-negative loops** | All | Continuous label refinement |
| **TI sharing alliances (Cyber Threat Alliance, MISP)** | Most major vendors | Cross-vendor intel exchange |
| **Email sender reputation (SPF/DKIM/DMARC alignment)** | Email gateways | Signal even for URL inside email |

### 30.2 What's Common to Quad9 / NextDNS Specifically

| Method | Quad9 | NextDNS |
|---|---|---|
| Blocklist aggregation (~19 sources) | ✅ | ✅ (~70 sources, user-selectable) |
| NRD filter | ❌ | ✅ |
| AI domain classification | ❌ | ✅ (lightweight) |
| Category filtering | partial | ✅ |
| Cryptojacking blocklist | ❌ | ✅ |
| Tracker blocklist | ❌ | ✅ (very granular) |
| DNS rebinding protection | ❌ | ✅ |
| ECS (EDNS Client Subnet) anonymization | ✅ | ✅ |
| DoH/DoT/DNSCrypt | ✅ | ✅ |
| Per-user analytics dashboard | ❌ | ✅ |
| Block-page customization | ❌ | ✅ |

NextDNS is closest in *deployment model* to what you should build. The differentiator is the brain — they don't do visual brand match, identity-mismatch, behavioral sandbox, or LLM reasoning.

### 30.3 Domain-Age Scoring (Your Question Directly)

**Yes — brand-new domains get the highest risk score in the industry baseline.** A typical age-scoring curve:

| Domain age | Default risk contribution |
|---|---|
| <1 hour | +50 |
| <24 hours | +40 |
| <7 days | +30 |
| <30 days | +20 |
| <90 days | +10 |
| <1 year | +5 |
| 1–5 years | 0 |
| >5 years | -5 (mild trust) |

Combined with cert age, ASN reputation, and lexical signals via the fusion model. NextDNS, Umbrella, and Cloudflare all weight NRDs heavily.

### 30.4 "Beyond Detection" — Industry Mechanisms That Aren't Strictly Detection

These features exist in incumbent products that you should know about:

| Mechanism | Purpose |
|---|---|
| **Sinkholing** | Redirect malicious lookups to a logging server — captures who is infected (Conficker sinkhole is the famous example). |
| **Threat-actor attribution** | Map domains/IPs/wallets to known APT groups (CrowdStrike, Mandiant, Recorded Future). |
| **Takedown coordination** | Automated abuse-reports to registrars/hosts; APWG/PhishTank submissions; NetCraft cooperation. |
| **Honeyaccounts + honeyfiles** | Bait that triggers an alert when touched (a tripwire, not a detector). |
| **Sandbox decoy responses** | Return fake "success" to malware connecting to sinkholed C2 to keep the malware quiet while it's studied. |
| **Beacon timing analysis** | Detect malware by periodicity of its callback intervals, not its destination. |
| **JA3S / TLS reverse-fingerprint** | Servers can be fingerprinted by how *they* respond. |
| **Watering-hole pre-emption** | Identify popular sites visited by targeted users and pre-scan them more aggressively. |
| **Active scanning (Shodan-style)** | Proactively crawl IPs/domains looking for phishing kits' default file paths (`/admin.php`, `/login_ok.php`, kit-specific files). |
| **Underground monitoring** | Telegram channels, dark-web forums, GitHub for leaked kits and credential dumps. |
| **DNS recursion analytics** | Pattern-mine recursive resolver logs across users to find emerging C2 (used by Umbrella, Quad9). |
| **Glue-record / NS-takeover monitoring** | Catch hijacks via name-server change patterns. |
| **Decoy DNS replies** | For known-bad domains, return random non-routable IPs to misdirect malware. |
| **Domain similarity clustering** | Group domains by infrastructure overlap to "guilt by association" entire campaigns. |
| **Credential reuse correlation** | Match harvested credentials at canary endpoints to known breach data. |
| **Abuse-rate scoring per registrar** | Some registrars host 100× more phishing than others; weight accordingly. |
| **Active deception in sandbox** | Provide fake "high-value" responses to detected malware to extract its full behavior chain. |

### 30.5 What the System Has That Quad9 / NextDNS Don't

| Capability | Quad9 | NextDNS | Cloudflare | This system |
|---|---|---|---|---|
| Visual brand-impersonation detection | ❌ | ❌ | ❌ | ✅ |
| Identity-mismatch fusion | ❌ | ❌ | ❌ | ✅ |
| Behavioral sandbox + canary creds | ❌ | ❌ | partial | ✅ |
| LLM reasoner explanations | ❌ | ❌ | ❌ | ✅ |
| Per-URL transparency portal | ❌ | partial | ❌ | ✅ |
| CT-log proactive pre-scan | ❌ | ❌ | partial | ✅ |
| AI page-understanding | ❌ | ❌ | ❌ | ✅ |
| Multi-egress cloaking diff | ❌ | ❌ | ❌ | ✅ |

The intersection is the moat.

---

## 31. Coverage Boundaries & Out-of-Scope Positioning

### 31.1 What This System Covers Well

| Threat | Coverage |
|---|---|
| Web/browser-borne phishing (known + zero-day) | ~99% |
| Email phishing (with #40 rewriting) | ~95% |
| SMS / messenger phishing (with #55) | ~85% |
| Web-delivered malware (known + zero-day) | ~99% |
| Drive-by exploits, malvertising, cryptojacking | ~98% |
| C2 / exfil over DNS or HTTPS | ~98% |
| Lookalike / impersonation domains | ~99% |
| Tracking / fingerprinting surveillance | ~95% |
| Compromised legitimate sites | ~80% |

### 31.2 What This System Does NOT Cover (Adjacent Categories)

| Gap | Category | Vendor type to integrate with |
|---|---|---|
| Insider data exfil to personal cloud | DLP | Symantec DLP, Forcepoint |
| Already-installed malicious software | EDR | CrowdStrike, SentinelOne, Defender for Endpoint |
| Lateral movement on internal network | NDR / XDR | Darktrace, Vectra, ExtraHop |
| Identity / token / session hijack | ITDR / IAM | Okta, Push, Material |
| BEC without malicious URL | Email AI | Abnormal Security, Material |
| Hardware / firmware / BIOS attacks | Hardware security | Eclypsium, vendor TPMs |
| Mobile app store malware | Mobile security | Lookout, Zimperium |
| Software supply chain (npm/PyPI) | SCA | Snyk, Socket.dev |
| Browser extension supply chain | Endpoint policy | Spin.AI, LayerX |
| Network-layer (ARP spoof, Wi-Fi MITM) | Network security | VPN, IDS/IPS |
| Voice deepfake / vishing | Voice AI | Pindrop |

### 31.3 Positioning Statement
**"The most complete defense against web-borne and DNS-borne threats."**

Do **not** claim to replace EDR, DLP, NDR, or identity-protection products. The system is the **prevention layer at the web/DNS edge** — it pairs with those products, doesn't compete with them. The clean integration story: ingest endpoint/identity signals, emit verdicts, hand off to SIEM/SOAR.

### 31.4 Marketing Lines That Are Defensible
- "Stops phishing other tools can't see — even on day-zero domains."
- "Sees with you, blocks for you, and shows you why."
- "Identity-mismatch detection at DNS speed."
- "The transparency-first protective DNS."

### 31.5 Marketing Lines To Avoid (Overpromise)
- "Total security solution" — not true; doesn't cover EDR/DLP/identity.
- "Stops all malware" — no product does; you stop most web-delivered.
- "Replaces antivirus" — false unless you ship the AV-class endpoint (Stage 4+).
- "100% accuracy" — no detector reaches 100%; claim 99.9% with caveats.

---

---

## 32. XGenGuardian — Positioning, Differentiation & Sales Pitch

### 32.1 Market Tier Map

```
TIER 4 — Brain-First Protective DNS (XGenGuardian)
        Visual + identity-mismatch + LLM + transparency
                          ▲
TIER 3 — Smart Protective DNS (NextDNS, DNSFilter, ControlD)
        Blocklists + NRD + ML domain classifier + dashboard
                          ▲
TIER 2 — Basic Protective DNS (Quad9, Cloudflare 1.1.1.2, AdGuard)
        Threat-intel blocklist aggregation
                          ▲
TIER 1 — Plain DNS (8.8.8.8, ISP DNS) — no security
```

XGenGuardian is one full tier above NextDNS. It is a new category: **brain-first protective DNS**.

### 32.2 Capability Delta vs. Incumbents

| Capability | Quad9 | NextDNS | Cloudflare 1.1.1.2 | **XGenGuardian** |
|---|:---:|:---:|:---:|:---:|
| DoH/DoT + DNSSEC | ✅ | ✅ | ✅ | ✅ |
| Threat-intel blocklists | ✅ | ✅ | ✅ | ✅ |
| NRD / DGA / category filters | partial | ✅ | partial | ✅ |
| Tracker / fingerprint blocking | ❌ | ✅ | partial | ✅ |
| Per-user dashboard | ❌ | ✅ | ❌ | ✅✅ (evidence pages) |
| Multi-tenant admin (SaaS) | ❌ | ✅ | ✅ | ✅ |
| CT-log proactive pre-scan | ❌ | ❌ | ❌ | ✅ |
| Sandboxed page render for unknowns | ❌ | ❌ | ❌ | ✅ |
| **Visual brand-impersonation detection** | ❌ | ❌ | ❌ | ✅ |
| **Identity-mismatch fusion verdict** | ❌ | ❌ | ❌ | ✅ |
| Multi-egress cloaking diff | ❌ | ❌ | ❌ | ✅ |
| Behavioral sandbox + canary creds | ❌ | ❌ | ❌ | ✅ |
| LLM page-understanding | ❌ | ❌ | ❌ | ✅ |
| LLM verdict reasoner | ❌ | ❌ | ❌ | ✅ |
| Per-URL Transparency Portal | ❌ | ❌ | ❌ | ✅ |
| File detonation (CAPE-class) | ❌ | ❌ | ❌ | ✅ |

### 32.3 Accuracy Delta

| Metric | NextDNS / Quad9 / Cloudflare | XGenGuardian | Delta |
|---|---|---|---|
| Known phishing | ~85% | ~99% | +14 pts |
| Zero-day lookalike phishing (<24h) | <30% | ~95% | **+65 pts** |
| AI-generated phishing pages | <20% | ~90% | **+70 pts** |
| Cloaked phishing | <40% | ~95% | +55 pts |
| Time to block new campaign | hours–days | minutes–seconds | order-of-magnitude |

### 32.4 Five Core Differentiators (The Moat)

1. **Visual + identity-mismatch detection at DNS speed** — looks like Brand X + isn't Brand X = blocked.
2. **CT-log proactive pre-scan** — phishing infra detected at cert issuance, before first victim.
3. **LLM reasoner — every verdict explained** — plain-English explanation with screenshot.
4. **Per-URL Transparency Portal** — every block becomes a public, shareable evidence page.
5. **AI-aware** — multimodal page understanding catches AI-generated novel phishing.

### 32.5 Sales Pitches

**8-second tagline:**
> XGenGuardian. The phishing your DNS missed. Caught.

Alternates:
- Sees what NextDNS can't. Blocks what Quad9 won't.
- AI-grade phishing defense at DNS speed.
- Transparent DNS security. Every block, explained.
- Zero-day phishing, blocked on day zero.

**30-second cold intro:**
> NextDNS and Quad9 block phishing they've already heard of. Modern phishing kits live 4–6 hours — by the time a blocklist updates, the victims are already phished. XGenGuardian watches the Certificate Transparency log firehose and uses visual brand-impersonation detection to catch phishing the instant it appears, before anyone is victimized. Every block comes with a screenshot, evidence page, and plain-English explanation, so users trust it instead of disabling it.

**2-minute pitch:** see §32.6 below.

### 32.6 The 2-Minute Story
Today's protective-DNS market has two failures.

**1. Detection.** Quad9 and NextDNS are blocklist aggregators. They catch what others have already labeled. Modern phishing kits live 4–6 hours: by the time a blocklist updates, the domain is dead. Anything truly new gets through.

**2. Transparency.** When a site is blocked, the user sees "blocked by policy." Users disable filtering, IT can't audit, trust erodes.

XGenGuardian solves both. We watch the Certificate Transparency log firehose in real time — every TLS cert issued worldwide. The moment a lookalike like `pаypal-secure.com` gets a cert, we render the page in a sandbox, compute visual similarity to the real PayPal login, check whether it's hosted on PayPal's infrastructure, and block it before a single user has visited. That's our **identity-mismatch** engine.

When a user hits a blocked site, they get a Transparency Portal page: sandboxed screenshot, visual-similarity score, domain age, host ASN, form-action target, LLM-written explanation. They see exactly why.

All of this runs over DoH. One DNS setting. No client install. No TLS interception. The first protective-DNS product that catches zero-day phishing as well as a $20-per-user SWG, delivered through the same channel as Quad9.

### 32.7 Pitch by Audience

| Audience | One-liner |
|---|---|
| Consumer / family | "Your DNS already blocks ads. Ours blocks the scams designed to fool your mom — including ones the big guys haven't heard of yet." |
| SMB / startup | "All the phishing protection your team would get from Cloudflare Zero Trust or Zscaler, without the proxy, the CA install, the broken apps, or $20/user." |
| Mid-market / enterprise | "We catch the phishing your current SWG misses. CT-log + visual brand-match plugs into your existing Zscaler/Netskope/Cloudflare via API. Stack-additive, not rip-and-replace." |
| Schools / parents | "Everything NextDNS does, plus AI that catches phishing scams the first time anyone sees them. Full screenshot reports of every site your kids tried to visit." |

### 32.8 Demo Script (Closes Deals)
1. Open `report.xgenguardian.io`.
2. Paste a real PhishTank URL from the last 6 hours.
3. ~3 s: side-by-side screenshots — phishing vs. real brand.
4. "Visual similarity 0.96. Domain age 14 h. Cert 3 h. Bulletproof host. Form posts to evil-collect.tk."
5. Live API comparison: Google Safe Browsing + VirusTotal + SmartScreen — all return CLEAN.
6. "This is what your current vendor lets through. XGenGuardian blocked it 14 hours before they will."

### 32.9 Pricing Anchors

| Tier | Price | Anchors |
|---|---|---|
| Free | $0 | Beats Quad9 (free) |
| Plus | $2.99/mo | Beats NextDNS Plus ($1.99) on brain |
| Family | $5.99/mo | Beats NextDNS Family |
| Pro (SMB) | $3/user/mo | Half of Cloudflare Zero Trust |
| Business | $8/user/mo | Matches Cloudflare Zero Trust, undercuts Zscaler |
| Enterprise | custom | Dedicated PoPs + premium intel + SWG mode |

Positioning: **Cloudflare Zero Trust pricing, NextDNS deployment simplicity, SlashNext-grade phishing detection.**

### 32.10 Strategic Realities (For Founders/Investors)
- Don't fight Cloudflare on infrastructure; win on the brain.
- Cloudflare may ship similar within 2–3 years — move fast, build a user base, weaponize Transparency Portal as a viral moat.
- Federation (#75) is the network effect — more tenants → faster zero-day catch → harder to displace.
- Distribution > tech. Pursue OS/browser DNS defaults, router OEM partnerships, power-user communities (HN, Reddit r/privacy, r/selfhosted).

### 32.11 The Thesis One-Liner
> **XGenGuardian is what protective DNS looks like when the brain catches up to the network.**

---

## 33. Implementation Plan — Phased Feature Build

Six-phase build, each phase a shippable milestone with a clear launch story. Effort in engineer-months for one engineer; team-of-3 calendar in parentheses.

### 33.1 Phase 0 — Foundations (Pre-Phase, 2 weeks)
**Goal:** repos, infra, CI/CD ready.
- Monorepo (Turborepo) or polyrepo decision; standardize Go for backend, TypeScript for frontend, Python for ML.
- GitHub org + branch protection + CI (lint, test, build).
- Cloud account (single region to start) + Terraform skeleton.
- Postgres, Redis, S3-compatible storage, observability (Grafana Cloud free tier).
- Domain registration: `xgenguardian.com`, `xgenguardian.io`, `report.xgenguardian.io`, `dns.xgenguardian.io`.
- Internal: status page, error tracking (Sentry), Linear/Jira, Slack/Discord.

**Deliverable:** "Hello world" deploy pipeline working end-to-end.
**Effort:** 1.0 mo (1 wk calendar with 3 engineers).

---

### 33.2 Phase 1 — POC (Public Demo) — 3 calendar months, ~9 engineer-months

**Mission:** prove the brain works publicly. The artifact that gets posted to Hacker News.

**Features in this phase:**
| # | Feature | Notes |
|---|---|---|
| 1 | Hardened DoH/DoT resolver (CoreDNS or Knot) | Single region, no anycast yet |
| 2 | DNSSEC validation | Resolver-level |
| 3 | Threat-intel blocklist ingest (PhishTank, OpenPhish, URLhaus) | Subset of full list |
| 4 | NRD filter (<24h) | Daily refresh |
| 5 | WHOIS/RDAP age lookup | Cached |
| 6 | TLS cert inspection (age, issuer) | Cached |
| 7 | CT log monitor (Certstream) — pre-scan brand-lookalike issuances | Subset of full L4 |
| 8 | Homoglyph + typosquat detector vs. mini brand registry | 50 brands |
| 9 | Tranco top 1M Bloom allowlist | Single-load |
| 10 | Sandboxed render (Playwright in Docker) | Single egress |
| 11 | Visual brand-impersonation (CLIP + favicon) | 50 brands |
| 12 | Brand Protection Registry (seeded for 50 brands) | Manual + scripted |
| 13 | Identity-mismatch fusion rule | Static thresholds, no ML |
| 14 | Site Registry (Postgres + pgvector) | Verdict + history |
| 15 | Redis fast-path cache | 24h TTL |
| 16 | Block-page interstitial | Per-URL evidence template |
| 22 | Form-action analysis | Single check |
| 37 | Transparency Portal (Next.js) | Public, paste-URL endpoint |

**Out of scope this phase:** behavioral sandbox, canary creds, LLM reasoner, multi-egress, file scanning, mobile, native client, federation, admin console.

**Sub-milestones:**
| Week | Deliverable |
|---|---|
| 1 | Resolver up, blocklists ingested, DoH endpoint live |
| 2 | URL Verdict API skeleton + Redis cache + Postgres registry |
| 3 | Lexical layer + WHOIS/RDAP/cert/NRD; Tranco allowlist; rule-based verdict |
| 4 | Playwright render service; screenshot + DOM + favicon capture |
| 5 | Brand Registry seeding for 50 brands; CLIP embeddings; pgvector |
| 6 | Visual + favicon fusion; threshold tuning on labeled PhishTank set |
| 7 | Transparency Portal UI + per-verdict evidence pages + CT-log pre-scanner |
| 8 | Hardening, rate-limiting, public health page, launch prep |
| 9–12 | Public launch (HN/PH/X), iterate on feedback, fix FPs/FNs |

**Phase 1 success metrics:**
- Catches ≥50% of last 100 PhishTank submissions while <24h old
- Catches ≥10 phishing URLs that GSB + SmartScreen + VT all label clean at scan time
- Median verdict <5s on unknown, <100ms on cached
- ≥1,000 daily verdict-page views within 30 days of launch
- One side-by-side demo video that closes any deal

**Phase 1 deliverable:** A live public service at `report.xgenguardian.io` + public DoH endpoint `dns.xgenguardian.io`.

---

### 33.3 Phase 2 — v1 Hybrid Launch — +3 calendar months, ~10 engineer-months

**Mission:** turn the POC into a real product with browser extension, user accounts, and mobile profile. The first revenue-eligible release.

**New features added:**
| # | Feature |
|---|---|
| 17 | Public-DoH bypass control (block 1.1.1.1, dns.google from clients) |
| 18 | Multi-egress fetch + cloaking diff (residential + datacenter + Tor exits) |
| 19 | Redirect chain forensics |
| 20 | Behavioral sandbox hooks (clipboard, credential, crypto, WebSocket) |
| 21 | Canary credential submission |
| 25 | Chained external scanning on borderline (GSB + VT + urlscan + OTX) |
| 28 | JS deobfuscation + AST analysis |
| 30 | ASN / hosting reputation |
| 32 | LLM page-understanding (multimodal) |
| 33 | LLM reasoner — verdict explanations |
| 38 | Continuous model retraining + feedback loop (manual loop OK at v1) |
| 39 | Passive DNS history (SecurityTrails free tier or paid) |

**Client features:**
- Chrome extension (MV3): sends URL hashes, shows block interstitial, runs tracker blocklist (#70).
- Firefox port.
- Mobile DoH/DoT config profile (iOS .mobileconfig + Android Private DNS instructions).
- User account creation, personal dashboard with visit history + verdicts.
- Block-page UX overhaul with full evidence.

**Brand Registry expansion:** 50 → 500 brands via CT-log mining + Tranco top-500 auto-seed.

**Sub-milestones:**
| Week | Deliverable |
|---|---|
| 1–2 | Multi-egress fetch infrastructure + cloaking diff |
| 3–4 | Behavioral sandbox + canary creds wired into verdict |
| 5 | Redirect chain forensics + JS AST analysis |
| 6 | LLM page-understanding + reasoner (using hosted LLM API) |
| 7–8 | Chrome + Firefox extension MV3 (URL reporting + block page + tracker blocklist) |
| 9 | User accounts (Auth0 or self-hosted) + personal dashboard |
| 10 | Mobile DoH/DoT profile generators + onboarding flow |
| 11 | Brand Registry expansion to 500 brands |
| 12 | v1 launch — billing, free tier + Plus tier active |

**Phase 2 success metrics:**
- 10,000 active DoH endpoints
- 1,000 paid Plus subscribers
- Catches ≥80% of last 100 PhishTank submissions while <24h old
- LLM reasoner used by ≥50% of all block-page visitors (engagement signal)
- Extension stars on Chrome Web Store ≥500 within 60 days

---

### 33.4 Phase 3 — SaaS Multi-Tenant + Admin Console — +2 calendar months, ~8 engineer-months

**Mission:** unlock SMB and family-plan revenue. Compete head-on with NextDNS Pro.

**New features:**
| # | Feature |
|---|---|
| 62 | Per-user risk score |
| 66 | False-positive feedback table + analyst loop |
| 67 | Post-hoc clean→malicious notification |
| 71 | Third-party cookie + storage partitioning enforcement (extension) |
| 72 | Browser fingerprint randomization (extension) |
| 73 | CNAME-cloaking tracker detection |
| 83 | Per-tenant policy engine (OPA/Rego) |
| 90 | Reputation API for SaaS partners (Slack/Teams/Discord webhooks) |
| 93 | "Report phishing" user button → analyst queue |

**Platform features:**
- Multi-tenant data model (orgs, groups, members, devices).
- Admin Console (members, devices, policies, logs, reports, billing).
- Per-tenant DoH endpoint provisioning.
- SCIM + SAML/OIDC SSO.
- Policy profiles (default, strict, kids, work, gaming).
- Per-device QR-code enrollment for mobile.
- Weekly/monthly PDF reports.
- Slack/email/webhook notifications.
- Stripe billing (per-seat + per-query metering).

**Sub-milestones:**
| Week | Deliverable |
|---|---|
| 1 | Multi-tenancy schema + RBAC + auth flows |
| 2 | Admin Console — members + devices |
| 3 | Policy engine (OPA) + per-tenant policy storage |
| 4 | Logs viewer + reports (PDF/CSV export) |
| 5 | SSO (SAML/OIDC) + SCIM |
| 6 | Stripe billing + tier gating |
| 7 | Per-user risk score + FP/FN analyst workflow |
| 8 | Launch SMB tier + Family tier |

**Phase 3 success metrics:**
- 50 paying orgs
- 500 paying families
- $25k MRR
- NPS ≥40 on Admin Console

---

### 33.5 Phase 4 — Production-Grade Detection (Full P1) — +3 calendar months, ~12 engineer-months

**Mission:** close the remaining detection gaps; reach the ~99% accuracy claim defensibly. The "Series A-ready" milestone.

**New features:**
| # | Feature |
|---|---|
| 23 | Multi-AV + YARA file scanning |
| 24 | Dynamic file detonation (CAPE) |
| 26 | DGA classifier (ML) |
| 27 | DNS tunneling detector |
| 29 | Code-signing verification |
| 31 | DOM-tree similarity vs. brand fingerprints |
| 34 | DNS rebinding detection |
| 35 | Subdomain takeover detection |
| 36 | Bitsquatting check |
| 40 | Email URL rewriting + time-of-click scan (gateway integration) |
| 53 | Honeypots (bait emails harvesting URLs) |
| 75 | Federated intel sharing between tenants |
| 86 | SIEM integration (Splunk/Elastic/Chronicle) |
| 91 | Anycast multi-region resolver (3 PoPs) |
| 92 | DDoS protection on resolver |

**Sub-milestones:**
| Block | Deliverable |
|---|---|
| Block A (mo 1) | File scanning + CAPE detonation + code-signing |
| Block B (mo 2) | DGA + tunneling + rebinding + bitsquat + subdomain takeover + DOM similarity |
| Block C (mo 3) | Email URL rewriting + honeypot ingest + federation + SIEM + anycast PoPs (3 regions) |

**Phase 4 success metrics:**
- ≥99% block rate on internal phishing test corpus
- File-detonation pipeline processing 100k samples/day
- Anycast PoPs in NA, EU, APAC
- 5,000 paying users (consumer + SMB combined)
- $100k MRR

---

### 33.6 Phase 5 — Endpoint Client + Enterprise Mode — +6 calendar months, ~25 engineer-months

**Mission:** non-browser coverage + enterprise SWG-grade visibility. The first AV-equivalent product.

**Endpoint deliverables:**
- Windows endpoint (no MITM initially): DoH manager, tray, DNS-log viewer, browser-ext synergy.
- Windows endpoint MVP with local HTTPS-intercepting proxy + per-install CA + top-50 pinned-app bypass.
- Linux endpoint (eBPF + nftables + fanotify + local proxy).
- macOS desktop (no MITM at v1 of macOS endpoint; MITM in Phase 6).

**Backend features added:**
| # | Feature |
|---|---|
| 41 | Geo-rotated fetch (3+ regions) |
| 42 | Time-delayed re-scan (+1h/+6h/+24h) |
| 43 | Wayback / Common Crawl diff |
| 44 | WHOIS history |
| 45 | Related-domain pivot |
| 46 | Infrastructure graph + GNN |
| 47 | BGP hijack monitoring |
| 48 | DOM/JS hash drift on known-good sites |
| 49 | Subresource Integrity verification |
| 50 | Third-party script provenance |
| 51 | Iframe origin analysis |
| 56 | OAuth consent-screen abuse detection |
| 57 | Browser-in-the-browser (BITB) detector |
| 58 | Anti-analysis detection |
| 59 | Push-notification abuse detection |
| 60 | Macro / LOLBin scan (Office/PDF) |
| 61 | PE entropy + packer detection |
| 63 | Honeytoken / canary creds on endpoints |
| 64 | Browser autofill protection |
| 65 | JIT MFA prompts |
| 68 | Endpoint post-click forensics |
| 69 | Endpoint rollback via VSS/APFS |
| 87 | ICAP / API into existing SASE/SWG |

**Sub-milestones:**
| Month | Deliverable |
|---|---|
| 1 | Win endpoint (no MITM) GA — DoH manager + tray + log viewer |
| 2 | Linux endpoint (no MITM) GA |
| 3 | Win endpoint MVP with local MITM + CA + pinned-app bypass |
| 4 | Endpoint behavior monitor (ETW user-mode) + post-click forensics |
| 5 | Backend P2 detection block (41–51) |
| 6 | Enterprise SWG mode + ICAP + email gateway + launch |

**Phase 5 success metrics:**
- 10 enterprise contracts ≥$25k ARR each
- Win + Linux endpoint installed-base ≥10k devices
- $400k MRR
- SOC 2 Type 1 certification

---

### 33.7 Phase 6 — Privacy & Advanced AI — +3 calendar months, ~10 engineer-months

**Mission:** privacy-first features, advanced AI defenses, mobile depth. The "trust differentiator" release.

**New features:**
| # | Feature |
|---|---|
| 52 | Tor / dark-web phishing-kit monitoring |
| 54 | QR-code OCR + URL pipeline |
| 55 | SMS / messenger URL API |
| 70 (full) | Tracker / fingerprint blocklist completeness |
| 74 | Active disruption (automated takedown notices) |
| 76 | Oblivious DoH (ODoH) |
| 77 | OPRF / blinded URL lookups |
| 78 | Browser isolation fallback (remote pixel-stream) |
| 79 | Mobile VPN profile (native) — iOS + Android |
| 80 | Endpoint agent for non-browser processes (macOS full MITM) |
| 81 | TestFlight / sideload mobile-app fingerprinting |
| 82 | In-app browser detection (mobile) |
| 84 | Cryptographically signed verdicts |
| 85 | GDPR-aware retention |
| 88 | LLM red-team adversary generating synthetic phish |
| 89 | Autoencoder anomaly detection |
| 94 | Analyst workbench UI |
| 95 | Compliance dashboards |

**Phase 6 success metrics:**
- SOC 2 Type 2 + ISO 27001 in flight
- Mobile native apps in iOS App Store + Google Play
- ODoH partnership with at least one privacy-focused partner
- $1M ARR

---

### 33.8 Visual Roadmap

```
Phase 0 — Foundations             ▍ 2 wk
Phase 1 — POC                     ████ 3 mo
Phase 2 — v1 Hybrid Launch        ████ 3 mo
Phase 3 — SaaS Multi-Tenant       ███ 2 mo
Phase 4 — Production P1           ████ 3 mo
Phase 5 — Endpoint + Enterprise   ████████ 6 mo
Phase 6 — Privacy & Advanced AI   ████ 3 mo
                                  ────────────────
                                  ~20 calendar months to feature-complete
```

### 33.9 Cumulative Engineer-Months by Phase

| Phase | Effort (em) | Cumulative | Cumulative calendar (team of 3) |
|---|---|---|---|
| 0 | 1 | 1 | 0.5 mo |
| 1 | 9 | 10 | 3.5 mo |
| 2 | 10 | 20 | 6.5 mo |
| 3 | 8 | 28 | 8.5 mo |
| 4 | 12 | 40 | 11.5 mo |
| 5 | 25 | 65 | 17.5 mo |
| 6 | 10 | 75 | 20.5 mo |

**Total to feature-complete XGenGuardian: ~75 engineer-months / ~20 calendar months / team of 3.**

### 33.10 Team Composition by Phase

| Phase | Team |
|---|---|
| 1 (POC) | 1 backend + 1 ML/CV + 1 frontend |
| 2 (v1) | + 1 extension/mobile |
| 3 (SaaS) | + 1 full-stack (admin console) |
| 4 (P1) | + 1 security engineer (file/network detection) |
| 5 (Endpoint) | + 2 systems engineers (Win/Linux drivers + proxy) |
| 6 (Privacy/AI) | + 1 mobile engineer + 1 ML researcher |

Peak team size ~8–10 engineers by Phase 6.

### 33.11 Critical Dependencies & Risks Per Phase

| Phase | Top risks |
|---|---|
| 1 | CLIP threshold tuning / false-positive rate; Brand Registry quality |
| 2 | Chrome Web Store review delays; LLM API cost at scale |
| 3 | Stripe + SSO integration; per-tenant data isolation correctness |
| 4 | CAPE Sandbox operability; anycast IP/BGP procurement |
| 5 | Kernel driver signing (WHQL) lead time; pinned-app bypass list maintenance; AV conflicts |
| 6 | iOS App Store review for VPN apps; ODoH partner availability |

### 33.12 Phase Exit Criteria

Each phase has a "go-live" gate. Phase must meet **all** criteria to advance:

| Phase | Gate criteria |
|---|---|
| 0 | CI green; staging deploy works; observability shows logs |
| 1 | Demo URL catches X10 zero-day phishing URLs that incumbents miss; 1k DoH users; HN front page hit |
| 2 | $5k MRR; 10k DoH users; extension stars ≥500 |
| 3 | $25k MRR; 50 paid orgs; SCIM verified with 1 enterprise pilot |
| 4 | 99% block rate on test corpus; SOC 2 Type 1; 3 anycast PoPs live |
| 5 | 10 enterprise contracts; Win + Linux endpoint GA; $400k MRR |
| 6 | Mobile apps live; SOC 2 Type 2 in flight; $1M ARR |

### 33.13 Cost Profile (Cloud Infra)

| Phase | Monthly infra cost |
|---|---|
| 1 | ~$300 (single VPS + Postgres + small GPU box) |
| 2 | ~$1,500 (more sandbox capacity + LLM API spend) |
| 3 | ~$4,000 (multi-tenant scale + Stripe + auth) |
| 4 | ~$15,000 (CAPE sandbox farm + anycast PoPs + premium TI feeds) |
| 5 | ~$35,000 (enterprise scale + endpoint telemetry storage) |
| 6 | ~$60,000 (full feature load at scale) |

### 33.14 Recommended Sequencing Notes
- Ship Phase 1 publicly even if rough. The Transparency Portal artifact compounds in value as it indexes.
- Phase 2's extension is the moment XGenGuardian becomes "sticky" — users see history, can't go back.
- Resist building endpoint (Phase 5) before Phase 4 detection is solid; the endpoint is only worth installing if the brain behind it is best-in-class.
- Phase 6's ODoH/OPRF is the trust differentiator that closes EU/regulated buyers.

### 33.15 What Comes After Phase 6
- Industry partnerships: OS/browser DNS defaults (Brave-tier wins), router OEM bundles.
- Threat-intelligence resale: your verdict feed becomes a product for other SOCs.
- API platform: partners (Slack, Discord, Notion) call XGenGuardian per-link.
- Geographic expansion: anycast PoPs in 15+ regions.
- ML research arm: publish on the visual-impersonation detector, build defensible academic position.

---

---

## 34. Phase 0/1 Starter Repo Structure

Monorepo (Turborepo or Nx). Go for backend services, Python for ML/sandbox, TypeScript for frontend and extension.

### 34.1 Top-Level Layout

```
xgenguardian/
├── README.md
├── LICENSE
├── .github/
│   └── workflows/
│       ├── ci.yml                  # lint + test + build per package
│       ├── deploy-staging.yml
│       └── deploy-prod.yml
├── turbo.json                      # task pipeline
├── package.json                    # workspace root
├── go.work                         # Go workspace
├── pyproject.toml                  # Python workspace (uv / poetry)
├── docker-compose.yml              # local dev: Postgres + Redis + MinIO
│
├── infra/                          # Terraform + Kubernetes
│   ├── terraform/
│   │   ├── modules/
│   │   │   ├── resolver-pop/
│   │   │   ├── analysis-cloud/
│   │   │   └── postgres/
│   │   └── envs/{staging,prod}/
│   └── k8s/
│       ├── resolver/
│       ├── verdict-api/
│       ├── sandbox-pool/
│       └── portal/
│
├── services/                       # backend services
│   ├── resolver/                   # Go — DoH/DoT resolver
│   │   ├── cmd/resolver/main.go
│   │   ├── internal/
│   │   │   ├── doh/
│   │   │   ├── dot/
│   │   │   ├── rpz/                # response policy zones
│   │   │   ├── blocklists/         # ingest + bloom filters
│   │   │   ├── nrd/                # newly-registered-domain filter
│   │   │   ├── cache/              # redis client
│   │   │   └── verdict_client/     # calls verdict-api
│   │   ├── Dockerfile
│   │   └── go.mod
│   │
│   ├── verdict-api/                # Go — central scoring service
│   │   ├── cmd/verdict-api/main.go
│   │   ├── internal/
│   │   │   ├── api/                # gRPC + HTTP handlers
│   │   │   ├── tier1/              # whois, cert, lexical, homoglyph
│   │   │   ├── tier2/              # async sandbox dispatch
│   │   │   ├── fusion/             # rule-based fusion v1
│   │   │   ├── registry/           # site registry client
│   │   │   └── cache/
│   │   ├── proto/
│   │   │   └── verdict.proto
│   │   └── Dockerfile
│   │
│   ├── sandbox-render/             # Python — Playwright headless render
│   │   ├── app/
│   │   │   ├── main.py             # FastAPI worker
│   │   │   ├── render.py           # playwright render + screenshot
│   │   │   ├── extract.py          # DOM/form/favicon extraction
│   │   │   └── egress.py           # proxy rotation
│   │   ├── pyproject.toml
│   │   └── Dockerfile              # Playwright image base
│   │
│   ├── visual-match/               # Python — CLIP + favicon + pgvector
│   │   ├── app/
│   │   │   ├── main.py             # FastAPI: POST /embed → vector
│   │   │   ├── clip_model.py
│   │   │   ├── favicon_hash.py
│   │   │   └── search.py           # pgvector queries
│   │   └── Dockerfile              # CUDA optional
│   │
│   ├── ct-monitor/                 # Go — Certstream subscriber
│   │   ├── cmd/ct-monitor/main.go
│   │   ├── internal/
│   │   │   ├── certstream/         # WebSocket client
│   │   │   ├── matcher/            # homoglyph vs. brand list
│   │   │   └── prescan_queue/      # pushes to verdict-api
│   │   └── Dockerfile
│   │
│   ├── registry-svc/               # Go — Site + Brand Registry CRUD
│   │   ├── cmd/registry-svc/main.go
│   │   ├── internal/
│   │   │   ├── db/                 # sqlc-generated Postgres bindings
│   │   │   ├── domains/
│   │   │   ├── urls/
│   │   │   ├── brands/
│   │   │   └── evidence/
│   │   ├── migrations/             # goose / golang-migrate SQL
│   │   │   ├── 0001_init.sql
│   │   │   ├── 0002_brand_registry.sql
│   │   │   └── 0003_evidence.sql
│   │   └── Dockerfile
│   │
│   └── portal-api/                 # Go — Transparency Portal backend
│       ├── cmd/portal-api/main.go
│       ├── internal/
│       │   ├── verdict_lookup/
│       │   └── evidence_serve/
│       └── Dockerfile
│
├── apps/                           # frontend apps
│   ├── portal/                     # Next.js — Transparency Portal
│   │   ├── app/
│   │   │   ├── page.tsx            # "Check this URL" landing
│   │   │   ├── report/[id]/page.tsx# per-verdict evidence page
│   │   │   └── compare/page.tsx    # side-by-side demo
│   │   ├── components/
│   │   │   ├── VerdictBadge.tsx
│   │   │   ├── EvidencePanel.tsx
│   │   │   └── SideBySide.tsx
│   │   ├── lib/api.ts
│   │   └── package.json
│   │
│   └── extension/                  # Phase 2 — Chrome MV3 extension
│       ├── manifest.json
│       ├── src/
│       │   ├── background.ts
│       │   ├── content.ts
│       │   └── popup/
│       └── package.json
│
├── tools/                          # one-off scripts + seeders
│   ├── brand-seeder/               # Python — fetch + embed 50 brands
│   │   ├── seed.py
│   │   ├── brands.yaml             # the seed list (see §36)
│   │   └── pyproject.toml
│   ├── blocklist-fetcher/          # cron-style ingest
│   └── eval/                       # phishing-corpus evaluation harness
│
├── proto/                          # shared protobuf definitions
│   └── verdict/v1/verdict.proto
│
└── docs/
    ├── architecture.md             # ← this document
    ├── runbooks/
    └── api/
```

### 34.2 Key Inter-Service Contracts

**`verdict.proto` (simplified):**
```protobuf
syntax = "proto3";
package verdict.v1;

service Verdict {
  rpc CheckURL  (CheckURLRequest)  returns (CheckURLResponse);
  rpc CheckDomain (CheckDomainRequest) returns (CheckDomainResponse);
}

message CheckURLRequest {
  string url = 1;
  string client_id = 2;  // tenant/user identity
  bool   force_rescan = 3;
}

message CheckURLResponse {
  string verdict = 1;          // CLEAN | WARN | BLOCK | ANALYZING
  double confidence = 2;
  string evidence_id = 3;      // links to portal-api
  repeated string signals = 4; // e.g. ["nrd<24h", "homoglyph=paypal", "visual=0.96"]
  string llm_explanation = 5;  // populated in Phase 2
}
```

### 34.3 Local Dev Stack (`docker-compose.yml`)
- `postgres` (with `pgvector` extension preinstalled)
- `redis`
- `minio` (S3-compatible for evidence)
- `coredns` (binds to `5300/udp` so it doesn't conflict with local `53`)
- `mailhog` (catches test emails)

Run `make dev` → spawns the whole stack + `air` watchers for Go services.

### 34.4 Initial Postgres DDL (Phase 1)
```sql
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE domains (
  domain TEXT PRIMARY KEY,
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen  TIMESTAMPTZ DEFAULT NOW(),
  registrar TEXT,
  registered_at TIMESTAMPTZ,
  asn INTEGER,
  cert_sha256 TEXT,
  verdict TEXT,
  verdict_confidence REAL,
  flags TEXT[],
  last_scanned_at TIMESTAMPTZ,
  next_rescan_at  TIMESTAMPTZ
);

CREATE TABLE urls (
  url_hash BYTEA PRIMARY KEY,
  url TEXT NOT NULL,
  domain TEXT REFERENCES domains(domain),
  redirect_chain TEXT[],
  final_url TEXT,
  verdict TEXT,
  verdict_confidence REAL,
  evidence_id UUID,
  last_scanned_at TIMESTAMPTZ
);

CREATE TABLE brands (
  brand_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_name TEXT UNIQUE NOT NULL,
  canonical_domains TEXT[] NOT NULL,
  legitimate_asns INTEGER[],
  legitimate_issuers TEXT[],
  favicon_hashes TEXT[],
  keywords TEXT[]
);

CREATE TABLE brand_screenshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  brand_id UUID REFERENCES brands(brand_id),
  page_label TEXT,         -- 'login', 'home', 'checkout', ...
  embedding vector(512) NOT NULL,
  screenshot_url TEXT
);
CREATE INDEX ON brand_screenshots USING ivfflat (embedding vector_cosine_ops);

CREATE TABLE evidence (
  evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  screenshot_url TEXT,
  dom_url TEXT,
  har_url TEXT,
  visual_top_brand TEXT,
  visual_top_score REAL,
  signals JSONB,
  llm_explanation TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  retention_until TIMESTAMPTZ
);
```

### 34.5 Service Boot Order (Phase 1)
1. Postgres + Redis + MinIO (dev) or managed equivalents (cloud).
2. `registry-svc` (DB owner; runs migrations).
3. `visual-match` (loads CLIP model into memory).
4. `sandbox-render` (Playwright workers).
5. `verdict-api` (calls all three above).
6. `resolver` (calls verdict-api).
7. `ct-monitor` (pushes pre-scan jobs).
8. `portal-api` + `portal` (Next.js).

---

## 35. Phase 1 Week-1 Backlog (Ticket-Level)

Issues to open on day one, with acceptance criteria. Format: `[ID] Title — owner-role — AC bullets`.

### Epic: E1 — Resolver MVP

- **`[XGG-1] Stand up Go monorepo + Turborepo + CI`** — *Lead*
  AC: `make build` builds every service; `make test` runs unit tests; `make lint` passes; GitHub Actions runs on PR.

- **`[XGG-2] Provision dev Postgres + Redis + MinIO via docker-compose`** — *Backend*
  AC: `docker-compose up` brings stack up; `psql` shows `vector` extension; Redis responds; MinIO bucket `xgg-evidence` exists.

- **`[XGG-3] Bootstrap resolver service with CoreDNS plugin shell`** — *Backend*
  AC: Resolver answers `dig @localhost -p 5300 example.com` with correct answer; logs every query at structured JSON.

- **`[XGG-4] Implement DoH endpoint over HTTPS at /dns-query`** — *Backend*
  AC: `curl -H 'accept: application/dns-message' …` returns RFC 8484 wire format; passes DoH compliance test from Cloudflare.

- **`[XGG-5] Ingest PhishTank + OpenPhish + URLhaus as blocklist`** — *Backend*
  AC: A cron pulls each feed hourly; bad domains land in a Bloom filter loaded by resolver; resolver sinkholes a known-bad PhishTank domain end-to-end.

- **`[XGG-6] Tranco top-1M allowlist Bloom filter`** — *Backend*
  AC: Resolver fast-paths `google.com` in <5ms; falls through for unknown.

### Epic: E2 — Verdict API + Site Registry

- **`[XGG-7] Define verdict.proto + scaffold gRPC server`** — *Backend*
  AC: `grpcurl` can call `CheckURL` with a stub; returns `ANALYZING`.

- **`[XGG-8] Postgres migrations (domains, urls, brands, brand_screenshots, evidence)`** — *Backend*
  AC: `golang-migrate up` runs cleanly; tables visible; pgvector index created.

- **`[XGG-9] Redis verdict cache with TTLs (24h allow / 30d block / 0 unknown)`** — *Backend*
  AC: Repeated calls for same URL return cached verdict in <10ms.

- **`[XGG-10] Tier-1 worker: WHOIS/RDAP + cert age + lexical features`** — *Backend*
  AC: Calling `CheckURL` for an unknown domain returns a verdict in <300ms with `signals[]` populated.

- **`[XGG-11] Homoglyph + Levenshtein detector vs. brand keyword list`** — *Backend*
  AC: Unit test: `paypa1.com` matches `paypal` with confidence ≥0.9; `paypa1-secure.tk` likewise.

### Epic: E3 — Sandbox Render

- **`[XGG-12] Playwright headless render worker in Docker`** — *ML/Infra*
  AC: POST `/render` with a URL returns `{screenshot_url, dom, favicon_url, forms[]}` within 3s for typical sites.

- **`[XGG-13] Form-action extractor`** — *Backend*
  AC: Pages with login forms return `forms[].action_origin`; cross-origin POSTs flagged.

- **`[XGG-14] Evidence uploader to MinIO/S3 with signed URLs`** — *Backend*
  AC: Every render produces an `evidence_id` row with valid signed URLs for screenshot/dom/har.

### Epic: E4 — Visual Brand Match

- **`[XGG-15] Visual-match service loading OpenCLIP ViT-B/32`** — *ML*
  AC: POST `/embed` with image bytes returns `{vector: [512 floats]}`; cold start <3s; warm <300ms.

- **`[XGG-16] Brand seeder script — 50 brands → screenshots → embeddings → DB`** — *ML*
  AC: After running `brand-seeder seed`, `brand_screenshots` has ≥50 rows with embeddings; pgvector kNN returns expected brand for known login page.

- **`[XGG-17] Favicon pHash + MMH3 hashing service`** — *ML*
  AC: Hashes are deterministic; known-brand favicon matches in DB.

- **`[XGG-18] Identity-mismatch fusion rule (v1, rule-based)`** — *Backend*
  AC: For a labeled phishing URL (`pаypal-login.tk` against PayPal): visual_similarity≥0.92 + non-canonical-domain + age<90d → verdict=BLOCK, confidence≥0.95.

### Epic: E5 — Portal & Demo

- **`[XGG-19] Transparency Portal — Next.js scaffold with paste-URL form`** — *Frontend*
  AC: User pastes URL → frontend calls `/verdict?url=…` → shows skeleton "Analyzing…" → renders verdict.

- **`[XGG-20] Per-verdict evidence page /report/[id]`** — *Frontend*
  AC: Page shows screenshot, signals list, top-brand match, LLM explanation placeholder, downloadable artifacts.

- **`[XGG-21] Side-by-side comparison view`** — *Frontend*
  AC: For phishing verdicts with `visual_top_brand`, page shows phishing screenshot side-by-side with the brand's canonical screenshot from registry.

- **`[XGG-22] Public deployment to a single region (staging.xgenguardian.io)`** — *Infra*
  AC: HTTPS site live; DoH endpoint `dns.staging.xgenguardian.io` reachable; resolver, verdict-api, sandbox-render, visual-match, portal all on internal network.

### Epic: E6 — Eval & CT Monitor

- **`[XGG-23] CT-log monitor (Certstream client + brand-prefix matcher)`** — *Backend*
  AC: Service streams Certstream WebSocket; any newly-issued cert containing a brand keyword (Levenshtein ≤2) gets pushed into the prescan queue; verdict-api dequeues and scans.

- **`[XGG-24] Evaluation harness against last-24h PhishTank set`** — *ML*
  AC: `make eval` runs scoring against PhishTank's last 24h submissions; outputs precision/recall/F1; baseline ≥50% recall.

### Day-1 Setup Tickets
- `[XGG-25] Register `xgenguardian.com`, `.io`, configure DNS, ACM certs`
- `[XGG-26] Set up Sentry, Grafana Cloud, status page`
- `[XGG-27] Decide observability conventions (OTel spans naming)`
- `[XGG-28] Create Linear/Jira workspace, milestones for Phase 1 weeks`
- `[XGG-29] Write CONTRIBUTING.md + SECURITY.md`

**Week 1 success criteria:** XGG-1 through XGG-10 closed; resolver returns blocked-domain sinkhole end-to-end against PhishTank list; verdict-api answers Tier-1 in <300ms.

---

## 36. Brand Registry Seed List (Phase 1 — 50 Brands)

The 50 most-impersonated brands worldwide (per APWG + Vade + Microsoft phishing-trend reports, cross-referenced with Tranco top sites). For each: canonical login URL(s) to screenshot + embed.

### Format
`Brand · Canonical login URL(s) — purpose`

### Financial Services (10)
1. **PayPal** · https://www.paypal.com/signin
2. **Stripe** · https://dashboard.stripe.com/login
3. **Chase** · https://secure01a.chase.com/web/auth/dashboard
4. **Bank of America** · https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go
5. **Wells Fargo** · https://connect.secure.wellsfargo.com/auth/login
6. **Citi** · https://online.citi.com/US/login.do
7. **HSBC** · https://www.hsbc.com.hk/credit-cards/login/
8. **American Express** · https://www.americanexpress.com/en-us/account/login
9. **Coinbase** · https://www.coinbase.com/signin
10. **Binance** · https://accounts.binance.com/en/login

### Big Tech Identity / Cloud (12)
11. **Google (accounts)** · https://accounts.google.com/signin
12. **Microsoft 365 / Outlook** · https://login.microsoftonline.com
13. **Apple ID** · https://appleid.apple.com/sign-in
14. **Amazon** · https://www.amazon.com/ap/signin
15. **AWS Console** · https://signin.aws.amazon.com/signin
16. **Azure Portal** · https://portal.azure.com
17. **GitHub** · https://github.com/login
18. **GitLab** · https://gitlab.com/users/sign_in
19. **Dropbox** · https://www.dropbox.com/login
20. **Box** · https://account.box.com/login
21. **Adobe Creative Cloud** · https://auth.services.adobe.com
22. **Atlassian** · https://id.atlassian.com/login

### Communication / Collaboration (8)
23. **Slack** · https://slack.com/signin
24. **Microsoft Teams** · https://teams.microsoft.com
25. **Zoom** · https://zoom.us/signin
26. **Webex** · https://web.webex.com
27. **Notion** · https://www.notion.so/login
28. **Discord** · https://discord.com/login
29. **Telegram Web** · https://web.telegram.org
30. **WhatsApp Web** · https://web.whatsapp.com

### Social / Consumer (8)
31. **Facebook** · https://www.facebook.com/login
32. **Instagram** · https://www.instagram.com/accounts/login
33. **LinkedIn** · https://www.linkedin.com/login
34. **Twitter / X** · https://x.com/login
35. **TikTok** · https://www.tiktok.com/login
36. **Reddit** · https://www.reddit.com/login
37. **Snapchat** · https://accounts.snapchat.com/accounts/login
38. **Pinterest** · https://www.pinterest.com/login

### E-Commerce / Logistics (6)
39. **eBay** · https://signin.ebay.com
40. **Shopify** · https://accounts.shopify.com/store-login
41. **Walmart** · https://www.walmart.com/account/login
42. **DHL** · https://www.dhl.com/in-en/home/tracking.html
43. **FedEx** · https://www.fedex.com/secure-login
44. **UPS** · https://www.ups.com/lasso/login

### SaaS / Enterprise (6)
45. **Salesforce** · https://login.salesforce.com
46. **Okta** · https://www.okta.com/login
47. **Zoho** · https://accounts.zoho.com/signin
48. **DocuSign** · https://account.docusign.com
49. **HubSpot** · https://app.hubspot.com/login
50. **ServiceNow** · https://signon.service-now.com

### Per-Brand Registry Entry Fields
For each of the 50:
- `brand_name` (string)
- `canonical_domains[]` (e.g., `paypal.com`, `paypalobjects.com`)
- `legitimate_asns[]` (lookup via ipinfo.io)
- `legitimate_issuers[]` (current cert issuer CN)
- `keywords[]` (brand, product names)
- 1–3 `brand_screenshots` per brand (login, home, checkout if relevant)
- `favicon_hashes[]` (pHash + MMH3)

### Seeder Workflow
1. `brand-seeder/brands.yaml` lists the 50 entries above + canonical URLs.
2. Script uses Playwright to load each URL through realistic UA + cookies-accepted state.
3. Capture screenshot at 1920×1080 + 1440×900 viewports.
4. Compute CLIP embedding (OpenCLIP ViT-B/32) → store in `brand_screenshots`.
5. Fetch favicon → pHash + MMH3 → store in `brands.favicon_hashes`.
6. Fetch current TLS cert → record issuer CN in `legitimate_issuers`.
7. Resolve canonical domain → IP → ipinfo.io → `legitimate_asns`.
8. Manual review pass: confirm screenshots are the intended page (not a captcha, not a region-redirected variant).

### Test Vectors for Phase 1 Acceptance
For each brand, also store **5 confirmed-phishing URLs** historically observed (from PhishTank archive). Phase 1 evaluation harness must:
- Correctly identify the brand each phish impersonates (recall ≥80%).
- Issue BLOCK verdict on ≥50% of phish while domain still <24h old.
- Issue ≤5% FPs against Tranco top 10k.

### Brand Registry Expansion Plan
- Phase 1: 50 brands (manual).
- Phase 2: 500 brands (CT-log mining + Tranco top 500 auto-seed).
- Phase 4: 5,000 brands (community + auto-seed at scale).
- Phase 6: 50,000 brands (federated tenant contributions).

---

*End of document.*
