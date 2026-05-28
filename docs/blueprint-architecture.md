# XGenGuardian Blueprint Architecture

This document explains XGenGuardian as a system: what it is, what it is not, why it is different from DNS filters and enterprise secure web gateways, where it shines, and how it integrates with xhelix.

## 1. Product Definition

XGenGuardian is a browser-side, DNS-side, and API-backed web safety engine for security, identity, content, and action decisions.

It is not only a phishing detector. It is an **action-aware web trust system**.

The core idea:

> A website is not simply safe or unsafe. A website may be safe to read, unsafe to log into, unsafe to copy a terminal command from, unsafe to download from, unsafe for a child, or safe only inside isolation.

XGenGuardian therefore protects at the point of action:

- DNS lookup,
- page navigation,
- login or payment form,
- OAuth consent,
- browser popup,
- terminal command copy,
- file download,
- manual URL scan,
- child/admin approval decision.

## 2. Main Differentiator

Most web filters are reputation-first.

```text
domain or URL -> reputation lookup -> category -> allow/block
```

XGenGuardian is proof-first for sensitive actions.

```text
page -> claimed identity -> requested action -> sink/target -> active policy mode -> verdict + evidence
```

This matters because modern attacks increasingly happen on:

- real provider domains through OAuth consent abuse,
- trusted platforms like GitHub Pages, Netlify, Cloudflare Pages, Google Forms, or Notion,
- compromised legitimate sites,
- fake developer documentation with copied terminal commands,
- QR codes and image-only lures,
- JavaScript-injected commands that static scanners never see,
- first-seen phishing kits before blocklists have caught up.

## 3. First-Viewport GitHub Message

For a GitHub project page, the strongest concise positioning is:

> XGenGuardian is a self-hostable, action-aware web safety engine that verifies identity, sink, command, content, and context before allowing sensitive web actions.

Top-level feature line:

```text
Protective DNS + browser action guard + sandbox evidence + transparent verdicts.
```

Short version:

```text
NextDNS-style DNS control tells you whether a domain is allowed.
XGenGuardian tells you whether this page is allowed to ask for this action.
```

## 4. System Diagram

```text
                         +----------------------+
                         |      User/Browser    |
                         | navigation, copy,    |
                         | download, popup      |
                         +----------+-----------+
                                    |
                                    v
          +-------------------------+-------------------------+
          |                                                   |
          v                                                   v
+---------+----------+                             +----------+---------+
| Browser Extension |                             | Protective DNS     |
| - URL submit      |                             | - resolver policy  |
| - copy mediation  |                             | - RPZ/blocklists   |
| - popup lineage   |                             | - category rules   |
| - submit recheck  |                             | - rebind defense   |
+---------+----------+                             +----------+---------+
          |                                                   |
          +-------------------------+-------------------------+
                                    |
                                    v
                            +-------+-------+
                            | Verdict API   |
                            | staged policy |
                            +-------+-------+
                                    |
       +----------------------------+----------------------------+
       |                            |                            |
       v                            v                            v
+------+-------+            +-------+-------+            +-------+-------+
| Fast Checks  |            | Deep Render   |            | Registries    |
| DNS, feeds,  |            | Playwright,   |            | brand, OAuth, |
| URL lexical  |            | DOM, JS, OCR, |            | install,      |
| cache, RDAP  |            | YARA, files   |            | trust, policy |
+------+-------+            +-------+-------+            +-------+-------+
       |                            |                            |
       +----------------------------+----------------------------+
                                    |
                                    v
                         +----------+-----------+
                         | Fusion + Mode Policy |
                         +----------+-----------+
                                    |
                 +------------------+------------------+
                 |                  |                  |
                 v                  v                  v
              ALLOW/WARN          BLOCK          ISOLATE/DETONATE/
                                                  REQUIRE_APPROVAL
```

## 5. Enforcement Surfaces

| Surface | Sees | Strength | Limitation |
|---|---|---|---|
| DNS resolver | domain-level requests | fastest, device/network-wide when configured | cannot see URL path, DOM, forms, commands, or OAuth scopes |
| Browser extension | full URL, DOM context, copy/paste, popups | best for phishing, command lures, OAuth, and child policy | browser-specific unless backed by local agent |
| Verdict API | normalized URL, registries, feeds, policy, evidence | consistent decision point for DNS, extension, portal, and tools | depends on the quality of submitted context |
| Portal/manual scan | user-submitted URLs | transparent evidence and analyst workflow | not automatic protection by itself |
| Sandbox render | page behavior and artifacts | catches cloaking, JS mutation, downloads, sinks, and rendered text | slower and more expensive |
| xhelix bridge | process execution after web action | catches post-execution secret theft/C2 | outside XGenGuardian's web boundary |

## 6. Staged Verdict Model

XGenGuardian avoids a single flat score where unrelated signals get mixed too early.

| Stage | Inputs | Output |
|---|---|---|
| URL normalization | redirects, nested URLs, shorteners, punycode, encoded URLs | canonical URL graph |
| Reputation | public feeds, DNS provider votes, local history, graph reuse | known bad, known safe, unknown |
| Page class | login, payment, OAuth, developer install, download, chat, adult, generic | risk profile |
| Replica analysis | screenshot, OCR, favicon, DOM, title, visual embedding | claimed brand and similarity |
| Identity binding | canonical domains, certs, ASN, script origins, form targets | authorized, mismatch, unknown |
| Sink analysis | forms, fetch, XHR, beacon, WebSocket, clipboard, downloads | trusted sink, untrusted sink, unknown |
| Content safety | text, OCR, image, category lists, child-risk communities | safe, restricted, harmful |
| Mode policy | normal, child, strict, paranoid, allowlist | final verdict |

## 7. Verdict States

| Verdict | Meaning | Example |
|---|---|---|
| ALLOW | Enough evidence to proceed under the active mode | official docs with canonical install command |
| WARN | Suspicious but not enough to block | new domain with weak scam signals |
| BLOCK | High-confidence malicious, harmful, or disallowed | visible command differs from copied command |
| ISOLATE | Risky or unknown; open remotely without endpoint trust | first-seen login page in paranoid mode |
| REQUIRE_APPROVAL | Parent/admin/operator approval required | child tries a new chat site or unknown download |
| DETONATE | File/script needs sandbox analysis before release | executable or script from unknown source |
| ALLOW_TEMP | Temporary approval with expiry | parent-approved homework site for one hour |

## 8. The Four Core Questions

### 8.1 Replica

Does the page claim to be a known entity?

Signals:

- visual embedding similarity,
- favicon pHash/MMH3,
- screenshot pHash/dHash,
- OCR text,
- title and metadata,
- DOM skeleton,
- copied brand assets.

Replica is not proof of phishing. It identifies the claimed identity.

### 8.2 Identity

Is this page authorized for that identity?

Signals:

- canonical host,
- tenant pattern,
- ASN/CDN,
- certificate issuer,
- script origins,
- form/API origins,
- OAuth endpoints,
- official install command templates.

High-confidence rule:

```text
high replica + identity mismatch + sensitive action = block
```

### 8.3 Sink

Where does the sensitive action go?

Sensitive actions:

- password entry,
- OTP/MFA entry,
- payment/card entry,
- OAuth consent,
- wallet connection,
- copied terminal command,
- file download,
- browser notification,
- remote support/install prompt.

Strongest rule:

```text
sensitive action + untrusted sink = block
```

### 8.4 Context

Should this mode allow the action even if evidence is incomplete?

Context:

- child vs adult,
- normal vs strict vs paranoid,
- first-seen page,
- opener lineage,
- user personal profile,
- known school/work/bank/app list,
- unknown sensitive category.

## 9. Developer Install-Lure Defense

This is a first-class page class because modern developer attacks do not always ask for credentials. They ask the user to copy a command.

### 9.1 Attack Pattern

```text
fake docs page -> copy install command -> terminal paste -> loader -> stealer/C2
```

### 9.2 Why Traditional Filters Miss It

| Traditional Check | Why It Fails |
|---|---|
| Domain reputation | Fake pages rotate quickly and often use trusted hosting platforms |
| Visual similarity | Fake docs intentionally look identical to real docs |
| Static DOM scan | Malicious command can be injected after render |
| Download scan | The user may paste a command, not download a file |
| AV scan | Payload may be fileless or staged after execution |

### 9.3 XGenGuardian Controls

| Control | Purpose |
|---|---|
| `developer_tool_install_lure` page class | Routes AI/dev tool pages to stricter policy |
| Official install registry | Positive-match official host and command templates |
| Command analyzer | Shell/PowerShell structure, encoded payloads, LOLBins, UNC paths |
| Copy-button mediation | Blocks the actual paste path, not only the page load |
| Visible-vs-clipboard comparison | Catches JavaScript command swaps |
| Post-render code-block diff | Catches runtime-injected commands |
| xhelix provenance bridge | Catches execution if prevention fails |

### 9.4 Command Risk Families

| Family | Example | Default |
|---|---|---|
| official template | canonical vendor host + known command pattern | allow |
| shell chain | `&`, `&&`, `;`, `|` | corroborate |
| remote execute | `curl-to-shell`, `irm-to-iex` | allow only if official; otherwise warn/approval/block |
| Windows LOLBin | `mshta`, `rundll32`, `regsvr32` remote | block |
| encoded payload | base64 to shell, PowerShell EncodedCommand | block or detonate |
| UNC/WebDAV | `\\host\share\file` | block |
| clipboard mismatch | visible text != copied text | block |

## 10. Mode Policy Matrix

| Action | Normal | Strict | Child | Paranoid |
|---|---|---|---|---|
| known bad URL | block | block | block | block |
| unknown login page | warn/isolate | isolate | block/approval | isolate/block |
| unknown payment page | warn/isolate | isolate | block/approval | isolate/block |
| copied terminal command from unknown site | warn/approval | approval/block | block | block |
| official install command | allow | allow | approval | allow if profile permits |
| executable download from unknown site | detonate | detonate/block | block | block |
| anonymous chat/community | allow/warn | warn | block/approval | isolate |
| adult content | allow/warn by config | block by config | block | block by config |
| OAuth sensitive scopes from unknown app | warn/isolate | isolate/block | block | block |

## 11. Comparison With Other Security Solutions

| Capability | DNS-only products | Browser built-ins | Enterprise SWG | XGenGuardian |
|---|---:|---:|---:|---:|
| Domain reputation | Strong | Strong | Strong | Strong |
| URL/path context | Weak | Medium | Strong | Strong |
| DOM/page analysis | None | Limited | Medium/Strong | Strong |
| Copy-command mediation | None | None | Rare | Core feature |
| OAuth consent analysis | None | Weak | Limited | Core feature |
| Identity binding by action | None | Weak | Mixed | Core model |
| Child mode with action policy | Category-only | Weak | Mixed | First-class |
| Transparent evidence | Weak | Weak | Weak/Mixed | Core feature |
| Self-hostable | Mixed | No | Usually no | Yes |
| Cross-tenant telemetry | Weak to strong by provider | Huge | Huge | Limited by deployment |
| Mobile/app coverage | DNS products win | Browser-specific | Strong with agents | Roadmap/local-agent dependent |

## 12. Why It Can Beat Bigger Products In Narrow Areas

XGenGuardian cannot out-index Google, Microsoft, Cisco, Cloudflare, or Zscaler across the entire internet.

It can still win where bigger systems are optimized for speed, broad reputation, and category policy:

- command-copy malware,
- OAuth consent abuse,
- first-seen sensitive pages,
- personal-profile brand impersonation,
- visible-vs-clipboard mismatch,
- explainable evidence,
- strict child/paranoid mode,
- self-hosted privacy.

This is the out-of-box value: XGenGuardian protects the **moment of sensitive action**, not just the domain lookup before it.

## 13. Data Stores

| Store | Contains |
|---|---|
| Brand registry | canonical domains, visual seeds, favicon hashes, allowed scripts/forms |
| Install registry | official docs hosts, official script URLs, command templates, package names |
| OAuth registry | known clients, scopes, publisher status, redirect URI reputation |
| URL verdict cache | per-URL and per-path verdicts |
| Domain reputation | feeds, DNS votes, first seen, last seen, cert/ASN metadata |
| Evidence store | screenshots, DOM, HAR, redirects, sinks, downloads, reasons |
| Infrastructure graph | domains, IPs, certs, favicons, wallets, phones, webhooks, file hashes |
| Personal profile | banks, schools, SaaS, AI tools, cloud apps, payment processors |

## 14. Reason Codes

Stable reason codes make decisions explainable and testable.

| Reason Code | Meaning |
|---|---|
| `IDENTITY_MISMATCH_DOMAIN` | page claims brand but host is not canonical |
| `CREDENTIAL_SINK_UNTRUSTED_ENDPOINT` | credentials leave trusted origins |
| `VISIBLE_CLIPBOARD_MISMATCH` | copied command differs from displayed command |
| `DANGEROUS_COMMAND_STRUCTURE` | command contains high-risk execution structure |
| `DEVELOPER_TOOL_INSTALL_LURE` | page is an install/docs lure for a developer tool |
| `OAUTH_SENSITIVE_SCOPES_UNKNOWN_APP` | OAuth app requests risky scopes without trust |
| `FIRST_SEEN_SENSITIVE_PAGE` | new page asks for sensitive action |
| `CLOAKING_DETECTED` | scanner/user variants differ materially |
| `HTML_SMUGGLING_PAYLOAD` | page generates downloadable payload in browser |
| `CHILD_POLICY_CATEGORY_BLOCK` | active child mode disallows category/action |

## 15. Reference Request Flow

```text
1. User navigates to a page or copies a command.
2. Extension or DNS submits domain/URL/action context.
3. Verdict API normalizes URL and extracts domain.
4. Fast path checks cache, feeds, lexical, DNS, RDAP, trust lists.
5. Unknown or suspicious pages go to sandbox render.
6. Render captures DOM, screenshot, forms, JS behavior, downloads, OCR/YARA.
7. Registries bind claimed identity to allowed infrastructure and sinks.
8. Fusion engine produces verdict, confidence, reason codes, and evidence ID.
9. Policy mode converts risk into user action: allow, warn, block, isolate, detonate, approval.
10. Portal stores the result for review, audit, and false-positive tuning.
```

## 16. Build Priorities

| Rank | Work Item | Why |
|---|---|---|
| 1 | `developer_tool_install_lure` page class | routes high-risk AI/dev install pages correctly |
| 2 | official install registry | positive allow for real vendors, scrutiny for clones |
| 3 | shell/PowerShell command analyzer | understands the real attack payload |
| 4 | copy-button mediation | blocks the paste path |
| 5 | visible-vs-clipboard mismatch | catches JS-injected command swaps |
| 6 | fp-bench corpus for dev install pages | prevents rule sprawl and false-positive drift |
| 7 | path-level reputation | catches compromised legitimate sites |
| 8 | OAuth registry | catches real-domain consent abuse |
| 9 | QR/OCR recursion | catches image-hidden URLs |
| 10 | xhelix provenance bridge | closes post-execution gap |

## 17. xhelix Coexistence

xhelix is a Linux server EDR and runtime enforcement system. It is not a web content classifier. XGenGuardian is a web trust system. They overlap only at the boundary between web-originated actions and host behavior.

### 17.1 Boundary

| Layer | XGenGuardian | xhelix |
|---|---|---|
| URL reputation | owns | consumes selected intel |
| page/DOM/visual/OAuth analysis | owns | no |
| copy-button mediation | owns | consumes provenance |
| file download pre-scan | owns | observes execution |
| process execution | no | owns |
| secret file/API key reads | no | owns |
| outbound C2 from process | enriches with intel | owns |
| containment/quarantine | browser/isolation | host/process/cgroup |

### 17.2 Bridge

```text
XGenGuardian evidence:
  source_url
  page_class
  copied_command_hash
  downloaded_file_hash
  verdict
  reason_codes

            |
            v

xhelix event enrichment:
  process lineage
  command executed
  file opened
  secrets touched
  outbound destination
  containment decision
```

### 17.3 Combined Detection Example

| Step | XGenGuardian | xhelix |
|---|---|---|
| user visits fake AI tool docs | visual/identity/install-lure detection | no event yet |
| user clicks copy | command mediation blocks or tags command | no event yet |
| user pastes anyway | browser boundary ends | sees shell execution and source provenance |
| command runs `curl-to-bash` or `mshta` | prior verdict becomes context | process lineage + suspicious exec |
| malware reads local API keys/secrets | no host visibility | secret access escalates severity |
| malware calls C2 | domain intel can enrich | egress/verifier/incident graph contain |

Together they cover both sides:

- XGenGuardian prevents risky web actions.
- xhelix contains the host when prevention fails.

## 18. Non-Goals

XGenGuardian should not try to become:

- a full Linux EDR,
- a generic SIEM,
- a replacement for xhelix,
- a mobile MDM,
- a misinformation truth engine,
- a universal malware sandbox vendor.

Its strength is narrower and more valuable: web action trust with transparent evidence.

## 19. Final Positioning

XGenGuardian is best described as:

> A self-hostable action-aware web safety engine that verifies identity, sink, command, content, and context before allowing sensitive web actions.

It is not stronger than every commercial product at every layer. It is stronger in specific places where reputation-first products are structurally weak:

- fresh phishing,
- OAuth consent abuse,
- command-copy malware,
- fake developer documentation,
- child/paranoid uncertainty handling,
- transparent evidence,
- personal-profile sensitive actions.
