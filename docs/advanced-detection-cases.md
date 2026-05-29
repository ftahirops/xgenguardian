# Advanced Detection Cases

This document explains where XGenGuardian outperforms reputation-first DNS filters and browser blocklists. The point is not that every case is impossible for every other product. The point is that these attacks are weakly covered by systems that only ask whether a domain is already known bad.

XGenGuardian combines:

```text
external intelligence
+ URL/action classification
+ sandbox render
+ visual brand matching
+ identity binding
+ sink analysis
+ command/OAuth/download/scam-specific rules
+ policy mode
```

## 1. Fresh Login Clone Before Feeds Catch Up

| Field | Detail |
|---|---|
| Scenario | new domain hosts a clone of Microsoft, PayPal, GitHub, bank, or SaaS login |
| Why normal filters miss | no reputation history; domain not yet in feeds |
| XGG catch | visual replica + brand keyword + identity mismatch + password form |
| Verdict | BLOCK or ISOLATE depending evidence strength |

Rule:

```text
high visual brand match + non-canonical host + credential form = block
```

## 2. Fake Developer Documentation With Malicious Command

| Field | Detail |
|---|---|
| Scenario | fake Claude/OpenAI/Cursor/Cline docs ask the user to copy a terminal command |
| Why normal filters miss | no file download; payload is text; domain may be new or hosted on a trusted platform |
| XGG catch | developer-install page class + code-block scan + copy-event mediation + install registry |
| Verdict | WARN, REQUIRE_APPROVAL, or BLOCK |

Rule examples:

```text
unknown docs host + mshta/rundll32/encoded PowerShell = block
official docs host + official command template = allow
visible command != copied command = block
```

## 3. OAuth Consent Abuse On A Real Provider Domain

| Field | Detail |
|---|---|
| Scenario | user lands on real Google/Microsoft/GitHub OAuth page, but app is unknown and requests high-risk scopes |
| Why normal filters miss | provider domain is legitimate |
| XGG catch | OAuth client registry + scope risk + redirect URI analysis |
| Verdict | BLOCK for unknown high-scope app |

Rule:

```text
real provider + unknown client_id + sensitive scopes = block
```

## 4. SafeLinks Or Proofpoint Wrapped Phishing

| Field | Detail |
|---|---|
| Scenario | email link is wrapped by Microsoft SafeLinks, Proofpoint, Mimecast, Cisco, Barracuda, or Symantec |
| Why normal filters struggle | visible host is trusted wrapper; destination is nested and encoded |
| XGG catch | wrapper recognition + destination extraction + final URL scan |
| Verdict | wrapper can pass only if destination passes |

Rule:

```text
trusted wrapper != trusted destination
unwrap -> normalize -> scan destination
```

## 5. Public Raw-IP Malware URL

| Field | Detail |
|---|---|
| Scenario | malware opens `http://1.2.3.4/x86`, `http://1.2.3.4/mips`, or `http://1.2.3.4/payload.exe` |
| Why DNS misses | no DNS lookup exists |
| XGG catch | browser/API raw-IP detection + architecture path + direct-download logic |
| Verdict | BLOCK/DETONATE unless operator/user allowlisted |

Policy:

```text
public raw IP + binary path = block
public raw IP + login/payment/admin = isolate/block
private/local IP = bypass or local policy
operator allowlisted IP = allow or trust-but-log
```

## 6. Compromised Legitimate Site With One Bad Path

| Field | Detail |
|---|---|
| Scenario | clean WordPress/business site hosts `/wp-content/cache/login.html` phishing page |
| Why normal filters miss | root domain reputation is clean |
| XGG catch | path-level verdict + sandbox render + form sink + visual replica |
| Verdict | exact path block, then path/subdomain escalation if repeated |

Rule:

```text
one infected page on known site -> block exact URL
repeated infected paths -> escalate to directory/subdomain
major/shared domains -> never punish apex from one page
```

## 7. Scam Support Page With Unknown Phone Number

| Field | Detail |
|---|---|
| Scenario | fake Microsoft/Apple/browser warning says "call support now" |
| Why normal filters miss | phone may be in rendered text or image; domain may be fresh |
| XGG catch | visual brand match + popup/alert/fullscreen behavior + phone extraction + official phone registry |
| Verdict | BLOCK when unknown phone correlates with brand/scareware |

Rule:

```text
brand support claim + unknown phone + scareware behavior = block
```

## 8. Refund, Tax, Or Government Scam

| Field | Detail |
|---|---|
| Scenario | fake IRS/HMRC/CRA/ATO refund page asks for card, bank, gift card, wire, or crypto |
| Why normal filters miss | scam language is page-specific; domain may not be known |
| XGG catch | government brand registry + refund/tax page class + payment-rail phrase detection |
| Verdict | WARN/BLOCK depending evidence |

Rule:

```text
government/tax claim + non-government domain + payment instruction = block
```

## 9. HTML Smuggling

| Field | Detail |
|---|---|
| Scenario | page uses JavaScript to assemble a malicious file in the browser |
| Why normal filters miss | file is not present as a normal URL at first load |
| XGG catch | sandbox render + YARA + auto-download behavior + blob/download hooks |
| Verdict | BLOCK or DETONATE |

Rule:

```text
JS-generated download + smuggling YARA + unknown host = block/detonate
```

## 10. Popup Storm / Browser Lock Scareware

| Field | Detail |
|---|---|
| Scenario | page opens random popups, alert loops, fullscreen traps, or beforeunload locks |
| Why normal filters miss | behavior happens after page load |
| XGG catch | behavior instrumentation in sandbox + opener lineage in extension |
| Verdict | WARN/BLOCK |

Rule:

```text
popup storm + alert loop + fullscreen/beforeunload = fake support scareware
```

## 11. Image-Only Or QR Phishing

| Field | Detail |
|---|---|
| Scenario | phishing URL, phone, or login instruction is hidden in image/QR instead of DOM |
| Why normal filters miss | text scanner sees little or nothing |
| XGG catch | screenshot OCR/QR extraction + recursive URL scan |
| Verdict | WARN/BLOCK when extracted target is risky |

Rule:

```text
QR URL domain != visible brand domain + sensitive action = warn/block
```

## 12. Shared Hosting Tenant Abuse

| Field | Detail |
|---|---|
| Scenario | attacker uses `evil.pages.dev`, `evil.github.io`, `evil.vercel.app`, or `evil.netlify.app` |
| Why normal filters struggle | parent platform is legitimate and must not be blocked globally |
| XGG catch | tenant-aware reputation and sandboxing |
| Verdict | block tenant, never apex |

Rule:

```text
badtenant.github.io = punish tenant
github.io = do not punish parent platform
```

## 13. Cross-Origin Credential Sink On A Clean-Looking Page

| Field | Detail |
|---|---|
| Scenario | page looks normal, but password/OTP/card is sent to a hidden endpoint |
| Why normal filters miss | domain may not be known bad and visual may be weak |
| XGG catch | credential sink hooks: form action, fetch, XHR, beacon, WebSocket, hidden mirror |
| Verdict | BLOCK for untrusted credential sink |

Rule:

```text
sensitive input + untrusted sink = block
```

## 14. Payment Checkout False Positive Avoidance

| Field | Detail |
|---|---|
| Scenario | legitimate billing page posts to Stripe, PayPal, Paddle, Adyen, Braintree, or similar |
| Why naive rules fail | payment flows are intentionally cross-origin |
| XGG catch | action-scoped payment processor trust |
| Verdict | allow payment sink without treating processor as page identity |

Rule:

```text
Stripe can be trusted as payment sink
Stripe is not trusted as Microsoft login identity
```

## 15. Operator Self-Hosted IP

| Field | Detail |
|---|---|
| Scenario | operator runs a trusted app on `https://135.181.79.27:18443/...` |
| Why raw-IP rule can FP | public IPs are usually suspicious, but operators have legitimate self-hosted tools |
| XGG catch | operator trusted hosts and user allowlist |
| Verdict | allow when explicitly trusted; otherwise scan aggressively |

Rule:

```text
public raw IP = risky by default
operator/user allowlisted raw IP = trusted exception
```

## Summary Matrix

| Detection Family | Best Against |
|---|---|
| external feeds | known malware/phishing |
| visual brand match | fresh brand clones |
| identity binding | fake brand on wrong infrastructure |
| credential sink | phishing even without strong visual match |
| command scanner | fake developer docs and ClickFix |
| OAuth registry | consent phishing on real provider domains |
| raw-IP policy | malware links DNS cannot see |
| scam artifacts | fake support, refund, tax, remote-access scams |
| behavior hooks | popup storm, scareware, auto-downloads |
| correlation graph | repeated phones, wallets, favicons, commands, sinks |

The strongest verdicts come from correlation:

```text
not one signal, but multiple independent signals agreeing
```

