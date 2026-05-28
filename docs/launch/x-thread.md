# X / Twitter Launch Thread

**Post at:** 12:00 Eastern (after HN peak).
**Visual:** the side-by-side screenshot (real PayPal login vs. paypa1.com lookalike). Same image attached to each of the first 3 tweets.

---

### 1/10

Today we're launching XGenGuardian.

NextDNS and Quad9 block phishing they've already heard of.
We catch it the moment it appears.

How? ↓

[image: side-by-side screenshots, real-brand vs. lookalike]

---

### 2/10

Modern phishing kits live 4–6 hours.

By the time PhishTank or Google Safe Browsing updates their blocklist, victims are already phished and the kit is gone.

That's the entire problem. Blocklist-based defenders are always one step behind.

---

### 3/10

We do two things blocklist defenders can't:

— Subscribe to the Certificate Transparency log firehose. Every new TLS cert worldwide, in real time.

— When a fresh cert looks like a brand we protect, render the page in a sandbox and visually compare it to that brand's real login screen.

---

### 4/10

If the page looks like Brand X (CLIP embedding ≥0.92) but isn't on Brand X's infrastructure (wrong ASN, wrong cert issuer, domain registered yesterday) → we block it.

Often before the first victim has even clicked the link.

That's the universal phishing tell.

---

### 5/10

Every block comes with a public evidence page.

— Sandboxed screenshot
— Visual-similarity score
— Domain age, host ASN, TLS cert age
— Form-action analysis (where do the credentials go?)
— Plain-English LLM explanation

You can audit every verdict.

→ report.xgenguardian.com

---

### 6/10

How you use it:

Set your DNS to dns.xgenguardian.com.
That's it.

— No client install
— No root CA
— No TLS interception
— Works on Win, macOS, Linux, iOS, Android, every browser

Free tier blocks the known stuff. Plus ($2.99/mo) adds the visual brain.

---

### 7/10

Honest comparison to incumbents:

[image: comparison table from landing page]

We're not trying to out-Cloudflare Cloudflare on infrastructure. We're trying to out-detect them on zero-day phishing. That's where the moat is.

---

### 8/10

What we deliberately don't claim:

— "Total security solution" — we don't replace EDR, DLP, or identity protection
— "100% accuracy" — no detector is perfect; we publish FP/FN rates
— "AI-powered" without saying what AI — CLIP for visual, optional LLM for explanations, classic ML for fusion

We respect your time.

---

### 9/10

Open questions we're tracking:

— Brands we've never seen (we only protect brands in our registry; coverage grows weekly)
— AI-generated novel pages (multimodal page-understanding is our defense, but it's an arms race)
— Cloaking (multi-egress diff helps, never solves)

Help us close them by reporting misses.

---

### 10/10

Try it now:

🔗 Demo (paste any URL): report.xgenguardian.com
🔗 Free DoH endpoint: xgenguardian.com#get-started
🔗 Architecture deep-dive (50 pages, every detail): xgenguardian.com/architecture
🔗 HN thread: <link>

Built by [name + small team]. Reply with the weirdest URL you've ever clicked, we'll scan it.
