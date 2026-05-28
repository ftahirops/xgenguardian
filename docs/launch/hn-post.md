# Hacker News — Show HN Post

**Submit at:** 09:00 Eastern Tuesday or Wednesday (avoid Mondays and Fridays).
**Title (≤80 chars):**

```
Show HN: XGenGuardian – Catches phishing your DNS missed, with full evidence
```

**URL:** `https://xgenguardian.com`

---

## Body (paste into the "text" field below the URL, or as first comment if posting URL-only)

Hi HN,

I'm building XGenGuardian — a DNS-layer phishing detector that catches lookalike sites NextDNS, Quad9, and Cloudflare 1.1.1.2 don't (yet).

The trick: most blocklist-based DNS providers wait for someone else to label a phishing site. Modern phishing kits live 4–6 hours, so by the time PhishTank or Google Safe Browsing updates, the victims are already phished.

We do two things differently:

1. **Pre-victim detection via Certificate Transparency.** We subscribe to the CT log firehose (every TLS cert issued worldwide, in real time). When a new cert appears for a domain that visually impersonates a brand we protect — even an edit-distance-1 lookalike like `paypa1.com` or `g00gle.com` — we sandbox-render the page, compare its screenshot against our brand registry with a CLIP embedding, and pre-classify it. Usually before the first user has clicked.

2. **Per-URL transparency portal.** Every block produces a public evidence page: sandboxed screenshot, visual-similarity score, domain age, host ASN, form-action target, and a plain-English LLM explanation. Try any URL: https://report.xgenguardian.com

It's a DoH/DoT endpoint — one DNS setting change to use, no client install, no TLS interception, no root CA. A browser extension is optional and adds per-page evidence + tracker blocking. Free tier blocks the known stuff; Plus ($2.99/mo) adds the visual-match brain.

I'd genuinely value your help on three things:
- Throw any URL at the Transparency Portal. The interesting cases for us are sites Google Safe Browsing + VirusTotal call clean that you think shouldn't be. Comment with whatever it flags or misses.
- Tell me what's wrong with the threat model. Cloaking, attacker-AI page generation, and brand-new brands we've never seen are our known weak spots.
- If you run a small SaaS / Slack workspace / community, the partner API is free for the next 90 days while we tune it.

Repo is open: https://github.com/xgenguardian/xgenguardian  (Phase-1 POC code; not production-clean yet)
Architecture doc — including what we deliberately don't do: https://xgenguardian.com/architecture

Happy to answer anything. I'll be on the thread all day.

— [name], founder

---

## Operational Notes (not in the post)

- Don't ask for upvotes. Don't seed comments from alt accounts. HN flags both.
- Reply to every top-level comment within 30 minutes for the first 4 hours.
- If asked "how is this different from X" → answer with a one-line difference + a link to the comparison table on the landing page.
- If asked "why open-source the code but charge for the product" → answer honestly: the brain (brand registry, models) is the moat, not the plumbing; we want the plumbing audited.

## Common Pushback → Honest Replies

| Pushback | Reply |
|---|---|
| "NextDNS does most of this for $1.99" | True for the blocklist + tracker layer. The visual brand-match and identity-mismatch fusion is what NextDNS doesn't do. Try the demo with a fresh PhishTank URL and you'll see. |
| "You'll never beat Cloudflare on scale" | Correct, and we're not trying. We pair with SASE products; the brain is the differentiator, not the anycast network. |
| "What about my privacy" | The default deployment is DNS-only — we never see your HTTPS traffic. The sandbox fetches suspect pages independently in our infra. ODoH is on the Phase-6 roadmap. |
| "AI hype" | The LLM only generates the verdict explanation users read on the block page. The actual detection is CLIP image embeddings + rule-based fusion, both of which we can show you in code. |
| "Show me a real catch" | <link to a specific live PhishTank entry we blocked that GSB+VT didn't> |
