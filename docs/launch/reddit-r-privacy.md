# Reddit Posts — r/privacy, r/selfhosted, r/sysadmin

Post sequence: r/privacy first (highest signal-to-noise), then r/selfhosted (different audience), then r/sysadmin (enterprise eyeballs). Stagger by 90 minutes so each gets fresh attention.

Reddit hates self-promotion. Lead with the user benefit, not the product name. Disclose your affiliation honestly.

---

## r/privacy

**Title:**
> Built a DNS-layer phishing detector that works without seeing your HTTPS traffic — looking for feedback

**Body:**

I've been frustrated for years with the two options for blocking phishing:

1. **Blocklist-based DNS** (NextDNS, Quad9): excellent privacy posture, but only catches phishing someone else has already labeled. Modern kits live a few hours; the lists update too slowly.
2. **Cloud SWGs** (Cloudflare Gateway, Zscaler): catch more, but you install a root CA on every device so they can read all your HTTPS. Hard pass for personal use.

I built XGenGuardian to try a middle path.

It's a DoH endpoint. You change one DNS setting, and it does three things blocklists alone don't:

- **CT-log monitoring**: subscribes to every TLS certificate issued worldwide. When a fresh cert looks like a brand (e.g. `paypa1-secure.tk`), the system pre-renders the page in a sandbox we control. No user traffic involved.
- **Visual brand-match**: CLIP image embedding of the rendered page vs. a registry of real login pages. If the page looks like PayPal but isn't on PayPal's infrastructure, blocked.
- **Per-URL evidence portal**: every block comes with a public page showing the screenshot, similarity score, domain age, where the credentials POST goes, and an LLM-generated explanation. Audit-able.

What I care about for r/privacy specifically:

- We never see your HTTPS traffic. The sandbox renders suspect pages independently, in our infrastructure, from public IPs we own.
- The default deployment is just DNS. The optional browser extension runs inside your browser (post-TLS-decryption) but only sends URL hashes — not page content — to our API.
- Oblivious DoH (ODoH) is on the roadmap so even we can't link queries to users.

Free tier is honestly useful (blocklists + NRD filter + dashboard). The visual brain costs $2.99/mo because the GPU sandboxes aren't free.

Demo (paste any URL): https://report.xgenguardian.com
Architecture doc with privacy section: https://xgenguardian.com/architecture#privacy

I'd genuinely appreciate:
1. Roasting the privacy model. What's wrong with it?
2. Submitting weird URLs to the portal. The ones that show what's broken are most useful.
3. r/privacy-specific feedback: would you self-host the resolver? (We're considering open-sourcing it.)

Disclosure: I'm the founder. Happy to take any question.

---

## r/selfhosted

**Title:**
> Show: brain-first protective DNS — open-source roadmap, MIT-licensed Phase-1 POC

**Body:**

Hey r/selfhosted. I've been building a phishing-detection DNS resolver that goes beyond the usual blocklists. The MIT-licensed POC is up on GitHub: https://github.com/xgenguardian/xgenguardian

The basic stack:
- Go DoH/DoT resolver (Knot Resolver / CoreDNS-compatible)
- Postgres + pgvector for the brand-screenshot registry
- Playwright sandbox-render service in Docker
- OpenCLIP ViT-B/32 for visual matching (CPU works; GPU faster)
- Next.js Transparency Portal
- Certstream subscriber for proactive cert-issuance scanning

Everything runs in docker-compose for dev. `make dev` brings it all up. `make seed-brands` populates a 50-brand registry. `make eval` runs against PhishTank's last 24h for a Phase-1 sanity check.

We host a managed version (xgenguardian.com), but the architecture document is genuinely complete enough that you can run this yourself if you want.

Things I'd love help with:
- Pi-hole / OPNsense / OpenWRT integration. We have docker-compose; we don't yet have OS-level packages.
- Brand registry contributions. If you maintain a brand or know its real infrastructure, send a PR to `tools/brand-seeder/brands.yaml`.
- Bug reports on the resolver itself. It's been load-tested but only at small scale.

License: MIT. Founder here, AMA.

---

## r/sysadmin

**Title:**
> Catching zero-day phishing at the DNS layer without TLS interception — looking for IT feedback

**Body:**

Built XGenGuardian for the case where you want phishing protection but don't want to install a root CA on every endpoint to run a TLS-intercepting proxy.

It's a DoH/DoT resolver with a brain:
- Real-time Certificate Transparency log monitoring — flags brand-lookalike certs at issuance time
- Sandboxed page render + CLIP visual brand-impersonation detection
- Identity-mismatch fusion (looks like Brand X + isn't on Brand X's infrastructure → block)
- Per-block evidence page IT can audit when a user complains

Deploys via a DNS setting; no Group Policy MSI to push, no endpoint agent (yet). Multi-tenant admin console with SSO/SCIM is Phase-3 (ETA Q3). Open API for SIEM ingestion.

Pricing for org use:
- Pro $3/user/mo — admin console, policies, logs
- Business $8/user/mo — SSO/SCIM, SIEM, SLA
- Enterprise: dedicated PoPs, premium intel, SWG integration via ICAP

Comparing yourself to Zscaler / Cloudflare One? We don't replace them. We pair with them — our verdict API is callable from existing SWGs. The pitch is: "catch the phishing your current SWG misses, especially the zero-day visual lookalikes."

Demo: https://report.xgenguardian.com
Architecture (for the IT decision-maker): https://xgenguardian.com/architecture

Looking specifically for IT feedback:
- What would block you from trialing this in an org of 100–1000 seats?
- Are TLS-interception products giving you grief on cert-pinned apps (Slack, banking, Teams)?
- Where do you currently spend the most analyst time on phishing triage?

Founder, will answer all day.
