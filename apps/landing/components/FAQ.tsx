const faqs = [
  {
    q: "Do you see all my HTTPS traffic?",
    a: "No. Default deployment is DNS-only, so we only see which domains you ask for — never the path or the page contents. When something looks suspicious, our sandbox fetches the page independently in our own infrastructure; we never mirror or decrypt your traffic.",
  },
  {
    q: "Do I have to install anything?",
    a: "No. You change one DNS setting in your OS, router, or browser. That's it. A browser extension is optional and gives you per-page evidence + tracker blocking; it doesn't intercept HTTPS.",
  },
  {
    q: "How is this different from NextDNS?",
    a: "NextDNS is a smart blocklist aggregator. We do everything NextDNS does, plus visual brand-impersonation detection, behavioral sandboxing, LLM verdict explanations, and a per-URL evidence portal — which catches phishing the blocklist-based vendors miss for hours.",
  },
  {
    q: "Will it break my banking app / Slack / Zoom?",
    a: "No. We don't intercept TLS or install a root CA. Cert-pinned apps work normally because we only operate at the DNS layer (and inside your own browser if you install the extension).",
  },
  {
    q: "What about my privacy?",
    a: "We don't sell data. We don't log queries in identifiable form unless you opt into the personal dashboard. Oblivious DoH (ODoH) is on the roadmap so even we can't link queries to users.",
  },
  {
    q: "How fast is it?",
    a: "Sub-10ms on cached lookups (95%+ of queries). 250ms for first-time domain analysis. 3–6s for the deepest sandbox+visual+LLM pass — and that only happens when something looks suspicious. Your normal browsing feels exactly like normal browsing.",
  },
  {
    q: "What about false positives?",
    a: "Less than 0.5% on legitimate top-1M sites. Every block comes with a 'Report false positive' button and a public evidence page. We unblock within 1 hour of a confirmed FP report.",
  },
  {
    q: "Is there an API?",
    a: "Yes — the same engine that powers the dashboard is available via REST API for SaaS partners (Slack, Teams, Discord, your own product). Business and Enterprise tiers include API access.",
  },
];

export default function FAQ() {
  return (
    <section style={{ padding: "80px 24px", borderTop: "1px solid #1a1f2c" }}>
      <div style={{ maxWidth: 820, margin: "0 auto" }}>
        <h2 style={{ fontSize: 32, margin: "0 0 32px" }}>Questions, honestly answered.</h2>
        <div>
          {faqs.map((f) => (
            <details key={f.q} style={{ borderBottom: "1px solid #1a1f2c", padding: "18px 0" }}>
              <summary style={{ cursor: "pointer", fontSize: 16, fontWeight: 600, color: "#e8eaed" }}>
                {f.q}
              </summary>
              <p style={{ marginTop: 12, color: "#bcc3d0", fontSize: 15 }}>{f.a}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}
