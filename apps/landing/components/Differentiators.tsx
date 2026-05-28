const items = [
  {
    title: "Catches zero-day lookalikes",
    body:
      "Visual brand-impersonation detection at DNS speed. If a page looks like PayPal but isn't on PayPal's infrastructure, we block it — even when the domain was registered an hour ago and no blocklist has seen it.",
    metric: "+65 pts recall vs. NextDNS on <24h phishing",
  },
  {
    title: "Pre-victim detection",
    body:
      "We watch every TLS certificate issued worldwide in real time. The moment a brand-lookalike cert appears, we scan the page — usually hours before the first user clicks it.",
    metric: "Certificate Transparency firehose, always on",
  },
  {
    title: "Every block, explained",
    body:
      "When we block something, you get the sandboxed screenshot, the visual-similarity score, the domain age, the host ASN, the form-action target, and a plain-English LLM explanation. Yours to inspect.",
    metric: "Per-URL transparency portal",
  },
];

export default function Differentiators() {
  return (
    <section style={{ padding: "80px 24px", borderTop: "1px solid #1a1f2c", background: "#0c0f17" }}>
      <div style={{ maxWidth: 1200, margin: "0 auto" }}>
        <h2 style={{ fontSize: 32, margin: "0 0 12px" }}>What blocklists can&apos;t do.</h2>
        <p style={{ fontSize: 16, color: "#9aa3b2", margin: "0 0 48px", maxWidth: 720 }}>
          Modern phishing kits live 4–6 hours. By the time PhishTank or Google Safe Browsing
          updates, the victims are already phished. We don&apos;t wait for someone else to label it.
        </p>
        <div style={{ display: "grid", gap: 18, gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
          {items.map((it) => (
            <article
              key={it.title}
              style={{
                padding: 24,
                background: "#11141d",
                border: "1px solid #1f2330",
                borderRadius: 12,
              }}
            >
              <h3 style={{ fontSize: 18, margin: "0 0 12px", color: "#fff" }}>{it.title}</h3>
              <p style={{ fontSize: 15, color: "#bcc3d0", margin: "0 0 16px" }}>{it.body}</p>
              <p style={{ fontSize: 12, color: "#5e8bff", fontWeight: 600, margin: 0, textTransform: "uppercase", letterSpacing: 0.5 }}>
                {it.metric}
              </p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
