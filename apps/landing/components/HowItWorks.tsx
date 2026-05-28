const steps = [
  {
    n: "01",
    title: "Set your DNS",
    body:
      "Point your device or router at our DoH endpoint. One setting. 30 seconds. Works on Windows, macOS, Linux, iOS, Android, and every modern browser.",
  },
  {
    n: "02",
    title: "We watch every cert",
    body:
      "Our Certificate Transparency monitor scans every TLS certificate issued worldwide and pre-renders any domain that visually impersonates a brand we protect — before anyone visits it.",
  },
  {
    n: "03",
    title: "Block + explain",
    body:
      "When you click a malicious link, we return a sinkhole. Your browser lands on an evidence page: screenshot, similarity score, domain age, infrastructure, LLM explanation. No mystery.",
  },
  {
    n: "04",
    title: "Your dashboard",
    body:
      "Every site you visit shows up in your personal dashboard, color-coded. Click any block to see exactly why. Export, share, or report a mistake — your data stays yours.",
  },
];

export default function HowItWorks() {
  return (
    <section id="how" style={{ padding: "80px 24px", borderTop: "1px solid #1a1f2c" }}>
      <div style={{ maxWidth: 1200, margin: "0 auto" }}>
        <h2 style={{ fontSize: 32, margin: "0 0 12px" }}>How it works.</h2>
        <p style={{ fontSize: 16, color: "#9aa3b2", margin: "0 0 48px", maxWidth: 720 }}>
          No proxy. No root CA. No tunneled traffic. Just smarter DNS.
        </p>
        <ol style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 18, gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
          {steps.map((s) => (
            <li key={s.n} style={{ padding: 24, border: "1px solid #1f2330", borderRadius: 12 }}>
              <div style={{ color: "#5e8bff", fontSize: 14, fontWeight: 700, letterSpacing: 1 }}>{s.n}</div>
              <h3 style={{ fontSize: 18, margin: "8px 0 8px" }}>{s.title}</h3>
              <p style={{ fontSize: 14, color: "#bcc3d0", margin: 0 }}>{s.body}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
