const rows: { feature: string; quad9: string; nextdns: string; cf: string; xgg: string }[] = [
  { feature: "Encrypted DNS (DoH/DoT)",                  quad9: "✓", nextdns: "✓", cf: "✓", xgg: "✓" },
  { feature: "DNSSEC validation",                        quad9: "✓", nextdns: "✓", cf: "✓", xgg: "✓" },
  { feature: "Known-phishing blocklists",                quad9: "✓", nextdns: "✓", cf: "✓", xgg: "✓" },
  { feature: "Newly-Registered-Domain filter",           quad9: "—", nextdns: "✓", cf: "partial", xgg: "✓" },
  { feature: "Tracker / fingerprint blocking",           quad9: "—", nextdns: "✓", cf: "partial", xgg: "✓" },
  { feature: "Per-user dashboard",                       quad9: "—", nextdns: "✓", cf: "—",      xgg: "✓✓" },
  { feature: "Pre-victim CT-log scanning",               quad9: "—", nextdns: "—", cf: "—",      xgg: "✓" },
  { feature: "Sandboxed page render for unknowns",       quad9: "—", nextdns: "—", cf: "—",      xgg: "✓" },
  { feature: "Visual brand-impersonation detection",     quad9: "—", nextdns: "—", cf: "—",      xgg: "✓" },
  { feature: "Identity-mismatch fusion (zero-day phish)", quad9: "—", nextdns: "—", cf: "—",     xgg: "✓" },
  { feature: "Multi-egress cloaking diff",               quad9: "—", nextdns: "—", cf: "—",      xgg: "✓" },
  { feature: "Behavioral sandbox + canary creds",        quad9: "—", nextdns: "—", cf: "—",      xgg: "✓" },
  { feature: "LLM verdict explanations",                 quad9: "—", nextdns: "—", cf: "—",      xgg: "✓" },
  { feature: "Per-URL transparency portal",              quad9: "—", nextdns: "—", cf: "—",      xgg: "✓" },
];

export default function Comparison() {
  return (
    <section id="vs" style={{ padding: "80px 24px", borderTop: "1px solid #1a1f2c", background: "#0c0f17" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <h2 style={{ fontSize: 32, margin: "0 0 12px" }}>vs. NextDNS, Quad9, Cloudflare 1.1.1.2</h2>
        <p style={{ fontSize: 16, color: "#9aa3b2", margin: "0 0 32px", maxWidth: 720 }}>
          We respect them all. They&apos;re fine blocklist aggregators. They cannot do what we do.
        </p>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #2a3142" }}>
                <th style={th}>Capability</th>
                <th style={th}>Quad9</th>
                <th style={th}>NextDNS</th>
                <th style={th}>Cloudflare 1.1.1.2</th>
                <th style={{ ...th, color: "#5e8bff" }}>XGenGuardian</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={r.feature} style={{ background: i % 2 ? "transparent" : "#11141d" }}>
                  <td style={td}>{r.feature}</td>
                  <td style={tdMark}>{r.quad9}</td>
                  <td style={tdMark}>{r.nextdns}</td>
                  <td style={tdMark}>{r.cf}</td>
                  <td style={{ ...tdMark, color: r.xgg === "—" ? "#6f7787" : "#5e8bff", fontWeight: 600 }}>{r.xgg}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p style={{ fontSize: 13, color: "#6f7787", marginTop: 18 }}>
          Sources: vendor product pages and our internal eval, as of {new Date().getFullYear()}. We&apos;ll
          happily correct any item with documentation.
        </p>
      </div>
    </section>
  );
}

const th: React.CSSProperties = {
  textAlign: "left",
  padding: "12px 16px",
  fontWeight: 600,
  fontSize: 13,
  color: "#cfd4dd",
  textTransform: "uppercase",
  letterSpacing: 0.5,
};
const td: React.CSSProperties = { padding: "10px 16px", color: "#bcc3d0", borderBottom: "1px solid #1a1f2c" };
const tdMark: React.CSSProperties = { ...td, textAlign: "center", color: "#9aa3b2", fontFamily: "monospace" };
