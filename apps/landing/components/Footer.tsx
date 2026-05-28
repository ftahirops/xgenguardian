export default function Footer() {
  return (
    <footer style={{ padding: "40px 24px 60px", borderTop: "1px solid #1a1f2c", background: "#070a10" }}>
      <div style={{
        maxWidth: 1200, margin: "0 auto",
        display: "grid", gap: 24,
        gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
      }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 18, marginBottom: 12 }}>
            XGen<span style={{ color: "#5e8bff" }}>Guardian</span>
          </div>
          <p style={{ fontSize: 13, color: "#6f7787", margin: 0 }}>
            Brain-first protective DNS. Catches what blocklists miss.
          </p>
        </div>

        <div>
          <h4 style={ftH}>Product</h4>
          <a href="#how"     style={ftL}>How it works</a>
          <a href="#vs"      style={ftL}>vs. NextDNS</a>
          <a href="#pricing" style={ftL}>Pricing</a>
          <a href="https://report.xgenguardian.com" style={ftL}>Try the demo</a>
        </div>

        <div>
          <h4 style={ftH}>Company</h4>
          <a href="/about"   style={ftL}>About</a>
          <a href="/blog"    style={ftL}>Blog</a>
          <a href="mailto:hello@xgenguardian.com" style={ftL}>Contact</a>
        </div>

        <div>
          <h4 style={ftH}>Trust</h4>
          <a href="/privacy"      style={ftL}>Privacy</a>
          <a href="/terms"        style={ftL}>Terms</a>
          <a href="/security"     style={ftL}>Security</a>
          <a href="/transparency" style={ftL}>Transparency reports</a>
          <a href="https://status.xgenguardian.com" style={ftL}>Status</a>
        </div>
      </div>

      <p style={{
        maxWidth: 1200, margin: "32px auto 0",
        fontSize: 12, color: "#4f5765",
      }}>
        © {new Date().getFullYear()} XGenGuardian. Made by people who got tired of clicking the wrong link.
      </p>
    </footer>
  );
}

const ftH: React.CSSProperties = {
  fontSize: 12,
  color: "#9aa3b2",
  textTransform: "uppercase",
  letterSpacing: 0.5,
  margin: "0 0 12px",
};
const ftL: React.CSSProperties = {
  display: "block",
  color: "#cfd4dd",
  textDecoration: "none",
  fontSize: 14,
  padding: "4px 0",
};
