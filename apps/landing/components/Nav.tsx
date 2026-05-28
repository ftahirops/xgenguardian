export default function Nav() {
  return (
    <header
      style={{
        position: "sticky",
        top: 0,
        zIndex: 50,
        backdropFilter: "blur(8px)",
        background: "rgba(10, 12, 17, 0.85)",
        borderBottom: "1px solid #1a1f2c",
      }}
    >
      <div style={container({ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 24px" })}>
        <a href="/" style={{ color: "inherit", textDecoration: "none", fontWeight: 700, fontSize: 18 }}>
          XGen<span style={{ color: "#5e8bff" }}>Guardian</span>
        </a>
        <nav style={{ display: "flex", gap: 22, fontSize: 14 }}>
          <a href="#how"  style={link}>How it works</a>
          <a href="#vs"   style={link}>vs. NextDNS / Quad9</a>
          <a href="#pricing" style={link}>Pricing</a>
          <a href="https://report.xgenguardian.com" style={link}>Check a URL</a>
          <a
            href="#get-started"
            style={{
              ...link,
              background: "#5e8bff",
              color: "white",
              padding: "6px 14px",
              borderRadius: 6,
              fontWeight: 600,
            }}
          >
            Get started — free
          </a>
        </nav>
      </div>
    </header>
  );
}

const link = { color: "#cfd4dd", textDecoration: "none" };
const container = (extra: React.CSSProperties = {}) => ({ maxWidth: 1200, margin: "0 auto", ...extra });
