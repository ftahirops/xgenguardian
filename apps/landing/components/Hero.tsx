export default function Hero() {
  return (
    <section style={{ padding: "96px 24px 64px", maxWidth: 1200, margin: "0 auto" }}>
      <div style={{ maxWidth: 820 }}>
        <span
          style={{
            display: "inline-block",
            padding: "4px 12px",
            background: "#1c2540",
            color: "#a8b8ff",
            fontSize: 12,
            fontWeight: 600,
            borderRadius: 999,
            letterSpacing: 0.5,
            textTransform: "uppercase",
          }}
        >
          Brain-first protective DNS
        </span>
        <h1
          style={{
            fontSize: "clamp(40px, 6vw, 68px)",
            lineHeight: 1.05,
            margin: "22px 0 18px",
            letterSpacing: -0.5,
          }}
        >
          The phishing your DNS missed.{" "}
          <span style={{ color: "#5e8bff" }}>Caught.</span>
        </h1>
        <p style={{ fontSize: 19, color: "#9aa3b2", margin: "0 0 32px", maxWidth: 700 }}>
          NextDNS and Quad9 block phishing they&apos;ve already heard of. We catch it the
          moment it appears — with visual brand-match detection at DNS speed, plus a
          screenshot and a plain-English explanation for every block.
        </p>

        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <a
            id="get-started"
            href="https://app.xgenguardian.com/signup"
            style={btnPrimary}
          >
            Get started — free
          </a>
          <a href="https://report.xgenguardian.com" style={btnGhost}>
            Try the demo →
          </a>
        </div>

        <p style={{ marginTop: 18, fontSize: 13, color: "#6f7787" }}>
          One DNS setting. No client install. No TLS interception. No credit card.
        </p>
      </div>
    </section>
  );
}

const btnPrimary: React.CSSProperties = {
  display: "inline-block",
  padding: "12px 22px",
  background: "#5e8bff",
  color: "white",
  fontWeight: 600,
  textDecoration: "none",
  borderRadius: 8,
  boxShadow: "0 0 0 1px rgba(255,255,255,0.06), 0 6px 20px -8px rgba(94,139,255,0.6)",
};

const btnGhost: React.CSSProperties = {
  display: "inline-block",
  padding: "12px 22px",
  background: "transparent",
  color: "#cfd4dd",
  fontWeight: 500,
  textDecoration: "none",
  borderRadius: 8,
  border: "1px solid #2a3142",
};
