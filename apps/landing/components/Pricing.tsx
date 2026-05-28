const tiers = [
  {
    name: "Free",
    price: "$0",
    sub: "forever",
    bullets: [
      "DoH endpoint + blocklists + NRD",
      "Personal dashboard",
      "Per-URL evidence pages",
      "Up to 50k queries/month",
    ],
    cta: "Get started",
    href: "https://app.xgenguardian.com/signup?plan=free",
    highlight: false,
  },
  {
    name: "Plus",
    price: "$2.99",
    sub: "per month",
    bullets: [
      "Everything in Free",
      "Visual brand-impersonation detection",
      "Behavioral sandbox + LLM explanations",
      "Mobile DoH profile (iOS / Android)",
      "Unlimited queries",
    ],
    cta: "Start 14-day trial",
    href: "https://app.xgenguardian.com/signup?plan=plus",
    highlight: true,
  },
  {
    name: "Family",
    price: "$5.99",
    sub: "per month · up to 6 profiles",
    bullets: [
      "Everything in Plus",
      "Parental control profiles",
      "Per-child reports",
      "Block scheduling",
    ],
    cta: "Start 14-day trial",
    href: "https://app.xgenguardian.com/signup?plan=family",
    highlight: false,
  },
  {
    name: "Business",
    price: "$8",
    sub: "per user / month",
    bullets: [
      "Everything in Plus",
      "Multi-tenant admin + policies",
      "SSO (SAML / OIDC) + SCIM",
      "SIEM integration",
      "99.9% SLA",
    ],
    cta: "Talk to sales",
    href: "mailto:sales@xgenguardian.com",
    highlight: false,
  },
];

export default function Pricing() {
  return (
    <section id="pricing" style={{ padding: "80px 24px", borderTop: "1px solid #1a1f2c", background: "#0c0f17" }}>
      <div style={{ maxWidth: 1200, margin: "0 auto" }}>
        <h2 style={{ fontSize: 32, margin: "0 0 12px" }}>Honest pricing.</h2>
        <p style={{ fontSize: 16, color: "#9aa3b2", margin: "0 0 48px", maxWidth: 720 }}>
          The free tier is genuinely useful. The brain — visual match, LLM explanations,
          and behavioral sandbox — lives in Plus and above.
        </p>

        <div style={{ display: "grid", gap: 18, gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
          {tiers.map((t) => (
            <div
              key={t.name}
              style={{
                padding: 24,
                background: t.highlight ? "#13192a" : "#11141d",
                border: t.highlight ? "1px solid #5e8bff" : "1px solid #1f2330",
                borderRadius: 12,
                position: "relative",
              }}
            >
              {t.highlight && (
                <span style={{
                  position: "absolute",
                  top: -10,
                  left: 18,
                  background: "#5e8bff",
                  color: "white",
                  padding: "2px 10px",
                  fontSize: 11,
                  fontWeight: 700,
                  borderRadius: 999,
                  letterSpacing: 0.5,
                  textTransform: "uppercase",
                }}>
                  Most popular
                </span>
              )}
              <h3 style={{ fontSize: 16, color: "#cfd4dd", margin: "0 0 8px" }}>{t.name}</h3>
              <div style={{ marginBottom: 16 }}>
                <span style={{ fontSize: 32, fontWeight: 700 }}>{t.price}</span>{" "}
                <span style={{ fontSize: 13, color: "#9aa3b2" }}>{t.sub}</span>
              </div>
              <ul style={{ listStyle: "none", padding: 0, margin: "0 0 22px", fontSize: 14, color: "#bcc3d0" }}>
                {t.bullets.map((b) => (
                  <li key={b} style={{ marginBottom: 8 }}>
                    <span style={{ color: "#5e8bff", marginRight: 6 }}>✓</span>{b}
                  </li>
                ))}
              </ul>
              <a
                href={t.href}
                style={{
                  display: "block",
                  textAlign: "center",
                  padding: "10px 14px",
                  background: t.highlight ? "#5e8bff" : "transparent",
                  border: t.highlight ? "none" : "1px solid #2a3142",
                  color: t.highlight ? "white" : "#cfd4dd",
                  textDecoration: "none",
                  borderRadius: 6,
                  fontWeight: 600,
                  fontSize: 14,
                }}
              >
                {t.cta}
              </a>
            </div>
          ))}
        </div>

        <p style={{ marginTop: 32, fontSize: 13, color: "#6f7787" }}>
          Enterprise? Dedicated PoPs, premium intel feeds, SWG-mode integration.{" "}
          <a href="mailto:sales@xgenguardian.com" style={{ color: "#5e8bff" }}>Contact sales →</a>
        </p>
      </div>
    </section>
  );
}
