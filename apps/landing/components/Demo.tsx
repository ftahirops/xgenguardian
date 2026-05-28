export default function Demo() {
  return (
    <section style={{ padding: "80px 24px", borderTop: "1px solid #1a1f2c" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <h2 style={{ fontSize: 32, margin: "0 0 12px" }}>See it catch a fresh phishing site, live.</h2>
        <p style={{ fontSize: 16, color: "#9aa3b2", margin: "0 0 32px", maxWidth: 720 }}>
          Paste any URL into our Transparency Portal. We render it in a sandbox,
          compare it visually to 500+ brands, and return a verdict with full evidence.
          For research, for IT, for the curious.
        </p>

        <div style={{
          background: "#11141d",
          border: "1px solid #2a3142",
          borderRadius: 12,
          padding: 24,
        }}>
          <p style={{ margin: 0, fontSize: 14, color: "#6f7787" }}>example block, real format:</p>
          <div style={{
            marginTop: 14,
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
            fontSize: 13,
            color: "#cfd4dd",
            background: "#070a10",
            padding: 18,
            borderRadius: 8,
            border: "1px solid #1a1f2c",
            whiteSpace: "pre",
            overflowX: "auto",
          }}>
{`URL:         https://w1thineartht.com/login
Verdict:     BLOCK   (confidence 0.97)

Signals
  ■ visual_brand_match     withinearth  similarity 0.96
  ■ identity_mismatch      4d-old domain on AS12345 (non-canonical)
  ■ cert_age               cert <24h old (Let's Encrypt)
  ■ cred_form_cross_origin POST → collect.evil-c2.tk/api

Why
  Visually impersonates withinearth (0.96), but w1thineartht.com
  is not a canonical withinearth domain. Registered 4 days ago on
  infrastructure unrelated to the real brand. Credentials are
  exfiltrated to a third-party domain.

Cross-check
  Google Safe Browsing:   clean
  VirusTotal:             0/70
  Microsoft SmartScreen:  clean
  → blocked here, missed everywhere else.`}
          </div>

          <div style={{ marginTop: 22 }}>
            <a href="https://report.xgenguardian.com" style={{
              display: "inline-block",
              padding: "12px 22px",
              background: "#5e8bff",
              color: "white",
              borderRadius: 8,
              textDecoration: "none",
              fontWeight: 600,
            }}>
              Try it with your own URL →
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
