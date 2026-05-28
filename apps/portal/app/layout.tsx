import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "XGenGuardian — Transparency Portal",
  description: "Check any URL. See the evidence. Block what blocklists miss.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          fontFamily: "system-ui, -apple-system, sans-serif",
          margin: 0,
          background: "#0b0d12",
          color: "#e8eaed",
        }}
      >
        <header
          style={{
            padding: "16px 24px",
            borderBottom: "1px solid #1f2330",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <strong>XGenGuardian</strong>
          <nav style={{ fontSize: 14, opacity: 0.7 }}>
            <a href="/" style={{ color: "inherit", marginRight: 16 }}>Check URL</a>
            <a href="/about" style={{ color: "inherit" }}>About</a>
          </nav>
        </header>
        <main style={{ maxWidth: 960, margin: "0 auto", padding: "32px 24px" }}>{children}</main>
      </body>
    </html>
  );
}
