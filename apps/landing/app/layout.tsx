import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "XGenGuardian — The phishing your DNS missed. Caught.",
  description:
    "Brain-first protective DNS. Catches zero-day phishing that NextDNS, Quad9, and Cloudflare miss — with full per-URL evidence for every block.",
  openGraph: {
    title: "XGenGuardian",
    description: "The phishing your DNS missed. Caught.",
    url: "https://xgenguardian.com",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          fontFamily:
            "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
          background: "#0a0c11",
          color: "#e8eaed",
          lineHeight: 1.55,
        }}
      >
        {children}
      </body>
    </html>
  );
}
