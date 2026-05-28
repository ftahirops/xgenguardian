"use client";

import { useState } from "react";

// Verdict + deep evidence shape returned by /api/check (which proxies
// verdict-api) and /api/evidence/:id (portal-api).
type Verdict = {
  verdict: "ALLOW" | "CLEAN" | "WARN" | "BLOCK" | "ISOLATE" | "ANALYZING";
  confidence: number;
  evidence_id?: string;
  visual_top_brand?: string;
  visual_top_score?: number;
  signals?: { name: string; weight: number; detail: string }[];
  reason_codes?: string[];
  llm_explanation?: string;
  block_reason?: string;
  // Deep fields hydrated from /v1/evidence/:id
  url?: string;
  final_url?: string;
  redirect_chain?: string[];
  grade?: string;
  page_class?: string;
  favicon_match?: string;
  form_actions?: string[];
  registrar?: string;
  domain_age_days?: number;
  current_asn?: number;
  cert_issuer?: string;
  cert_sha256?: string;
  external?: Record<string, unknown>;
  screenshot_url?: string;
};

type Severity = "low" | "medium" | "high" | "critical";

const REASON_TEMPLATES: Record<string, { title: string; body: string; sev: Severity }> = {
  KNOWN_PHISH_URL_MATCH: { title: "Confirmed phishing URL", body: "This exact URL is on a threat-intelligence feed of confirmed phishing pages.", sev: "critical" },
  KNOWN_MALWARE_DOMAIN_MATCH: { title: "Confirmed malware domain", body: "This domain is on a confirmed-malware threat feed.", sev: "critical" },
  BRAND_CLAIM_DOMAIN_MISMATCH: { title: "Brand impersonation", body: "The page visually matches a protected brand on a non-canonical domain.", sev: "critical" },
  FAVICON_BRAND_MISMATCH: { title: "Favicon impersonates a brand", body: "Favicon matches a protected brand on a non-canonical domain.", sev: "high" },
  TITLE_FAVICON_BRAND_IMPERSONATION: { title: "Title + favicon impersonation", body: "Both title and favicon imitate a protected brand.", sev: "high" },
  LOGIN_FORM_ON_UNAPPROVED_DOMAIN: { title: "Login form on unverified domain", body: "Credential collection on a domain not approved for the brand it claims.", sev: "high" },
  FORM_POSTS_TO_UNRELATED_DOMAIN: { title: "Cross-origin credential post", body: "The password form submits to an unrelated domain.", sev: "high" },
  SUSPICIOUS_REDIRECT_CHAIN: { title: "Suspicious redirect chain", body: "The URL redirected through multiple hops.", sev: "medium" },
  HOMOGLYPH_OF_PROTECTED_BRAND: { title: "Lookalike domain", body: "Character-substitution attack against a protected brand.", sev: "high" },
  DOMAIN_AGE_UNDER_THRESHOLD: { title: "Recently registered domain", body: "New domains are commonly used for one-shot phishing.", sev: "medium" },
  CERT_DRIFT_ON_TRUSTED_PAGE: { title: "Certificate changed unexpectedly", body: "TLS certificate changed since the last successful scan.", sev: "medium" },
  SCRIPT_ORIGIN_DRIFT_ON_TRUSTED_PAGE: { title: "Script sources changed", body: "Previously-trusted page now loads scripts from new origins.", sev: "medium" },
  FORM_ACTION_DRIFT_ON_TRUSTED_PAGE: { title: "Form target changed", body: "Form on this page now submits to a different endpoint.", sev: "medium" },
  MALICIOUS_DOWNLOAD_TRIGGER: { title: "Malicious download", body: "Attempted download matching known-malicious indicators.", sev: "critical" },
  RISKY_DOWNLOAD_LINKED: { title: "Risky download linked", body: "Page links to executable or archive downloads not verified safe.", sev: "medium" },
  POPUP_STORM_DETECTED: { title: "Popup storm", body: "Multiple windows opened without user interaction.", sev: "high" },
  ALERT_LOOP_DETECTED: { title: "Modal-dialog loop", body: "Repeated alert/confirm dialogs to trap the user.", sev: "high" },
  FULLSCREEN_TRAP_DETECTED: { title: "Fullscreen trap", body: "Forced fullscreen without a user gesture.", sev: "high" },
  BEFOREUNLOAD_ABUSE: { title: "beforeunload trap", body: "Blocks navigation away from the page.", sev: "medium" },
  CLIPBOARD_HIJACK_ATTEMPT: { title: "Clipboard tampering", body: "Page wrote to the clipboard without consent (ClickFix pattern).", sev: "high" },
  AUTO_DOWNLOAD_TRIGGER: { title: "Drive-by download", body: "Download started with no user click.", sev: "high" },
  FAKE_SUPPORT_SCAREWARE: { title: "Fake tech-support page", body: "Multiple scareware patterns combined.", sev: "critical" },
  BLOCKED_OPENER_LINEAGE: { title: "Opened by a blocked page", body: "Parent page was already blocked.", sev: "high" },
  UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER: { title: "Unknown target from suspicious opener", body: "Suspicious page opened this never-before-seen URL.", sev: "medium" },
  EXTERNAL_FEED_HIT: { title: "External feed hit", body: "External threat-intel source flags this URL or domain.", sev: "high" },
  GOOGLE_WEB_RISK_UNSAFE: { title: "Google Web Risk: unsafe", body: "Google Web Risk reports this URL as unsafe.", sev: "high" },
  VIRUSTOTAL_POSITIVE: { title: "VirusTotal detections", body: "Antivirus engines on VirusTotal flag this URL or file.", sev: "high" },
  YARA_SIGNATURE_MATCH: { title: "YARA signature match", body: "Matches a known-malicious YARA signature.", sev: "high" },
  SUBDOMAIN_TAKEOVER_RISK: { title: "Possible subdomain takeover", body: "CNAME target appears unclaimed.", sev: "high" },
  CLOAKING_DIVERGENCE: { title: "Server-side cloaking", body: "Different content served to different network locations.", sev: "high" },
  OAUTH_UNKNOWN_CLIENT_ID: { title: "Unknown OAuth application", body: "OAuth consent for an unknown application requesting sensitive scopes.", sev: "high" },
  HTML_SMUGGLING_PATTERN: { title: "HTML smuggling", body: "Payload reassembled client-side — evasion pattern.", sev: "high" },
  DGA_CLASSIFIER_HIT: { title: "Algorithmically-generated domain", body: "Domain pattern matches malware command-and-control DGA.", sev: "medium" },
  MINER_POOL_CONTACT: { title: "Cryptocurrency miner", body: "Contacts a known mining pool.", sev: "medium" },
  BLOCKED_BY_STRICTNESS_POLICY: { title: "Executive Mode policy", body: "This URL did not meet your trust threshold.", sev: "low" },
  ISOLATED_SENSITIVE_PAGE_CLASS: { title: "Sensitive page opened in isolation", body: "Login/payment/OAuth on an unverified domain — isolated by default.", sev: "low" },
};

const SEV_COLOR: Record<Severity, string> = {
  low: "#5e8bff",
  medium: "#faad14",
  high: "#ff8c8c",
  critical: "#ff4d4f",
};

const VERDICT_COLOR: Record<string, string> = {
  BLOCK:     "#ff4d4f",
  WARN:      "#faad14",
  ISOLATE:   "#5e8bff",
  ALLOW:     "#52c41a",
  CLEAN:     "#52c41a",
  ANALYZING: "#888",
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Verdict | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function check(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setErr(null);
    setResult(null);
    try {
      const r = await fetch("/api/check", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!r.ok) throw new Error(await r.text());
      const v: Verdict = await r.json();
      // Hydrate deep evidence if we got an ID back.
      if (v.evidence_id) {
        try {
          const e2 = await fetch(`/api/evidence/${v.evidence_id}`);
          if (e2.ok) {
            const deep = await e2.json();
            setResult({ ...v, ...deep });
            return;
          }
        } catch {
          /* fall through to setResult(v) */
        }
      }
      setResult(v);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 style={{ fontSize: 40, marginBottom: 4 }}>Check any URL.</h1>
      <p style={{ opacity: 0.75, marginTop: 0 }}>
        Submit a URL and see every signal that fires, the redirect chain, the
        hosting context, and a sandbox screenshot.
      </p>

      <form onSubmit={check} style={{ display: "flex", gap: 8, marginTop: 24 }}>
        <input
          type="url"
          required
          placeholder="https://example.com/login"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{
            flex: 1,
            padding: "12px 14px",
            background: "#11141c",
            border: "1px solid #2a3142",
            borderRadius: 8,
            color: "inherit",
            fontSize: 16,
          }}
        />
        <button
          disabled={loading}
          style={{
            padding: "12px 20px",
            background: "#4f7cff",
            border: "none",
            borderRadius: 8,
            color: "white",
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          {loading ? "Analyzing…" : "Check"}
        </button>
      </form>

      {err && <div style={{ marginTop: 24, color: "#ff6b6b" }}>Error: {err}</div>}

      {result && <VerdictReport v={result} />}
    </div>
  );
}

function VerdictReport({ v }: { v: Verdict }) {
  const verdictColor = VERDICT_COLOR[v.verdict] ?? "#888";
  return (
    <section style={{ marginTop: 32 }}>
      <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
        <span style={pill(verdictColor)}>{v.verdict}</span>
        {v.grade && <span style={pill("#2a3142", "#cfd4dd")}>Grade {v.grade}</span>}
        <span style={{ color: "#9aa3b2", fontSize: 13 }}>
          confidence {(v.confidence * 100).toFixed(0)}%
        </span>
        {v.page_class && v.page_class !== "generic" && (
          <span style={pill("#1a2436", "#bcc3d0")}>{v.page_class} page</span>
        )}
      </div>

      {v.block_reason && (
        <p style={{ marginTop: 16, color: "#bcc3d0" }}>{v.block_reason}</p>
      )}

      <Section title="Where it failed">
        {v.reason_codes && v.reason_codes.length > 0 ? (
          v.reason_codes.map((code) => <ReasonCard key={code} code={code} />)
        ) : (
          <Empty>No reason codes attached.</Empty>
        )}
      </Section>

      {v.signals && v.signals.length > 0 && (
        <Section title="Raw signal weights">
          <div style={panel()}>
            {v.signals.map((s, i) => (
              <div key={i} style={signalRow()}>
                <span style={{ flex: 1, fontFamily: "ui-monospace, Menlo, monospace", fontSize: 13 }}>
                  {s.name}
                </span>
                <span style={{ color: "#9aa3b2", fontSize: 12 }}>{s.detail}</span>
                <span style={{ color: "#cfd4dd", fontSize: 12, width: 50, textAlign: "right" }}>
                  {s.weight.toFixed(2)}
                </span>
              </div>
            ))}
          </div>
        </Section>
      )}

      <Section title="Page identity">
        <KV label="URL" value={v.url ?? "—"} mono />
        {v.final_url && v.final_url !== v.url && <KV label="Final URL" value={v.final_url} mono />}
        {v.redirect_chain && v.redirect_chain.length > 0 && (
          <KV label="Redirect chain" valueNode={<RedirectChain steps={v.redirect_chain} />} />
        )}
        {v.visual_top_brand && (
          <KV
            label="Visually similar to"
            value={`${v.visual_top_brand} · ${Math.round((v.visual_top_score ?? 0) * 100)}%`}
          />
        )}
        {v.favicon_match && <KV label="Favicon matches" value={v.favicon_match} />}
      </Section>

      <Section title="Hosting + identity">
        {v.registrar && <KV label="Registrar" value={v.registrar} />}
        {typeof v.domain_age_days === "number" && (
          <KV label="Domain age" value={formatAge(v.domain_age_days)} />
        )}
        {v.current_asn && <KV label="Hosting ASN" value={`AS${v.current_asn}`} />}
        {v.cert_issuer && <KV label="TLS issuer" value={v.cert_issuer} />}
        {v.cert_sha256 && <KV label="Cert SHA-256" value={v.cert_sha256} mono />}
        {v.external && Object.keys(v.external).length > 0 && (
          <KV label="External feeds" valueNode={<ExternalTags external={v.external} />} />
        )}
      </Section>

      {v.form_actions && v.form_actions.length > 0 && (
        <Section title="Form actions extracted">
          <div style={panel()}>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {v.form_actions.map((a, i) => (
                <li key={i} style={{ fontFamily: "ui-monospace, Menlo, monospace", fontSize: 13 }}>
                  {a}
                </li>
              ))}
            </ul>
          </div>
        </Section>
      )}

      {v.screenshot_url && (
        <Section title="Sandbox screenshot">
          <img
            src={v.screenshot_url}
            alt="Sandbox screenshot"
            style={{
              width: "100%",
              maxHeight: 480,
              objectFit: "contain",
              background: "#06080c",
              border: "1px solid #2a3142",
              borderRadius: 8,
            }}
          />
        </Section>
      )}

      {v.evidence_id && (
        <p style={{ marginTop: 24, fontSize: 12, color: "#6f7787" }}>
          Evidence ID: <span style={{ fontFamily: "ui-monospace, Menlo, monospace" }}>{v.evidence_id}</span>
          {" · "}
          <a href={`/report/${v.evidence_id}`} style={{ color: "#5e8bff" }}>open full report →</a>
        </p>
      )}
    </section>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 24 }}>
      <h2
        style={{
          fontSize: 13,
          textTransform: "uppercase",
          letterSpacing: 0.6,
          color: "#9aa3b2",
          margin: "0 0 8px",
        }}
      >
        {title}
      </h2>
      {children}
    </div>
  );
}

function ReasonCard({ code }: { code: string }) {
  const meta = REASON_TEMPLATES[code] ?? {
    title: code,
    body: "Detector triggered (no description registered).",
    sev: "medium" as Severity,
  };
  const color = SEV_COLOR[meta.sev];
  return (
    <div
      style={{
        marginTop: 8,
        padding: "12px 14px",
        background: "#11141d",
        borderLeft: `3px solid ${color}`,
        borderRadius: 6,
      }}
    >
      <div style={{ fontFamily: "ui-monospace, Menlo, monospace", fontSize: 11, color: "#6f7787", textTransform: "uppercase", letterSpacing: 0.3 }}>
        {code}
      </div>
      <div style={{ fontWeight: 600, marginTop: 4, fontSize: 15 }}>{meta.title}</div>
      <div style={{ color: "#bcc3d0", fontSize: 13, marginTop: 4 }}>{meta.body}</div>
    </div>
  );
}

function KV({
  label,
  value,
  valueNode,
  mono,
}: {
  label: string;
  value?: string;
  valueNode?: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "180px 1fr", gap: 12, padding: "8px 0", borderTop: "1px solid #1a1f2c" }}>
      <span style={{ color: "#9aa3b2", fontSize: 12, textTransform: "uppercase", letterSpacing: 0.5 }}>
        {label}
      </span>
      {valueNode ? (
        valueNode
      ) : (
        <span style={{ fontFamily: mono ? "ui-monospace, Menlo, monospace" : "inherit", fontSize: mono ? 13 : 14, wordBreak: "break-all" }}>
          {value}
        </span>
      )}
    </div>
  );
}

function RedirectChain({ steps }: { steps: string[] }) {
  return (
    <div>
      {steps.map((s, i) => (
        <div key={i} style={{ padding: "4px 0", fontFamily: "ui-monospace, Menlo, monospace", fontSize: 13 }}>
          {i > 0 && <span style={{ color: "#5e8bff", marginRight: 6 }}>↓</span>}
          {s}
        </div>
      ))}
    </div>
  );
}

function ExternalTags({ external }: { external: Record<string, unknown> }) {
  return (
    <div>
      {Object.entries(external).map(([k, v]) => (
        <span
          key={k}
          style={{
            display: "inline-block",
            padding: "2px 8px",
            margin: "2px 4px 2px 0",
            background: "#2a1a1a",
            color: "#ff8c8c",
            borderRadius: 4,
            fontFamily: "ui-monospace, Menlo, monospace",
            fontSize: 11,
          }}
        >
          {k}: {typeof v === "object" ? JSON.stringify(v) : String(v)}
        </span>
      ))}
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p style={{ color: "#6f7787", fontStyle: "italic", fontSize: 13 }}>{children}</p>;
}

function panel(): React.CSSProperties {
  return {
    padding: "12px 16px",
    background: "#11141d",
    border: "1px solid #2a3142",
    borderRadius: 8,
  };
}

function signalRow(): React.CSSProperties {
  return {
    display: "flex",
    alignItems: "center",
    gap: 12,
    padding: "6px 0",
    borderTop: "1px solid #1a1f2c",
  };
}

function pill(bg: string, color: string = "white"): React.CSSProperties {
  return {
    background: bg,
    color,
    padding: "4px 12px",
    borderRadius: 999,
    fontSize: 12,
    fontWeight: 700,
    letterSpacing: 0.5,
    textTransform: "uppercase",
  };
}

function formatAge(days: number): string {
  if (days < 1) return "less than a day";
  if (days < 30) return `${days} day${days === 1 ? "" : "s"}`;
  if (days < 365) return `${Math.floor(days / 30)} month${days < 60 ? "" : "s"}`;
  return `${Math.floor(days / 365)} year${days < 730 ? "" : "s"}`;
}
