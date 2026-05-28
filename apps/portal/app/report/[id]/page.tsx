// /report/[id] — per-verdict full evidence page.
//
// Server-rendered: fetches the rich evidence bundle (with joined urls +
// domains + scan_history rows) from portal-api, and renders every signal,
// fingerprint, hosting-context value, redirect step, and the sandbox
// screenshot. Same data shape as the home-page VerdictReport but presented
// as a permanent shareable record rather than a transient on-demand scan.

type Severity = "low" | "medium" | "high" | "critical";

type Evidence = {
  evidence_id: string;
  screenshot_url?: string;
  dom_url?: string;
  har_url?: string;
  visual_top_brand?: string;
  visual_top_score?: number;
  favicon_match?: string;
  form_actions?: string[];
  signals?: Record<string, unknown>;
  reason_codes?: string[];
  llm_explanation?: string;
  created_at?: string;

  url?: string;
  domain?: string;
  final_url?: string;
  redirect_chain?: string[];
  verdict?: string;
  verdict_confidence?: number;
  grade?: string;
  page_class?: string;

  registrar?: string;
  registered_at?: string;
  expires_at?: string;
  current_asn?: number;
  cert_issuer?: string;
  cert_sha256?: string;
  brand_match?: string;
  brand_canonical?: boolean;
  reputation_score?: number;
  domain_age_days?: number;

  external?: Record<string, unknown>;
};

const REASON_TEMPLATES: Record<string, { title: string; body: string; sev: Severity }> = {
  KNOWN_PHISH_URL_MATCH: { title: "Confirmed phishing URL", body: "This exact URL is on a threat-intelligence feed of confirmed phishing pages.", sev: "critical" },
  KNOWN_MALWARE_DOMAIN_MATCH: { title: "Confirmed malware domain", body: "Confirmed-malware threat feed entry.", sev: "critical" },
  BRAND_CLAIM_DOMAIN_MISMATCH: { title: "Brand impersonation", body: "Visually matches a protected brand on a non-canonical domain.", sev: "critical" },
  FAVICON_BRAND_MISMATCH: { title: "Favicon impersonates a brand", body: "Favicon matches a protected brand on a non-canonical domain.", sev: "high" },
  TITLE_FAVICON_BRAND_IMPERSONATION: { title: "Title + favicon impersonation", body: "Both title and favicon imitate a protected brand.", sev: "high" },
  LOGIN_FORM_ON_UNAPPROVED_DOMAIN: { title: "Login form on unverified domain", body: "Credential collection on a domain not approved for the brand it claims.", sev: "high" },
  FORM_POSTS_TO_UNRELATED_DOMAIN: { title: "Cross-origin credential post", body: "Password form submits to an unrelated domain.", sev: "high" },
  SUSPICIOUS_REDIRECT_CHAIN: { title: "Suspicious redirect chain", body: "Redirected through multiple hops.", sev: "medium" },
  HOMOGLYPH_OF_PROTECTED_BRAND: { title: "Lookalike domain", body: "Character-substitution attack against a protected brand.", sev: "high" },
  DOMAIN_AGE_UNDER_THRESHOLD: { title: "Recently registered domain", body: "New domains are commonly used for one-shot phishing.", sev: "medium" },
  CERT_DRIFT_ON_TRUSTED_PAGE: { title: "Certificate changed unexpectedly", body: "TLS certificate changed since the last successful scan.", sev: "medium" },
  SCRIPT_ORIGIN_DRIFT_ON_TRUSTED_PAGE: { title: "Script sources changed", body: "Previously-trusted page now loads scripts from new origins.", sev: "medium" },
  FORM_ACTION_DRIFT_ON_TRUSTED_PAGE: { title: "Form target changed", body: "Form on this page now submits to a different endpoint.", sev: "medium" },
  MALICIOUS_DOWNLOAD_TRIGGER: { title: "Malicious download", body: "Download matching known-malicious indicators.", sev: "critical" },
  RISKY_DOWNLOAD_LINKED: { title: "Risky download linked", body: "Page links to executable/archive downloads not verified safe.", sev: "medium" },
  POPUP_STORM_DETECTED: { title: "Popup storm", body: "Multiple windows opened without user interaction.", sev: "high" },
  ALERT_LOOP_DETECTED: { title: "Modal-dialog loop", body: "Repeated alert/confirm dialogs trap the user.", sev: "high" },
  FULLSCREEN_TRAP_DETECTED: { title: "Fullscreen trap", body: "Forced fullscreen without a user gesture.", sev: "high" },
  BEFOREUNLOAD_ABUSE: { title: "beforeunload trap", body: "Blocks navigation away from the page.", sev: "medium" },
  CLIPBOARD_HIJACK_ATTEMPT: { title: "Clipboard tampering", body: "Page wrote to clipboard without consent (ClickFix).", sev: "high" },
  AUTO_DOWNLOAD_TRIGGER: { title: "Drive-by download", body: "Download started with no user click.", sev: "high" },
  FAKE_SUPPORT_SCAREWARE: { title: "Fake tech-support page", body: "Multiple scareware patterns combined.", sev: "critical" },
  BLOCKED_OPENER_LINEAGE: { title: "Opened by a blocked page", body: "Parent page was already blocked.", sev: "high" },
  UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER: { title: "Unknown target from suspicious opener", body: "Suspicious page opened this never-before-seen URL.", sev: "medium" },
  EXTERNAL_FEED_HIT: { title: "External feed hit", body: "External threat-intel source flagged this URL/domain.", sev: "high" },
  GOOGLE_WEB_RISK_UNSAFE: { title: "Google Web Risk: unsafe", body: "Web Risk reports this URL as unsafe.", sev: "high" },
  VIRUSTOTAL_POSITIVE: { title: "VirusTotal detections", body: "AV engines on VirusTotal flag this URL/file.", sev: "high" },
  YARA_SIGNATURE_MATCH: { title: "YARA signature match", body: "Matches a known-malicious YARA signature.", sev: "high" },
  SUBDOMAIN_TAKEOVER_RISK: { title: "Possible subdomain takeover", body: "CNAME target appears unclaimed.", sev: "high" },
  CLOAKING_DIVERGENCE: { title: "Server-side cloaking", body: "Different content served to different network locations.", sev: "high" },
  OAUTH_UNKNOWN_CLIENT_ID: { title: "Unknown OAuth application", body: "OAuth consent for an unknown app requesting sensitive scopes.", sev: "high" },
  HTML_SMUGGLING_PATTERN: { title: "HTML smuggling", body: "Payload reassembled client-side — evasion pattern.", sev: "high" },
  DGA_CLASSIFIER_HIT: { title: "Algorithmically-generated domain", body: "Domain matches malware C2 DGA pattern.", sev: "medium" },
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
  BLOCK: "#ff4d4f", WARN: "#faad14", ISOLATE: "#5e8bff",
  ALLOW: "#52c41a", CLEAN: "#52c41a", ANALYZING: "#888",
};

async function getEvidence(id: string): Promise<Evidence | null> {
  const base = process.env.PORTAL_API_URL ?? "http://localhost:18081";
  try {
    const r = await fetch(`${base}/v1/evidence/${id}`, { cache: "no-store" });
    if (!r.ok) return null;
    return (await r.json()) as Evidence;
  } catch {
    return null;
  }
}

export default async function ReportPage({ params }: { params: { id: string } }) {
  const e = await getEvidence(params.id);
  if (!e) {
    return (
      <article>
        <h1>Evidence not found</h1>
        <p style={{ color: "#9aa3b2" }}>
          Either the ID is wrong or this scan was rotated out of retention.
        </p>
      </article>
    );
  }
  const verdictColor = e.verdict ? VERDICT_COLOR[e.verdict] ?? "#888" : "#888";

  return (
    <article>
      <p style={{ color: "#6f7787", fontSize: 12, fontFamily: "ui-monospace, Menlo, monospace" }}>
        Evidence ID: {e.evidence_id}
      </p>
      <h1 style={{ margin: "4px 0 12px", fontSize: 28 }}>
        {e.url ?? "Scan report"}
      </h1>

      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        {e.verdict && <span style={pill(verdictColor)}>{e.verdict}</span>}
        {e.grade && <span style={pill("#2a3142", "#cfd4dd")}>Grade {e.grade}</span>}
        {typeof e.verdict_confidence === "number" && (
          <span style={{ color: "#9aa3b2", fontSize: 13 }}>
            confidence {Math.round(e.verdict_confidence * 100)}%
          </span>
        )}
        {e.page_class && e.page_class !== "generic" && (
          <span style={pill("#1a2436", "#bcc3d0")}>{e.page_class} page</span>
        )}
        {e.created_at && (
          <span style={{ color: "#6f7787", fontSize: 12 }}>
            scanned {new Date(e.created_at).toLocaleString()}
          </span>
        )}
      </div>

      <Section title="Where it failed">
        {e.reason_codes && e.reason_codes.length > 0 ? (
          e.reason_codes.map((c) => <ReasonCard key={c} code={c} />)
        ) : (
          <Empty>No reason codes attached.</Empty>
        )}
      </Section>

      <Section title="Page identity">
        {e.url && <KV label="URL" value={e.url} mono />}
        {e.final_url && e.final_url !== e.url && <KV label="Final URL" value={e.final_url} mono />}
        {e.redirect_chain && e.redirect_chain.length > 0 && (
          <KV label="Redirect chain" valueNode={<RedirectChain steps={e.redirect_chain} />} />
        )}
        {e.visual_top_brand && (
          <KV
            label="Visually similar to"
            value={`${e.visual_top_brand} · ${Math.round((e.visual_top_score ?? 0) * 100)}%`}
          />
        )}
        {e.favicon_match && <KV label="Favicon matches" value={e.favicon_match} />}
      </Section>

      <Section title="Hosting + identity">
        {e.domain && <KV label="Domain" value={e.domain} mono />}
        {e.registrar && <KV label="Registrar" value={e.registrar} />}
        {typeof e.domain_age_days === "number" && (
          <KV label="Domain age" value={formatAge(e.domain_age_days)} />
        )}
        {e.registered_at && <KV label="Registered" value={new Date(e.registered_at).toDateString()} />}
        {e.expires_at && <KV label="Expires" value={new Date(e.expires_at).toDateString()} />}
        {e.current_asn && <KV label="Hosting ASN" value={`AS${e.current_asn}`} />}
        {e.cert_issuer && <KV label="TLS issuer" value={e.cert_issuer} />}
        {e.cert_sha256 && <KV label="Cert SHA-256" value={e.cert_sha256} mono />}
        {typeof e.reputation_score === "number" && (
          <KV label="Reputation score" value={e.reputation_score.toFixed(2)} />
        )}
        {e.external && Object.keys(e.external).length > 0 && (
          <KV label="External feeds" valueNode={<ExternalTags external={e.external} />} />
        )}
      </Section>

      {e.form_actions && e.form_actions.length > 0 && (
        <Section title="Form actions extracted">
          <div style={panel()}>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {e.form_actions.map((a, i) => (
                <li
                  key={i}
                  style={{ fontFamily: "ui-monospace, Menlo, monospace", fontSize: 13 }}
                >
                  {a}
                </li>
              ))}
            </ul>
          </div>
        </Section>
      )}

      {e.screenshot_url && (
        <Section title="Sandbox screenshot">
          <img
            src={e.screenshot_url}
            alt=""
            style={{
              width: "100%",
              maxHeight: 640,
              objectFit: "contain",
              background: "#06080c",
              border: "1px solid #2a3142",
              borderRadius: 8,
            }}
          />
        </Section>
      )}

      {e.llm_explanation && (
        <Section title="Narrative">
          <p style={{ color: "#bcc3d0", lineHeight: 1.55, whiteSpace: "pre-wrap" }}>
            {e.llm_explanation}
          </p>
        </Section>
      )}

      {(e.dom_url || e.har_url) && (
        <Section title="Artifacts">
          {e.dom_url && (
            <a href={e.dom_url} style={{ color: "#5e8bff", marginRight: 16 }}>
              DOM snapshot →
            </a>
          )}
          {e.har_url && <a href={e.har_url} style={{ color: "#5e8bff" }}>Network HAR →</a>}
        </Section>
      )}
    </article>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 28 }}>
      <h2 style={{ fontSize: 13, textTransform: "uppercase", letterSpacing: 0.6, color: "#9aa3b2", margin: "0 0 8px" }}>
        {title}
      </h2>
      {children}
    </div>
  );
}

function ReasonCard({ code }: { code: string }) {
  const meta = REASON_TEMPLATES[code] ?? { title: code, body: "Detector triggered (no description registered).", sev: "medium" as Severity };
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
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "180px 1fr",
        gap: 12,
        padding: "8px 0",
        borderTop: "1px solid #1a1f2c",
      }}
    >
      <span style={{ color: "#9aa3b2", fontSize: 12, textTransform: "uppercase", letterSpacing: 0.5 }}>
        {label}
      </span>
      {valueNode ? (
        valueNode
      ) : (
        <span
          style={{
            fontFamily: mono ? "ui-monospace, Menlo, monospace" : "inherit",
            fontSize: mono ? 13 : 14,
            wordBreak: "break-all",
          }}
        >
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
        <div
          key={i}
          style={{
            padding: "4px 0",
            fontFamily: "ui-monospace, Menlo, monospace",
            fontSize: 13,
          }}
        >
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
