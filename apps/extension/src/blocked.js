// blocked.js — runs inside blocked.html.
//
// Reads the URL params the background passed (?u, ?r, ?e, ?b, ?s, ?c) and,
// if an evidence_id is present, fetches the deep evidence bundle from
// portal-api so we can render every signal that fired, the redirect chain,
// hosting context, screenshot, and external corroborators.
//
// Falls back to URL-param data when portal-api is unreachable so the page
// still tells the user *why* even without server access.
//
// All DOM mutation uses createElement + textContent — no innerHTML — because
// the evidence payload (especially reason codes from URL params) is
// attacker-influenceable and this is a security UI.

// Reason-code → human template. Kept in sync with
// services/verdict-api/internal/reasons/reasons.go.
const REASONS = {
  KNOWN_PHISH_URL_MATCH: { title: "Confirmed phishing URL", body: "This exact URL is on a threat-intelligence feed of confirmed phishing pages.", sev: "critical" },
  KNOWN_MALWARE_DOMAIN_MATCH: { title: "Confirmed malware domain", body: "This domain is on a threat-intelligence feed of confirmed malware-distribution hosts.", sev: "critical" },
  BRAND_CLAIM_DOMAIN_MISMATCH: { title: "Page impersonates a known brand", body: "The page visually matches a protected brand but the domain is not owned by that brand.", sev: "critical" },
  FAVICON_BRAND_MISMATCH: { title: "Favicon impersonates a brand", body: "The page favicon matches a protected brand on a non-canonical domain.", sev: "high" },
  TITLE_FAVICON_BRAND_IMPERSONATION: { title: "Title + favicon brand impersonation", body: "Both the title and favicon imitate a protected brand on a non-canonical domain.", sev: "high" },
  LOGIN_FORM_ON_UNAPPROVED_DOMAIN: { title: "Login form on unverified domain", body: "This page collects credentials but is not on an approved domain for the brand it claims.", sev: "high" },
  FORM_POSTS_TO_UNRELATED_DOMAIN: { title: "Credentials posted to a third-party domain", body: "The password form submits to a domain unrelated to the page's own.", sev: "high" },
  SUSPICIOUS_REDIRECT_CHAIN: { title: "Suspicious redirect chain", body: "This URL redirected through multiple hops before reaching its destination.", sev: "medium" },
  HOMOGLYPH_OF_PROTECTED_BRAND: { title: "Lookalike domain", body: "This domain visually imitates a protected brand using character substitution.", sev: "high" },
  DOMAIN_AGE_UNDER_THRESHOLD: { title: "Domain registered recently", body: "New domains are often used for one-shot phishing.", sev: "medium" },
  CERT_DRIFT_ON_TRUSTED_PAGE: { title: "Certificate changed unexpectedly", body: "The TLS certificate for this page changed since the last successful scan.", sev: "medium" },
  SCRIPT_ORIGIN_DRIFT_ON_TRUSTED_PAGE: { title: "Script sources changed", body: "This previously-trusted page now loads scripts from origins it did not use before.", sev: "medium" },
  FORM_ACTION_DRIFT_ON_TRUSTED_PAGE: { title: "Form target changed", body: "The form on this page now submits to a different endpoint than before.", sev: "medium" },
  MALICIOUS_DOWNLOAD_TRIGGER: { title: "Malicious download detected", body: "This page attempted to start a download matching known-malicious indicators.", sev: "critical" },
  RISKY_DOWNLOAD_LINKED: { title: "Risky download linked", body: "This page links to executable or archive downloads that could not be verified safe.", sev: "medium" },
  POPUP_STORM_DETECTED: { title: "Popup storm", body: "This page tried to open multiple windows without user interaction.", sev: "high" },
  ALERT_LOOP_DETECTED: { title: "Modal-dialog loop", body: "This page repeatedly triggers alert or confirm dialogs to trap the user.", sev: "high" },
  FULLSCREEN_TRAP_DETECTED: { title: "Fullscreen trap", body: "This page forced fullscreen without a user gesture — a scareware pattern.", sev: "high" },
  BEFOREUNLOAD_ABUSE: { title: "beforeunload trap", body: "This page blocks navigation away from itself, a common scam pattern.", sev: "medium" },
  CLIPBOARD_HIJACK_ATTEMPT: { title: "Clipboard tampering", body: "This page wrote to the user's clipboard without consent — a ClickFix pattern.", sev: "high" },
  AUTO_DOWNLOAD_TRIGGER: { title: "Drive-by download", body: "This page started a download with no user click.", sev: "high" },
  FAKE_SUPPORT_SCAREWARE: { title: "Fake tech-support page", body: "Multiple scareware patterns: popups, alerts, fullscreen, fake virus warnings.", sev: "critical" },
  BLOCKED_OPENER_LINEAGE: { title: "Opened by a blocked page", body: "The page that tried to open this URL has already been blocked by XGenGuardian.", sev: "high" },
  UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER: { title: "Unknown target from suspicious page", body: "A suspicious page tried to open this never-before-seen URL.", sev: "medium" },
  EXTERNAL_FEED_HIT: { title: "External threat-intelligence hit", body: "An external feed flags this URL or domain.", sev: "high" },
  GOOGLE_WEB_RISK_UNSAFE: { title: "Google Web Risk: unsafe", body: "Google Web Risk reports this URL as unsafe.", sev: "high" },
  VIRUSTOTAL_POSITIVE: { title: "VirusTotal detections", body: "Multiple antivirus engines on VirusTotal flag this URL or file.", sev: "high" },
  YARA_SIGNATURE_MATCH: { title: "YARA signature match", body: "The page or downloaded file matches a known-malicious YARA signature.", sev: "high" },
  SUBDOMAIN_TAKEOVER_RISK: { title: "Possible subdomain takeover", body: "This subdomain's CNAME target appears unclaimed and may be hijacked.", sev: "high" },
  CLOAKING_DIVERGENCE: { title: "Server-side cloaking", body: "The page serves different content to different network locations.", sev: "high" },
  OAUTH_UNKNOWN_CLIENT_ID: { title: "Unknown OAuth application", body: "This OAuth consent screen requests sensitive permissions for an unknown app.", sev: "high" },
  HTML_SMUGGLING_PATTERN: { title: "HTML smuggling", body: "This page reassembles a downloadable payload entirely client-side.", sev: "high" },
  DGA_CLASSIFIER_HIT: { title: "Algorithmically-generated domain", body: "This domain matches the pattern of malware command-and-control domain generation.", sev: "medium" },
  MINER_POOL_CONTACT: { title: "Cryptocurrency miner", body: "This page contacts a known cryptocurrency-mining pool.", sev: "medium" },
};

// ---------- helpers (DOM builders, all textContent-based) ----------

function el(tag, opts) {
  const e = document.createElement(tag);
  if (opts?.className) e.className = opts.className;
  if (opts?.text != null) e.textContent = opts.text;
  return e;
}

function setText(id, text) {
  const node = document.getElementById(id);
  if (node) node.textContent = text;
}

function show(id) {
  const node = document.getElementById(id);
  if (node) node.hidden = false;
}

function clearChildren(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// ---------- bootstrap ----------

const p = new URLSearchParams(location.search);
const url        = p.get("u") || "";
const reasonText = p.get("r") || "";
const evidenceId = p.get("e") || "";
const brand      = p.get("b") || "";
const score      = p.get("s") || "";
const codesCSV   = p.get("c") || "";

setText("url", url);
setText("evidenceIdFooter", evidenceId || "(none)");
if (reasonText) setText("reason", reasonText);

const initialCodes = codesCSV ? codesCSV.split(",").filter(Boolean) : [];

if (brand) {
  show("brandRow");
  setText("brand", brand);
  setText("score", score ? Math.round(parseFloat(score) * 100) + "%" : "—");
}

renderSignals(initialCodes);

document.getElementById("viewFullEvidence").href = evidenceId
  ? `https://report.xgenguardian.com/report/${encodeURIComponent(evidenceId)}`
  : `https://report.xgenguardian.com/?url=${encodeURIComponent(url)}`;
document.getElementById("reportFP").href =
  `https://report.xgenguardian.com/report-fp?url=${encodeURIComponent(url)}`;

if (evidenceId) {
  fetchAndRender(evidenceId).catch((e) => {
    console.warn("blocked: evidence fetch failed", e);
    if (initialCodes.length === 0) {
      const node = document.getElementById("signals");
      node.className = "empty";
      clearChildren(node);
      node.textContent = "Could not reach evidence server. Showing minimal block info only.";
    }
  });
}

// ---------- fetch + render ----------

async function fetchAndRender(id) {
  const cfg = await chrome.storage.sync.get({
    portalApiBase: "https://api.xgenguardian.com",
  });
  const base = cfg.portalApiBase || "https://api.xgenguardian.com";
  const r = await fetch(`${base}/v1/evidence/${encodeURIComponent(id)}`);
  if (!r.ok) throw new Error("HTTP " + r.status);
  const ev = await r.json();
  renderEvidence(ev);
}

function renderSignals(codes) {
  const target = document.getElementById("signals");
  target.className = "";
  clearChildren(target);

  if (!codes.length) {
    target.className = "empty";
    target.textContent = "No reason codes attached. The block was likely cache-driven.";
    return;
  }

  for (const code of codes) {
    const meta = REASONS[code] || { title: code, body: "Detector triggered (no description registered).", sev: "medium" };
    const card = el("div", { className: "signal sev-" + meta.sev });
    card.appendChild(el("div", { className: "signal-code", text: code }));
    card.appendChild(el("div", { className: "signal-title", text: meta.title }));
    card.appendChild(el("div", { className: "signal-body",  text: meta.body }));
    target.appendChild(card);
  }
}

function renderEvidence(ev) {
  if (ev.grade) {
    const g = document.getElementById("grade");
    g.hidden = false;
    g.textContent = "Grade " + ev.grade;
  }

  if (Array.isArray(ev.reason_codes) && ev.reason_codes.length) {
    renderSignals(ev.reason_codes);
  }

  // Page identity
  if (ev.final_url && ev.final_url !== ev.url) {
    show("finalRow");
    setText("finalUrl", ev.final_url);
  }
  if (Array.isArray(ev.redirect_chain) && ev.redirect_chain.length) {
    show("redirectRow");
    const dest = document.getElementById("redirectChain");
    clearChildren(dest);
    ev.redirect_chain.forEach((step, i) => {
      const row = el("div", { className: "redirect-step" });
      if (i > 0) {
        row.appendChild(el("span", { className: "redirect-arrow", text: "↓ " }));
      }
      row.appendChild(document.createTextNode(step));
      dest.appendChild(row);
    });
  }
  if (ev.visual_top_brand) {
    show("brandRow");
    setText("brand", ev.visual_top_brand);
    setText("score", ev.visual_top_score ? Math.round(ev.visual_top_score * 100) + "%" : "—");
  }
  if (ev.favicon_match) {
    show("faviconRow");
    setText("favicon", ev.favicon_match);
  }
  if (ev.page_class && ev.page_class !== "generic") {
    show("pageClassRow");
    setText("pageClass", ev.page_class);
  }

  // Hosting context
  if (ev.registrar) {
    show("registrarRow");
    setText("registrar", ev.registrar);
  }
  if (typeof ev.domain_age_days === "number") {
    show("ageRow");
    setText("age", formatAge(ev.domain_age_days));
  }
  if (ev.current_asn) {
    show("asnRow");
    setText("asn", "AS" + ev.current_asn);
  }
  if (ev.cert_issuer) {
    show("certRow");
    setText("cert", ev.cert_issuer);
  }
  if (ev.cert_sha256) {
    show("certHashRow");
    setText("certHash", ev.cert_sha256);
  }
  if (ev.external && Object.keys(ev.external).length) {
    show("extRow");
    const dest = document.getElementById("ext");
    clearChildren(dest);
    for (const [k, v] of Object.entries(ev.external)) {
      const tag = el("span", { className: "ext-tag" });
      const display = typeof v === "object" ? JSON.stringify(v) : String(v);
      tag.textContent = `${k}: ${display}`;
      dest.appendChild(tag);
    }
  }

  // Form actions
  if (Array.isArray(ev.form_actions) && ev.form_actions.length) {
    show("formsHeader");
    show("formsPanel");
    const ul = document.getElementById("forms");
    clearChildren(ul);
    for (const action of ev.form_actions) {
      ul.appendChild(el("li", { text: action }));
    }
  }

  // Screenshot
  if (ev.screenshot_url) {
    show("screenshotHeader");
    const img = document.getElementById("screenshot");
    img.hidden = false;
    img.src = ev.screenshot_url; // src attribute, not innerHTML
  }
}

function formatAge(days) {
  if (days < 1)   return "less than a day";
  if (days < 30)  return days + " day" + (days === 1 ? "" : "s");
  if (days < 365) return Math.floor(days / 30) + " month" + (days < 60 ? "" : "s");
  return Math.floor(days / 365) + " year" + (days < 730 ? "" : "s");
}
