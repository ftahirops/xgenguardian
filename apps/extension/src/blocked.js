// blocked.js — runs inside blocked.html.
//
// Reads URL params the background passed (?u, ?r, ?e, ?b, ?s, ?c) and, if an
// evidence_id is present, fetches the deep evidence bundle from portal-api so
// we can render every signal that fired, the redirect chain, hosting context,
// side-by-side screenshot comparison, verification checklist, and external
// corroborators.
//
// Falls back to URL-param data when portal-api is unreachable so the page
// still tells the user *why* even without server access.
//
// All DOM mutation uses createElement + textContent — never innerHTML —
// because reason codes and brand names are attacker-influenceable and this
// is a security UI.

// Reason-code → human template. Kept in sync with
// services/verdict-api/internal/reasons/reasons.go.
const REASONS = {
  KNOWN_PHISH_URL_MATCH: { title: "Confirmed phishing URL", body: "This exact URL is on a threat-intelligence feed of confirmed phishing pages.", sev: "critical" },
  KNOWN_MALWARE_DOMAIN_MATCH: { title: "Confirmed malware domain", body: "This domain is on a threat-intelligence feed of confirmed malware-distribution hosts.", sev: "critical" },
  BRAND_CLAIM_DOMAIN_MISMATCH: { title: "Page impersonates a known brand", body: "The page visually matches a protected brand but the domain is not owned by that brand.", sev: "critical" },
  VISUAL_REPLICA_HIGH: { title: "Page visually replicates a known brand", body: "A high-confidence visual match against a brand-reference screenshot — the page is engineered to look like the real brand.", sev: "high" },
  IDENTITY_MISMATCH_DOMAIN: { title: "Domain does not match the impersonated brand", body: "The page claims (visually or by content) to be a brand but the hosting domain is not owned by that brand.", sev: "high" },
  IDENTITY_MISMATCH_ASN: { title: "Hosting network does not match the brand", body: "The page is served from an ISP/network that the impersonated brand never uses.", sev: "high" },
  IDENTITY_MISMATCH_CERT: { title: "TLS certificate issuer mismatch", body: "The TLS certificate authority does not match what the impersonated brand uses for their canonical domains.", sev: "medium" },
  IDENTITY_MISMATCH_SCRIPT_ORIGIN: { title: "Scripts loaded from unexpected origins", body: "The page loads scripts from origins that the impersonated brand does not use.", sev: "medium" },
  FAVICON_BRAND_MISMATCH: { title: "Favicon impersonates a brand", body: "The page favicon matches a protected brand on a non-canonical domain.", sev: "high" },
  TITLE_FAVICON_BRAND_IMPERSONATION: { title: "Title + favicon brand impersonation", body: "Both the title and favicon imitate a protected brand on a non-canonical domain.", sev: "high" },
  LOGIN_FORM_ON_UNAPPROVED_DOMAIN: { title: "Login form on unverified domain", body: "This page collects credentials but is not on an approved domain for the brand it claims.", sev: "high" },
  FORM_POSTS_TO_UNRELATED_DOMAIN: { title: "Credentials posted to a third-party domain", body: "The password form submits to a domain unrelated to the page's own.", sev: "high" },
  CREDENTIAL_SINK_HIDDEN_MIRROR: { title: "Hidden credential exfiltration", body: "The page silently sends credentials to a hidden second destination, in addition to the visible form action.", sev: "critical" },
  CREDENTIAL_SINK_PRE_SUBMIT_CAPTURE: { title: "Credentials captured before submit", body: "The page sends what you type to another server before you click Submit.", sev: "critical" },
  SUSPICIOUS_REDIRECT_CHAIN: { title: "Suspicious redirect chain", body: "This URL redirected through multiple hops before reaching its destination.", sev: "medium" },
  HOMOGLYPH_OF_PROTECTED_BRAND: { title: "Lookalike domain", body: "This domain visually imitates a protected brand using character substitution.", sev: "high" },
  DOMAIN_AGE_UNDER_THRESHOLD: { title: "Domain registered recently", body: "New domains are often used for one-shot phishing.", sev: "medium" },
  FRESH_DOMAIN: { title: "Domain registered very recently", body: "Real phishing campaigns burn through fresh, just-registered domains. Legitimate sites with login/payment flows almost always have established registration history.", sev: "high" },
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
  EXTERNAL_FEED_HIT: { title: "External threat-intelligence hit", body: "An external community feed flags this URL or domain as malicious.", sev: "high" },
  GOOGLE_WEB_RISK_UNSAFE: { title: "Google Web Risk: unsafe", body: "Google Web Risk reports this URL as unsafe.", sev: "high" },
  VIRUSTOTAL_POSITIVE: { title: "VirusTotal detections", body: "Multiple antivirus engines on VirusTotal flag this URL or file.", sev: "high" },
  YARA_SIGNATURE_MATCH: { title: "YARA signature match", body: "The page or downloaded file matches a known-malicious YARA signature.", sev: "high" },
  SUBDOMAIN_TAKEOVER_RISK: { title: "Possible subdomain takeover", body: "This subdomain's CNAME target appears unclaimed and may be hijacked.", sev: "high" },
  CLOAKING_DIVERGENCE: { title: "Server-side cloaking", body: "The page serves different content to different network locations.", sev: "high" },
  OAUTH_UNKNOWN_CLIENT_ID: { title: "Unknown OAuth application", body: "This OAuth consent screen requests sensitive permissions for an unknown app.", sev: "high" },
  OAUTH_UNVERIFIED_HIGH_SCOPE_APP: { title: "Unverified OAuth app on high-trust page", body: "An unverified OAuth application is asking for sensitive permissions on a real provider page.", sev: "high" },
  HTML_SMUGGLING_PATTERN: { title: "HTML smuggling", body: "This page reassembles a downloadable payload entirely client-side.", sev: "high" },
  DGA_CLASSIFIER_HIT: { title: "Algorithmically-generated domain", body: "This domain matches the pattern of malware command-and-control domain generation.", sev: "medium" },
  RANDOM_HOSTNAME: { title: "Hostname looks randomly generated", body: "Hostname has low vowel ratio / long consonant runs / no repeating bigrams — patterns typical of phishing kits and short-lived attack infrastructure.", sev: "medium" },
  RAW_IP_HOST: { title: "URL uses a raw IP address", body: "Legitimate websites use domain names, not raw IPs. This URL hits an IP directly.", sev: "medium" },
  MALWARE_RAW_IP_BINARY_DROP: { title: "Suspected botnet binary drop", body: "URL points at a raw IP and the path looks like an architecture-specific binary (Mirai-style malware pattern).", sev: "critical" },
  MINER_POOL_CONTACT: { title: "Cryptocurrency miner", body: "This page contacts a known cryptocurrency-mining pool.", sev: "medium" },
  VENDOR_DNS_CONSENSUS_BLOCK: { title: "Multiple security DNS providers block this domain", body: "Independent protective-DNS providers (Cloudflare, Quad9, AdGuard, OpenDNS, CleanBrowsing) maintain separate threat lists. When two or more agree to block, the threat is near-certainly confirmed.", sev: "critical" },
  VENDOR_DNS_SINGLE_HIT: { title: "One security DNS provider blocks this domain", body: "A single protective-DNS provider has this domain on their blocklist. Treating as advisory.", sev: "medium" },
  CATEGORY_BLOCK_ADULT: { title: "Adult-content category block", body: "Blocked by your adult-content category filter.", sev: "medium" },
  CATEGORY_BLOCK_GAMBLING: { title: "Gambling category block", body: "Blocked by your gambling category filter.", sev: "medium" },
  CATEGORY_BLOCK_PIRACY: { title: "Piracy category block", body: "Blocked by your piracy category filter.", sev: "medium" },
  CATEGORY_BLOCK_CRACK_KEYGEN: { title: "Crack/keygen category block", body: "Blocked by your crack/keygen category filter.", sev: "medium" },
  CATEGORY_BLOCK_MALVERTISING: { title: "Malvertising category block", body: "Blocked by your malvertising category filter.", sev: "high" },
  CATEGORY_BLOCK_POPUNDER: { title: "Popunder ad-network block", body: "Domain is part of a popunder ad network linked to malware-delivery chains.", sev: "high" },
  ULTRA_NOT_CLEARED: { title: "Ultra mode: full clearance not earned", body: "Ultra mode requires every verification gate to affirmatively pass. One or more gates failed or could not verify — opening in isolation as a precaution. See the verification checklist for the per-gate breakdown.", sev: "medium" },
  ULTRA_CLEARED: { title: "Ultra mode: page passed full clearance", body: "Every verification gate affirmatively passed.", sev: "low" },
};

// ---------- helpers (DOM builders, all textContent-based) ----------

// isHttpURL — gate values passed to attribute sinks (img.src etc.) so a
// MITMed portal-api response can't deliver javascript:/data:text/html URIs
// (audit FINDING #4 — CRITICAL).
function isHttpURL(s) {
  if (typeof s !== "string") return false;
  return /^https?:\/\/[^\s]+$/i.test(s);
}

function el(tag, opts, ...children) {
  const e = document.createElement(tag);
  if (opts?.className) e.className = opts.className;
  if (opts?.text != null) e.textContent = opts.text;
  if (opts?.attrs) {
    for (const [k, v] of Object.entries(opts.attrs)) e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    if (typeof c === "string") e.appendChild(document.createTextNode(c));
    else e.appendChild(c);
  }
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
const verdict    = (p.get("v") || "BLOCK").toUpperCase();

// v0.3.3 — pull the full verdict (with decision_trace) from session
// storage. Fail silent if absent (page opened directly).
(async () => {
  try {
    const all = await chrome.storage.session.get({ verdictStash: {} });
    const stashed = all?.verdictStash?.[url];
    // v0.3.5 — wrapper-chain render
    if (stashed?.wrapper_chain?.length) {
      const wWrap = document.getElementById("wrapperChain");
      const wBody = document.getElementById("wrapperChainBody");
      if (wWrap && wBody) {
        wWrap.hidden = false;
        while (wBody.firstChild) wBody.removeChild(wBody.firstChild);
        const niceName = {
          safelinks:  "Microsoft SafeLinks",
          proofpoint: "Proofpoint URL Defense",
          mimecast:   "Mimecast",
          cisco:      "Cisco Secure Email",
          barracuda:  "Barracuda",
          symantec:   "Symantec / Broadcom",
          gmail:      "Gmail link redirect",
        };
        for (const hop of stashed.wrapper_chain) {
          const row = el("div", { className: "wrapper-row" });
          row.appendChild(el("span", { className: "wrapper-tag", text: niceName[hop?.wrapper] || hop?.wrapper || "wrapper" }));
          row.appendChild(el("span", { className: "wrapper-url", text: hop?.url || "" }));
          wBody.appendChild(row);
        }
      }
    }
    if (stashed?.decision_trace?.length) {
      const wrap = document.getElementById("decisionTrace");
      const body = document.getElementById("decisionTraceBody");
      if (!wrap || !body) return;
      wrap.hidden = false;
      while (body.firstChild) body.removeChild(body.firstChild);
      for (const s of stashed.decision_trace) {
        const stage = String(s.stage || "");
        const outcome = String(s.outcome || "");
        const code = String(s.code || "");
        const detail = String(s.detail || "");
        const weight = typeof s.weight === "number" && s.weight !== 0 ? s.weight.toFixed(2) : "";
        const row = el("div", { className: "trace-row trace-" + outcome });
        row.appendChild(el("span", { className: "trace-stage", text: stage || "·" }));
        row.appendChild(el("span", { className: "trace-outcome", text: outcome || "·" }));
        row.appendChild(el("span", { className: "trace-code", text: code || "—" }));
        row.appendChild(el("span", { className: "trace-detail", text: detail || "" }));
        if (weight) row.appendChild(el("span", { className: "trace-weight", text: "w=" + weight }));
        body.appendChild(row);
      }
    }
  } catch {}
})();

// Verdict pill + heading copy
const pill = document.getElementById("verdictPill");
if (verdict === "WARN") {
  pill.textContent = "Warning";
  pill.className = "pill pill-warn";
  document.getElementById("title").textContent = "This page is suspicious.";
} else if (verdict === "ISOLATE") {
  pill.textContent = "Isolating";
  pill.className = "pill pill-isolate";
  document.getElementById("title").textContent = "Opening this page in isolation.";
}

// The URL is the SINGLE most important piece of info on this page.
// Without it the user can't tell what was blocked. Render it whether or
// not it passes isHttpURL (we show it as TEXT, not as a clickable link).
// Fallback to "(unknown URL)" only if the param is genuinely missing.
setText("url", url || "(unknown URL — extension may have been reloaded mid-navigation)");
setText("evidenceIdFooter", evidenceId || "(none)");
if (reasonText) setText("reason", reasonText);

const initialCodes = codesCSV ? codesCSV.split(",").filter(Boolean) : [];

// Phase D.3: trust score + contributors. ts=numeric score, tc encoded as
// "label1:w1|label2:w2|...". Render in its own row so users can see why
// the engine decided this page is (or isn't) trustworthy. Trust score
// renders even on BLOCK pages — it explains "we softened soft signals but
// still BLOCKed on hard evidence."
const tsRaw = p.get("ts") || "";
const tcRaw = p.get("tc") || "";
if (tsRaw) {
  const trustRow = document.getElementById("trustRow");
  const trustVal = document.getElementById("trust");
  if (trustRow && trustVal) {
    trustRow.hidden = false;
    trustVal.textContent = "";
    const header = document.createElement("div");
    const score = parseFloat(tsRaw);
    header.textContent = isFinite(score) ? `${score.toFixed(2)} / 1.00` : tsRaw;
    trustVal.appendChild(header);
    if (tcRaw) {
      for (const entry of tcRaw.split("|")) {
        const [label, weight] = entry.split(":");
        if (!label) continue;
        const w = parseFloat(weight || "0");
        const sign = w >= 0 ? "+" : "";
        const div = document.createElement("div");
        div.textContent = `  ${sign}${isFinite(w) ? w.toFixed(2) : weight}  ${label}`;
        trustVal.appendChild(div);
      }
    }
  }
}

// Phase B.6: connection identity, passed by background.js as cip/xip/dpc.
const cip = p.get("cip") || "";
const xipCSV = p.get("xip") || "";
const dpc = p.get("dpc") === "1";
if (cip) {
  const row = document.getElementById("connIdRow");
  const val = document.getElementById("connId");
  if (row && val) {
    row.hidden = false;
    val.textContent = ""; // reset
    const lines = [];
    lines.push(`browser connected to ${cip}`);
    if (xipCSV) {
      lines.push(`XGG resolver returned: ${xipCSV.split(",").join(", ")}`);
    }
    lines.push(dpc ? "DNS path consistent" : "DNS path NOT verified (ledger cold or mismatch)");
    for (const line of lines) {
      const div = document.createElement("div");
      div.textContent = line;
      val.appendChild(div);
    }
  }
}

if (brand) {
  show("brandRow");
  setText("brand", brand);
  setText("score", score ? Math.round(parseFloat(score) * 100) + "%" : "—");
}

renderSignals(initialCodes);
renderChecklistFromCodes(initialCodes, null);

// Wire "Go back" button (replaces inline javascript: href — audit FINDING #8).
document.getElementById("goBackBtn")?.addEventListener("click", () => {
  history.back();
});

// "Open full report" and "I think this is wrong" buttons.
//
// These previously pointed at https://report.xgenguardian.com/ — a domain
// that does NOT actually resolve. Users clicking them landed on the
// DNS-fail page, which was correct UX for a dead URL but a terrible
// experience for a "see more details" action.
//
// Until/unless the operator wires a real report UI (Phase 8 candidate),
// HIDE both buttons. Showing a button that takes the user nowhere is
// worse than not showing the button at all.
//
// To re-enable: set `reportUIBase` in chrome.storage.local to the URL of
// a deployed report UI (e.g. "https://report.mycompany.com"). The buttons
// will then become visible and point at the right place.
(async () => {
  const fullEvidenceLink = document.getElementById("viewFullEvidence");
  const reportFPLink = document.getElementById("reportFP");
  if (fullEvidenceLink) fullEvidenceLink.style.display = "none";
  if (reportFPLink) reportFPLink.style.display = "none";
  try {
    const cfg = await chrome.storage.local.get({ reportUIBase: "" });
    const base = cfg.reportUIBase
      && /^https?:\/\/[^\s]+$/i.test(cfg.reportUIBase.trim())
      ? cfg.reportUIBase.trim().replace(/\/+$/, "")
      : "";
    if (!base) return;
    if (evidenceId && fullEvidenceLink) {
      fullEvidenceLink.href = `${base}/report/${encodeURIComponent(evidenceId)}`;
      fullEvidenceLink.style.display = "";
    }
    if (reportFPLink) {
      reportFPLink.href = `${base}/report-fp?url=${encodeURIComponent(url)}`;
      reportFPLink.style.display = "";
    }
  } catch {}
})();

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
  // storage.local for consistency with options.js writes (FINDING #11).
  // Reading from storage.sync meant a self-hosted operator who configured
  // portalApiBase in Options would still fetch evidence from the hardcoded
  // default, causing every block-page evidence load to 404 silently.
  const cfg = await chrome.storage.local.get({
    portalApiBase: "http://135.181.79.11:18081",
  });
  const raw = cfg.portalApiBase || "https://api.xgenguardian.com";
  // Reject any non-http(s)://. portalApiBase is user-configurable via Options
  // and an invalid value here would otherwise be concatenated into a fetch
  // URL with surprising behavior. (audit FINDING #3 — CRITICAL.)
  if (!/^https?:\/\/[^\s]+$/i.test(raw.trim())) {
    throw new Error("portalApiBase is not a valid http(s) URL");
  }
  const base = raw.trim().replace(/\/+$/, "");
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

  // Sort by severity: critical → high → medium → low.
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...codes].sort((a, b) => {
    const sa = REASONS[a]?.sev || "medium";
    const sb = REASONS[b]?.sev || "medium";
    return (sevRank[sa] ?? 2) - (sevRank[sb] ?? 2);
  });

  for (const code of sorted) {
    const meta = REASONS[code] || { title: code, body: "Detector triggered (no description registered).", sev: "medium" };
    const card = el("div", { className: "signal sev-" + meta.sev });
    card.appendChild(el("div", { className: "signal-code", text: code }));
    card.appendChild(el("div", { className: "signal-title", text: meta.title }));
    card.appendChild(el("div", { className: "signal-body",  text: meta.body }));
    target.appendChild(card);
  }
}

// ---------- verification checklist ----------
//
// Renders an 8-layer "what passed / what failed" grid so the user can see
// exactly which independent checks contributed to the block. Each cell is
// rendered as pass/warn/fail/unknown based on the evidence payload.

function checklistRow(state, title, body) {
  const icon = state === "pass"  ? "✓"
             : state === "fail"  ? "✗"
             : state === "warn"  ? "!"
             :                     "·";
  const cell = el("div", { className: "check " + state });
  cell.appendChild(el("div", { className: "check-icon", text: icon }));
  const right = el("div");
  right.appendChild(el("div", { className: "check-title", text: title }));
  right.appendChild(el("div", { className: "check-body",  text: body }));
  cell.appendChild(right);
  return cell;
}

function renderChecklistFromCodes(codes, ev) {
  const dest = document.getElementById("checks");
  clearChildren(dest);

  // Phase 5: when the server returned an authoritative clearance_checks
  // map, render that directly — it's computed by the policy engine and
  // reflects the actual gate outcomes the engine used. Falls back to the
  // codes-derived heuristic when older clients hit a Phase-4 verdict-api.
  if (ev?.clearance_checks && typeof ev.clearance_checks === "object") {
    const labels = {
      feed:           ["Threat-intel feeds",
                       "On at least one community/commercial threat feed.",
                       "Not on any of our ingested threat-intel feeds."],
      vendor_dns:     ["Security DNS (Cloudflare / Quad9 / AdGuard / OpenDNS / CleanBrowsing)",
                       "Two or more independent protective-DNS providers block this domain.",
                       "No protective-DNS provider blocks this domain."],
      domain_age:     ["Domain age",
                       "Domain was registered recently — fresh-registration phishing pattern.",
                       "Domain is established."],
      hostname_shape: ["Hostname analysis",
                       "Hostname looks random / raw-IP / botnet pattern.",
                       "Hostname pattern looks normal."],
      visual:         ["Visual brand impersonation",
                       "Page visually replicates a brand it isn't authorized to use.",
                       "Does not visually replicate any protected brand."],
      identity:       ["Identity binding",
                       "Hosting domain / ASN / cert doesn't match the impersonated brand.",
                       "Hosting identity is consistent."],
      behavior:       ["Page behavior",
                       "Sandbox detected abusive runtime behavior (scareware / popup storm / clipboard / drive-by).",
                       "No abusive runtime behavior detected."],
      trust:          ["Positive trust signal",
                       "(unknown)",
                       "Host is in the curated trust registry OR matched a vendor install template."],
    };
    const order = ["feed", "vendor_dns", "domain_age", "hostname_shape",
                   "visual", "identity", "behavior", "trust"];
    for (const key of order) {
      const state = ev.clearance_checks[key] || "unknown";
      const meta = labels[key];
      if (!meta) continue;
      const body = state === "fail"   ? meta[1]
                 : state === "warn"   ? meta[1]
                 : state === "pass"   ? meta[2]
                 :                      "(could not verify)";
      dest.appendChild(checklistRow(state, meta[0], body));
    }
    return;
  }

  const has = (c) => codes.includes(c);
  const anyOf = (...cs) => cs.some(has);

  // 1. Threat-intel feeds (URLhaus, OpenPhish, etc.)
  dest.appendChild(checklistRow(
    has("EXTERNAL_FEED_HIT") || has("KNOWN_PHISH_URL_MATCH") || has("KNOWN_MALWARE_DOMAIN_MATCH") ? "fail" : "pass",
    "Threat-intel feeds",
    has("EXTERNAL_FEED_HIT") || has("KNOWN_PHISH_URL_MATCH") || has("KNOWN_MALWARE_DOMAIN_MATCH")
      ? "On at least one community/commercial threat feed."
      : "Not on any of our ingested threat-intel feeds."
  ));

  // 2. Multi-vendor DNS consensus
  let dnsState = "pass", dnsBody = "No protective-DNS provider blocks this domain.";
  if (has("VENDOR_DNS_CONSENSUS_BLOCK")) {
    dnsState = "fail";
    const list = ev?.vendor_dns_blocked_by;
    dnsBody = list?.length
      ? "Blocked by " + list.length + " provider" + (list.length === 1 ? "" : "s") + ": " + list.join(", ")
      : "Two or more independent protective-DNS providers block this domain.";
  } else if (has("VENDOR_DNS_SINGLE_HIT")) {
    dnsState = "warn";
    dnsBody = "One protective-DNS provider blocks this domain (advisory).";
  }
  dest.appendChild(checklistRow(dnsState, "Security DNS (Cloudflare/Quad9/AdGuard/…)", dnsBody));

  // 3. Domain age
  let ageState = "unknown", ageBody = "Domain registration date not available.";
  if (ev && typeof ev.domain_age_days === "number") {
    if (ev.domain_age_days < 30) {
      ageState = "fail";
      ageBody = "Domain registered " + formatAge(ev.domain_age_days) + " ago — fresh-registration phishing pattern.";
    } else if (ev.domain_age_days < 180) {
      ageState = "warn";
      ageBody = "Domain registered " + formatAge(ev.domain_age_days) + " ago.";
    } else {
      ageState = "pass";
      ageBody = "Domain registered " + formatAge(ev.domain_age_days) + " ago (established).";
    }
  } else if (has("FRESH_DOMAIN") || has("DOMAIN_AGE_UNDER_THRESHOLD")) {
    ageState = "fail";
    ageBody = "Domain was registered recently — fresh-registration phishing pattern.";
  }
  dest.appendChild(checklistRow(ageState, "Domain age", ageBody));

  // 4. Visual brand match
  let visState = "pass", visBody = "Does not visually replicate any protected brand.";
  if (anyOf("BRAND_CLAIM_DOMAIN_MISMATCH", "VISUAL_REPLICA_HIGH",
            "TITLE_FAVICON_BRAND_IMPERSONATION", "FAVICON_BRAND_MISMATCH",
            "HOMOGLYPH_OF_PROTECTED_BRAND")) {
    visState = "fail";
    const b = ev?.visual_top_brand || brand;
    visBody = b
      ? "Visually replicates " + b + " (likely impersonation)."
      : "Page visually replicates a protected brand it isn't authorized to use.";
  }
  dest.appendChild(checklistRow(visState, "Visual brand impersonation", visBody));

  // 5. Identity binding (domain/ASN/cert matches the brand it claims to be)
  let idState = "pass", idBody = "Hosting identity is consistent with no impersonation claim.";
  if (anyOf("IDENTITY_MISMATCH_DOMAIN", "IDENTITY_MISMATCH_ASN",
            "IDENTITY_MISMATCH_CERT", "IDENTITY_MISMATCH_SCRIPT_ORIGIN")) {
    idState = "fail";
    const parts = [];
    if (has("IDENTITY_MISMATCH_DOMAIN"))  parts.push("domain");
    if (has("IDENTITY_MISMATCH_ASN"))     parts.push("ASN");
    if (has("IDENTITY_MISMATCH_CERT"))    parts.push("certificate");
    if (has("IDENTITY_MISMATCH_SCRIPT_ORIGIN")) parts.push("script-origin");
    idBody = "Hosting " + parts.join(" / ") + " does not match the impersonated brand.";
  } else if (visState === "fail") {
    idState = "warn";
    idBody = "Visual match present; identity could not be fully verified.";
  }
  dest.appendChild(checklistRow(idState, "Identity binding", idBody));

  // 6. Credential-sink trust
  let sinkState = "pass", sinkBody = "No suspicious credential-handling behavior detected.";
  if (anyOf("CREDENTIAL_SINK_HIDDEN_MIRROR", "CREDENTIAL_SINK_PRE_SUBMIT_CAPTURE",
            "FORM_POSTS_TO_UNRELATED_DOMAIN", "LOGIN_FORM_ON_UNAPPROVED_DOMAIN")) {
    sinkState = "fail";
    sinkBody = "Form would send your credentials to an untrusted destination.";
  }
  dest.appendChild(checklistRow(sinkState, "Credential-handling check", sinkBody));

  // 7. Behavior (popups, scareware, clipboard, drive-by)
  let behState = "pass", behBody = "No abusive runtime behavior detected during sandbox render.";
  if (anyOf("POPUP_STORM_DETECTED", "ALERT_LOOP_DETECTED", "FULLSCREEN_TRAP_DETECTED",
            "CLIPBOARD_HIJACK_ATTEMPT", "AUTO_DOWNLOAD_TRIGGER", "FAKE_SUPPORT_SCAREWARE",
            "BEFOREUNLOAD_ABUSE")) {
    behState = "fail";
    behBody = "Sandbox detected abusive runtime behavior (popup storm, scareware, clipboard tamper, etc.).";
  }
  dest.appendChild(checklistRow(behState, "Page behavior", behBody));

  // 8. Hostname / DGA analysis
  let hostState = "pass", hostBody = "Hostname pattern looks normal.";
  if (anyOf("RANDOM_HOSTNAME", "DGA_CLASSIFIER_HIT", "RAW_IP_HOST",
            "MALWARE_RAW_IP_BINARY_DROP")) {
    hostState = "fail";
    if (has("MALWARE_RAW_IP_BINARY_DROP")) hostBody = "Raw IP host serving an architecture-specific binary (botnet drop pattern).";
    else if (has("RAW_IP_HOST")) hostBody = "URL points at a raw IP rather than a domain name.";
    else hostBody = "Hostname matches algorithmically-generated / burner-domain patterns.";
  }
  dest.appendChild(checklistRow(hostState, "Hostname analysis", hostBody));
}

function renderEvidence(ev) {
  // Verdict pill: use response verdict if present. All three non-default
  // verdicts are handled explicitly so evidence that overrides URL-param WARN
  // with a BLOCK is reflected correctly (audit FINDING #19).
  if (ev.verdict) {
    const v = String(ev.verdict).toUpperCase();
    if (v === "WARN") {
      pill.textContent = "Warning"; pill.className = "pill pill-warn";
    } else if (v === "ISOLATE") {
      pill.textContent = "Isolating"; pill.className = "pill pill-isolate";
    } else if (v === "BLOCK") {
      // Reset to BLOCK styling — URL param may have said WARN/ISOLATE but
      // the evidence bundle says BLOCK (escalation after full analysis).
      pill.textContent = "Blocked"; pill.className = "pill";
    }
  }
  if (typeof ev.verdict_confidence === "number") {
    const c = document.getElementById("confBadge");
    c.hidden = false;
    c.textContent = Math.round(ev.verdict_confidence * 100) + "% confidence";
  }

  if (ev.grade) {
    const g = document.getElementById("grade");
    g.hidden = false;
    g.textContent = "Grade " + ev.grade;
  }

  if (Array.isArray(ev.reason_codes) && ev.reason_codes.length) {
    renderSignals(ev.reason_codes);
    renderChecklistFromCodes(ev.reason_codes, ev);
  }

  // Side-by-side screenshot comparison
  // Image src values come from portal-api (potentially MITMed when API is
  // plaintext). Validate the URL scheme before assigning to .src so an
  // attacker can't slip a javascript:/data:text/html URI through (audit
  // FINDING #4 — CRITICAL).
  const badShot  = document.getElementById("badShot");
  const goodShot = document.getElementById("goodShot");
  if (ev.screenshot_url && isHttpURL(ev.screenshot_url)) {
    if (badShot) {
      badShot.onerror = () => { badShot.hidden = true; };
      badShot.src = ev.screenshot_url;
    }
    show("compareHeader");
    show("compareGrid");
    if (ev.brand_reference_screenshot && ev.visual_top_brand &&
        isHttpURL(ev.brand_reference_screenshot)) {
      if (goodShot) {
        goodShot.onerror = () => { goodShot.hidden = true; };
        goodShot.src = ev.brand_reference_screenshot;
      }
      document.getElementById("goodHead").textContent =
        "Real " + ev.visual_top_brand + " reference";
      const score = typeof ev.visual_top_score === "number"
        ? " · visual similarity " + Math.round(ev.visual_top_score * 100) + "%"
        : "";
      document.getElementById("goodMeta").textContent =
        "Curated brand reference" + score;
    } else {
      // No (or unsafe) reference to compare against — collapse the right
      // column message. Use .hidden instead of .remove() so a second
      // renderEvidence call doesn't null-deref on the removed element
      // (audit FINDING #16).
      if (goodShot) goodShot.hidden = true;
      document.getElementById("goodHead").textContent = "No brand reference";
      document.getElementById("goodMeta").textContent =
        "No protected brand was matched, so there's nothing to compare against.";
    }
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
  if (typeof ev.domain_age_days === "number") {
    show("ageRow");
    const badge = document.getElementById("ageBadge");
    if (ev.domain_age_days < 30) {
      badge.className = "age-badge fresh";
      badge.textContent = "Registered " + formatAge(ev.domain_age_days) + " ago";
    } else if (ev.domain_age_days < 180) {
      badge.className = "age-badge young";
      badge.textContent = formatAge(ev.domain_age_days) + " old";
    } else {
      badge.className = "age-badge aged";
      badge.textContent = formatAge(ev.domain_age_days) + " old";
    }
    if (ev.registered_at) {
      setText("ageDetail", "(registered " + new Date(ev.registered_at).toISOString().slice(0, 10) + ")");
    }
  }
  if (ev.registrar) {
    show("registrarRow");
    setText("registrar", ev.registrar);
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
  if (Array.isArray(ev.vendor_dns_blocked_by) && ev.vendor_dns_blocked_by.length) {
    show("vendorDNSRow");
    const dest = document.getElementById("vendorDNS");
    clearChildren(dest);
    for (const name of ev.vendor_dns_blocked_by) {
      dest.appendChild(el("span", { className: "provider-tag", text: name }));
    }
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

  // Scanned-at timestamp
  if (ev.created_at) {
    setText("scannedAt", new Date(ev.created_at).toLocaleString());
  }
}

function formatAge(days) {
  if (days < 1)   return "less than a day";
  if (days < 30)  return days + " day" + (days === 1 ? "" : "s");
  if (days < 365) {
    const m = Math.floor(days / 30);
    return m + " month" + (m === 1 ? "" : "s");
  }
  const y = Math.floor(days / 365);
  return y + " year" + (y === 1 ? "" : "s");
}
