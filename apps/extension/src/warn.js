// warn.js — runs inside warn.html.
//
// Reuses the same evidence rendering shape as blocked.js but with the
// WARN-page semantics: 5-second countdown gate on "Proceed anyway" and
// amber styling. Pulls deep evidence from portal-api when an evidence_id
// is present so the full transparency grid + hosting context show even
// on the warn level.

function isHttpURL(s) {
  if (typeof s !== "string") return false;
  return /^https?:\/\/[^\s]+$/i.test(s);
}

const REASONS = {
  EXTERNAL_FEED_HIT: { title: "External threat-intelligence hit", body: "A community feed flagged this URL or domain.", sev: "high" },
  FRESH_DOMAIN: { title: "Domain registered very recently", body: "Fresh registration is common in phishing campaigns. Established sites with sensitive flows almost always have older registration history.", sev: "high" },
  RANDOM_HOSTNAME: { title: "Hostname looks randomly generated", body: "Patterns typical of phishing kits and short-lived attack infrastructure.", sev: "medium" },
  VENDOR_DNS_SINGLE_HIT: { title: "One security DNS provider blocks this domain", body: "A single protective-DNS provider blocks this domain. Advisory only until corroborated.", sev: "medium" },
  HIDDEN_MALICIOUS_LINK: { title: "Multiple hidden cross-origin links", body: "The page has several hidden anchors pointing off-site. Common on link farms; also seen on legitimate sites with collapsed nav menus.", sev: "medium" },
  SUSPICIOUS_DOWNLOAD_OFFERED: { title: "Suspicious download offered", body: "The page links to an executable/installer in a context where that's unusual.", sev: "medium" },
  OBFUSCATED_JS_DETECTED: { title: "Obfuscated JavaScript", body: "Script content combines eval and atob patterns typical of obfuscated malware loaders.", sev: "medium" },
  HIDDEN_IFRAME_CROSS_ORIGIN: { title: "Hidden cross-origin iframe", body: "A cross-origin iframe is loaded but hidden from view.", sev: "medium" },
  OVERLAY_CLICKJACK: { title: "Possible clickjack overlay", body: "A full-viewport transparent element is intercepting clicks.", sev: "high" },
  POPUP_STORM_DETECTED: { title: "Popup storm", body: "The page tried to open multiple windows without user interaction.", sev: "high" },
  CLIPBOARD_HIJACK_ATTEMPT: { title: "Clipboard tampering", body: "The page wrote to the user's clipboard without consent.", sev: "high" },
  ULTRA_NOT_CLEARED: { title: "Ultra mode: full clearance not earned", body: "Ultra mode requires every verification gate to affirmatively pass. See the checklist for which gates didn't pass.", sev: "medium" },
};

function el(tag, opts, ...children) {
  const e = document.createElement(tag);
  if (opts?.className) e.className = opts.className;
  if (opts?.text != null) e.textContent = opts.text;
  for (const c of children) {
    if (c == null) continue;
    if (typeof c === "string") e.appendChild(document.createTextNode(c));
    else e.appendChild(c);
  }
  return e;
}
function setText(id, t) { const n = document.getElementById(id); if (n) n.textContent = t; }
function show(id) { const n = document.getElementById(id); if (n) n.hidden = false; }
function clearChildren(n) { while (n.firstChild) n.removeChild(n.firstChild); }

function setImageSrc(id, url) {
  const img = document.getElementById(id);
  if (!img) return;
  if (!isHttpURL(url)) { img.hidden = true; return; }
  img.onerror = () => { img.hidden = true; };
  img.src = url;
}

const p = new URLSearchParams(location.search);
const rawU = p.get("u") || "";
// The "url" used for actions (location.href etc.) must pass isHttpURL.
// The "url" displayed to the user must show SOMETHING even when the raw
// value fails the http check — otherwise the user has no idea what was
// warned (the most common confusion in the v0.3.1 RUAT session).
const url = isHttpURL(rawU) ? rawU : "";
const urlForDisplay = rawU || "(unknown URL)";
const reasonText = p.get("r") || "";
const evidenceId = p.get("e") || "";
const brand = p.get("b") || "";
const score = p.get("s") || "";
const codesCSV = p.get("c") || "";

setText("url", urlForDisplay);
setText("evidenceIdFooter", evidenceId || "(none)");
if (reasonText) setText("reason", reasonText);

const initialCodes = codesCSV ? codesCSV.split(",").filter(Boolean) : [];

if (brand) {
  show("brandRow");
  setText("brand", brand);
  setText("score", score ? Math.round(parseFloat(score) * 100) + "%" : "—");
}

renderSignals(initialCodes);
renderChecklistFromCodes(initialCodes, null);

if (evidenceId) {
  fetchAndRender(evidenceId).catch((e) => {
    console.warn("warn: evidence fetch failed", e);
  });
}

let remaining = 5;
const btn = document.getElementById("proceed");
const cd = document.getElementById("cd");
const tick = setInterval(() => {
  remaining -= 1;
  if (remaining <= 0) {
    clearInterval(tick);
    cd.textContent = "";
    btn.disabled = false;
  } else {
    cd.textContent = "(" + remaining + ")";
  }
}, 1000);

document.getElementById("goBackBtn")?.addEventListener("click", () => history.back());

btn.addEventListener("click", () => {
  if (btn.disabled) return;
  if (!isHttpURL(url)) return;
  try {
    chrome.runtime.sendMessage({ kind: "warn_overridden", url, codes: initialCodes });
  } catch {}
  location.href = url;
});

async function fetchAndRender(id) {
  const cfg = await chrome.storage.local.get({ portalApiBase: "http://135.181.79.11:18081" });
  const raw = cfg.portalApiBase || "http://135.181.79.11:18081";
  if (!/^https?:\/\/[^\s]+$/i.test(raw.trim())) throw new Error("invalid portal base");
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
    target.textContent = "No reason codes attached.";
    return;
  }
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...codes].sort((a, b) => (sevRank[REASONS[a]?.sev || "medium"] ?? 2) - (sevRank[REASONS[b]?.sev || "medium"] ?? 2));
  for (const code of sorted) {
    const meta = REASONS[code] || { title: code, body: "Detector triggered (no description registered).", sev: "medium" };
    const card = el("div", { className: "signal sev-" + meta.sev });
    card.appendChild(el("div", { className: "signal-code", text: code }));
    card.appendChild(el("div", { className: "signal-title", text: meta.title }));
    card.appendChild(el("div", { className: "signal-body", text: meta.body }));
    target.appendChild(card);
  }
}

function checklistRow(state, title, body) {
  const icon = state === "pass" ? "✓" : state === "fail" ? "✗" : state === "warn" ? "!" : "·";
  const cell = el("div", { className: "check " + state });
  cell.appendChild(el("div", { className: "check-icon", text: icon }));
  const right = el("div");
  right.appendChild(el("div", { className: "check-title", text: title }));
  right.appendChild(el("div", { className: "check-body", text: body }));
  cell.appendChild(right);
  return cell;
}

function renderChecklistFromCodes(codes, ev) {
  const dest = document.getElementById("checks");
  clearChildren(dest);
  if (ev?.clearance_checks && typeof ev.clearance_checks === "object") {
    const labels = {
      feed: ["Threat-intel feeds", "On at least one community/commercial threat feed.", "Not on any of our ingested threat-intel feeds."],
      vendor_dns: ["Security DNS providers", "Two or more independent protective-DNS providers block this domain.", "No protective-DNS provider blocks this domain."],
      domain_age: ["Domain age", "Domain was registered recently — fresh-registration pattern.", "Domain is established."],
      hostname_shape: ["Hostname analysis", "Hostname looks random / raw-IP / botnet pattern.", "Hostname pattern looks normal."],
      visual: ["Visual brand match", "Page visually replicates a brand it isn't authorized to use.", "Does not visually replicate any protected brand."],
      identity: ["Identity binding", "Hosting domain / ASN / cert doesn't match the impersonated brand.", "Hosting identity is consistent."],
      behavior: ["Page behavior", "Sandbox detected abusive runtime behavior.", "No abusive runtime behavior detected."],
      trust: ["Positive trust signal", "(unknown)", "Host is in the curated trust registry."],
    };
    const order = ["feed", "vendor_dns", "domain_age", "hostname_shape", "visual", "identity", "behavior", "trust"];
    for (const key of order) {
      const state = ev.clearance_checks[key] || "unknown";
      const meta = labels[key]; if (!meta) continue;
      const body = state === "fail" || state === "warn" ? meta[1] : state === "pass" ? meta[2] : "(could not verify)";
      dest.appendChild(checklistRow(state, meta[0], body));
    }
    return;
  }
  const has = (c) => codes.includes(c);
  dest.appendChild(checklistRow(has("EXTERNAL_FEED_HIT") ? "fail" : "pass", "Threat-intel feeds",
    has("EXTERNAL_FEED_HIT") ? "On a community feed." : "Not on any of our ingested feeds."));
  dest.appendChild(checklistRow(has("VENDOR_DNS_SINGLE_HIT") ? "warn" : "pass", "Security DNS providers",
    has("VENDOR_DNS_SINGLE_HIT") ? "One provider blocks this domain (advisory)." : "No protective-DNS provider blocks this domain."));
  dest.appendChild(checklistRow(has("FRESH_DOMAIN") ? "fail" : "unknown", "Domain age",
    has("FRESH_DOMAIN") ? "Domain registered very recently." : "Registration date not available."));
  dest.appendChild(checklistRow(has("RANDOM_HOSTNAME") ? "warn" : "pass", "Hostname analysis",
    has("RANDOM_HOSTNAME") ? "Hostname looks randomly generated." : "Hostname pattern looks normal."));
}

function renderEvidence(ev) {
  if (typeof ev.verdict_confidence === "number") {
    const c = document.getElementById("confBadge");
    c.hidden = false;
    c.textContent = Math.round(ev.verdict_confidence * 100) + "% confidence";
  }
  if (Array.isArray(ev.reason_codes) && ev.reason_codes.length) {
    renderSignals(ev.reason_codes);
    renderChecklistFromCodes(ev.reason_codes, ev);
  }
  if (ev.screenshot_url) {
    show("compareHeader"); show("compareGrid");
    setImageSrc("badShot", ev.screenshot_url);
    if (ev.brand_reference_screenshot && ev.visual_top_brand) {
      setImageSrc("goodShot", ev.brand_reference_screenshot);
      setText("goodHead", "Real " + ev.visual_top_brand + " reference");
      const sc = typeof ev.visual_top_score === "number" ? " · similarity " + Math.round(ev.visual_top_score * 100) + "%" : "";
      setText("goodMeta", "Curated brand reference" + sc);
    } else {
      const goodImg = document.getElementById("goodShot");
      if (goodImg) goodImg.hidden = true;
      setText("goodHead", "No brand reference");
      setText("goodMeta", "No protected brand matched — nothing to compare against.");
    }
  }
  if (ev.final_url && ev.final_url !== ev.url) { show("finalRow"); setText("finalUrl", ev.final_url); }
  if (ev.visual_top_brand) { show("brandRow"); setText("brand", ev.visual_top_brand); setText("score", ev.visual_top_score ? Math.round(ev.visual_top_score * 100) + "%" : "—"); }
  if (ev.page_class && ev.page_class !== "generic") { show("pageClassRow"); setText("pageClass", ev.page_class); }
  if (typeof ev.domain_age_days === "number") {
    show("ageRow");
    const b = document.getElementById("ageBadge");
    if (ev.domain_age_days < 30) { b.className = "age-badge fresh"; b.textContent = "Registered " + formatAge(ev.domain_age_days) + " ago"; }
    else if (ev.domain_age_days < 180) { b.className = "age-badge young"; b.textContent = formatAge(ev.domain_age_days) + " old"; }
    else { b.className = "age-badge aged"; b.textContent = formatAge(ev.domain_age_days) + " old"; }
    if (ev.registered_at) setText("ageDetail", "(registered " + new Date(ev.registered_at).toISOString().slice(0, 10) + ")");
  }
  if (ev.registrar) { show("registrarRow"); setText("registrar", ev.registrar); }
  if (ev.current_asn) { show("asnRow"); setText("asn", "AS" + ev.current_asn); }
  if (ev.cert_issuer) { show("certRow"); setText("cert", ev.cert_issuer); }
  if (Array.isArray(ev.vendor_dns_blocked_by) && ev.vendor_dns_blocked_by.length) {
    show("vendorDNSRow");
    const dest = document.getElementById("vendorDNS");
    clearChildren(dest);
    for (const n of ev.vendor_dns_blocked_by) dest.appendChild(el("span", { className: "provider-tag", text: n }));
  }
}

function formatAge(days) {
  if (days < 1) return "less than a day";
  if (days < 30) return days + " day" + (days === 1 ? "" : "s");
  if (days < 365) { const m = Math.floor(days / 30); return m + " month" + (m === 1 ? "" : "s"); }
  const y = Math.floor(days / 365);
  return y + " year" + (y === 1 ? "" : "s");
}
