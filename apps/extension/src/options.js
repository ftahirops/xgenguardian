// options.js — settings UI for XGenGuardian extension.
//
// Five protection modes with progressively stricter category defaults:
//   normal      — security only (current default; safe for general adults)
//   safe        — + blocks adult + popunder ad networks
//   family      — + blocks gambling
//   strict      — + blocks piracy / crack / keygen / warez
//   paranoid    — + sensitive pages on unknown hosts default to ISOLATE
//
// Each mode flips the per-category defaults; user can override individual
// categories after picking. The mode + category overrides are sent to
// verdict-api with every /v1/check so the policy engine honors them.

// --- defaults ---
const defaults = {
  apiBase: "http://135.181.79.11:18080",
  portalApiBase: "http://135.181.79.11:18081",
  enabled: true,
  enforceWarn: false,
  telemetry: true,
  mode: "safe",
  categories: {
    adult: true,
    popunder: true,
    gambling: false,
    piracy: false,
    crack_keygen: false,
    malvertising: true,
    unknown_sensitive_isolate: false,
  },
};

// --- mode definitions ---
const MODES = [
  {
    id: "normal",
    name: "Normal",
    badge: null,
    desc: "Security threats only — phishing, malware, scams, brand impersonation. Allows adult, gambling, piracy.",
    blocks: ["phishing", "malware", "scams", "brand impersonation"],
    cats: { adult: false, popunder: false, gambling: false, piracy: false, crack_keygen: false, malvertising: true, unknown_sensitive_isolate: false },
    dns: { name: "Cloudflare 1.1.1.1 or Quad9 9.9.9.9", v4: ["1.1.1.1", "1.0.0.1"], note: "General-purpose recursive DNS." },
  },
  {
    id: "safe",
    name: "Safe",
    badge: "recommended",
    desc: "Security + adult + popunder ad networks (random-redirect malware bait). Best default for most users.",
    blocks: ["security", "adult", "popunder ad networks"],
    cats: { adult: true, popunder: true, gambling: false, piracy: false, crack_keygen: false, malvertising: true, unknown_sensitive_isolate: false },
    dns: { name: "Cloudflare Family — Security only", v4: ["1.1.1.2", "1.0.0.2"], note: "Malware + adult phishing blocking; family content still allowed." },
  },
  {
    id: "family",
    name: "Family",
    badge: null,
    desc: "Safe + gambling. Suitable for shared/household devices.",
    blocks: ["security", "adult", "popunder", "gambling"],
    cats: { adult: true, popunder: true, gambling: true, piracy: false, crack_keygen: false, malvertising: true, unknown_sensitive_isolate: false },
    dns: { name: "Cloudflare Family", v4: ["1.1.1.3", "1.0.0.3"], note: "Malware + adult + family-unsafe blocking. The standard family-DNS pick." },
  },
  {
    id: "strict",
    name: "Strict",
    badge: null,
    desc: "Family + piracy / torrent / crack / keygen. For corporate or child devices.",
    blocks: ["security", "adult", "popunder", "gambling", "piracy", "crack_keygen"],
    cats: { adult: true, popunder: true, gambling: true, piracy: true, crack_keygen: true, malvertising: true, unknown_sensitive_isolate: false },
    dns: { name: "OpenDNS Family Shield", v4: ["208.67.222.123", "208.67.220.123"], note: "Adult + family-unsafe at the DNS layer." },
  },
  {
    id: "paranoid",
    name: "Paranoid",
    badge: null,
    desc: "Everything Strict blocks + unknown sensitive pages (login/payment/OAuth on unverified hosts) open in isolation by default.",
    blocks: ["everything in Strict", "unknown sensitive → ISOLATE"],
    cats: { adult: true, popunder: true, gambling: true, piracy: true, crack_keygen: true, malvertising: true, unknown_sensitive_isolate: true },
    dns: { name: "NextDNS or AdGuard DNS", v4: ["94.140.14.14", "94.140.15.15"], note: "AdGuard Family / NextDNS profile with full filtering. Configurable per-device for max coverage." },
  },
];

// --- category definitions ---
const CATEGORIES = [
  { id: "adult", name: "Adult content", meta: "porn, NSFW imageboards — ~28k domains from StevenBlack adult list" },
  { id: "popunder", name: "Popunder / random-redirect ad networks", meta: "popads, exoclick, juicyads, iknowthatgirl, etc." },
  { id: "gambling", name: "Gambling / casino", meta: "online casinos, sportsbook, poker rooms" },
  { id: "piracy", name: "Piracy / torrent / warez", meta: "thepiratebay, 1337x, rarbg, scnlog, etc." },
  { id: "crack_keygen", name: "Crack / keygen / serial-distribution", meta: "fitgirl-repacks, skidrowreloaded, getintopc, etc." },
  { id: "malvertising", name: "Malvertising networks", meta: "ad networks linked to malware delivery chains" },
  { id: "unknown_sensitive_isolate", name: "Unknown sensitive pages → ISOLATE", meta: "login/payment/OAuth on unverified hosts open in isolation" },
];

// --- DOM rendering (no innerHTML — everything via safe DOM APIs) ---

function clearChildren(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      if (k === "className") e.className = attrs[k];
      else if (k === "dataset") for (const d of Object.keys(attrs[k])) e.dataset[d] = attrs[k][d];
      else if (k.startsWith("on") && typeof attrs[k] === "function") e.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
      else e.setAttribute(k, attrs[k]);
    }
  }
  for (const c of children) {
    if (c == null) continue;
    if (typeof c === "string") e.appendChild(document.createTextNode(c));
    else e.appendChild(c);
  }
  return e;
}

function renderModes(selectedId) {
  const root = document.getElementById("modes");
  clearChildren(root);
  for (const m of MODES) {
    const head = el("div", { className: "mode-head" },
      el("div", { className: "mode-name" }, m.name),
      m.badge ? el("div", { className: "mode-badge " + m.badge }, m.badge) : null,
    );
    const desc = el("div", { className: "mode-desc" }, m.desc);
    const blocks = el("div", { className: "mode-blocks" }, "Blocks: " + m.blocks.join(" · "));
    const card = el("div", {
      className: "mode" + (m.id === selectedId ? " selected" : ""),
      dataset: { id: m.id },
      onClick: () => selectMode(m.id, true),
    }, head, desc, blocks);
    root.appendChild(card);
  }
}

function renderCategories(state) {
  const root = document.getElementById("categories");
  clearChildren(root);
  for (const c of CATEGORIES) {
    const cb = el("input", { type: "checkbox", id: "cat-" + c.id });
    cb.checked = !!state.categories[c.id];
    cb.addEventListener("change", () => { state.categories[c.id] = cb.checked; });
    const label = el("label", { for: cb.id, className: "cat-name" }, c.name);
    const head = el("div", { className: "cat-head" }, cb, label);
    const meta = el("div", { className: "cat-meta" }, c.meta);
    root.appendChild(el("div", { className: "cat" }, head, meta));
  }
}

function renderDNSRec(modeId) {
  const m = MODES.find((x) => x.id === modeId) || MODES[1];
  const root = document.getElementById("dns-rec");
  clearChildren(root);
  root.appendChild(el("div", { className: "dns-rec-head" }, m.dns.name));
  const ip = el("div");
  ip.style.cssText = "margin-top:6px;color:#bcc3d0;font-size:13px;";
  for (const v4 of m.dns.v4) {
    ip.appendChild(el("code", null, v4));
    ip.appendChild(document.createTextNode(" "));
  }
  root.appendChild(ip);
  const note = el("div", null, m.dns.note);
  note.style.cssText = "margin-top:8px;color:#9aa3b2;font-size:12px;";
  root.appendChild(note);
  const howto = el("div", null,
    "Set this DNS at your router (covers all devices) or OS network settings. XGenGuardian operates independently of DNS but pairs well with these providers.");
  howto.style.cssText = "margin-top:10px;color:#6f7787;font-size:11px;";
  root.appendChild(howto);
}

// --- state + persistence ---

let state = JSON.parse(JSON.stringify(defaults));

function selectMode(id, applyDefaults) {
  state.mode = id;
  if (applyDefaults) {
    const m = MODES.find((x) => x.id === id);
    if (m) state.categories = JSON.parse(JSON.stringify(m.cats));
  }
  renderModes(id);
  renderCategories(state);
  renderDNSRec(id);
}

async function load() {
  const stored = await new Promise((res) => chrome.storage.local.get(defaults, res));
  state = {
    ...defaults,
    ...stored,
    categories: { ...defaults.categories, ...(stored.categories || {}) },
  };
  document.getElementById("apiBase").value = state.apiBase;
  document.getElementById("portalApiBase").value = state.portalApiBase;
  document.getElementById("enabled").checked = state.enabled;
  document.getElementById("enforceWarn").checked = state.enforceWarn;
  document.getElementById("telemetry").checked = state.telemetry;
  selectMode(state.mode || "safe", false);
}

async function save() {
  state.apiBase = document.getElementById("apiBase").value || defaults.apiBase;
  state.portalApiBase = document.getElementById("portalApiBase").value || defaults.portalApiBase;
  state.enabled = document.getElementById("enabled").checked;
  state.enforceWarn = document.getElementById("enforceWarn").checked;
  state.telemetry = document.getElementById("telemetry").checked;
  await new Promise((res) => chrome.storage.local.set(state, res));
  const el = document.getElementById("saved");
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 1200);
}

document.getElementById("save").addEventListener("click", save);
load();
