// XGenGuardian — MV3 background service worker.
//
// Architecture (docs/UNIFIED-PLAN.md §3, §7):
//   1. Top-level navigation → swap to holding.html → poll verdict → route to
//      ALLOW / WARN / BLOCK / ISOLATE page.
//   2. New tab / popup / middle-click → onCreatedNavigationTarget fires →
//      swap to holding.html with opener context → apply §3.1 decision matrix
//      including BLOCKED_OPENER_LINEAGE and UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER.
//   3. Sensitive page classes (login/payment/oauth/admin/download) bypass the
//      ALLOW cache and force revalidation every visit.
//
// Cache lives in chrome.storage.session (cleared on browser restart) keyed by
// URL SHA-256. ALLOW entries TTL 5 min, BLOCK entries TTL 1 h. Sensitive URLs
// are never cached.

// Operator's VPS — UFW restricts inbound 18080 to trusted IPs only.
// Override via the Options page when running against a different deployment.
//
// SECURITY NOTE: the default endpoint is plaintext HTTP. This is a known
// MITM risk (audit FINDING #3 — CRITICAL): an attacker on the user's
// network path can return { verdict: "ALLOW" } for any URL, neutralizing
// the extension silently. The right long-term fix is to put nginx + Let's
// Encrypt in front of verdict-api and switch this default to https://.
// Until then, validateAPIBase rejects everything OTHER than http(s):// so
// javascript:/data:/file:/chrome: schemes cannot reach fetch(), and
// fetchVerdict warns loudly on every HTTP call so the operator is aware.
const DEFAULT_API       = "http://135.181.79.11:18080";
const DEFAULT_PORTAL_API = "http://135.181.79.11:18081";

// validateAPIBase — accept only http(s):// URLs. Returns null when the
// input is anything else (javascript:, data:, file:, chrome:, blob:, etc.)
// so the caller fails closed instead of fetching from an attacker-supplied
// scheme. Used to gate apiBase / portalApiBase reads.
function validateAPIBase(s) {
  if (typeof s !== "string") return null;
  const u = s.trim();
  if (!/^https?:\/\/[^\s]+$/i.test(u)) return null;
  return u.replace(/\/+$/, ""); // strip trailing slash
}

// Module-level "already warned" flag so we don't spam the console on every
// fetch. Reset on service-worker restart, which is fine — one warning per
// SW lifetime is enough to notify the operator.
let _warnedAboutHTTP = false;
function warnIfInsecure(u) {
  if (u.startsWith("http://") && !_warnedAboutHTTP) {
    _warnedAboutHTTP = true;
    console.warn(
      "[xgg] verdict-api is configured over plaintext HTTP (" + u + "). " +
      "A network-path attacker can return ALLOW for any URL. " +
      "Use HTTPS in production — see README for the nginx + Let's Encrypt setup."
    );
  }
}
const ALLOW_TTL_MS  = 5 * 60 * 1000;
const BLOCK_TTL_MS  = 60 * 60 * 1000;
const WARN_TTL_MS   = 30 * 60 * 1000; // WARN/ISOLATE — longer than ALLOW, shorter than BLOCK
const VERDICT_TIMEOUT_MS = 4000;

// URL substring → page_class. Order matters (first match wins).
const SENSITIVE_PATTERNS = [
  { re: /\/oauth|\/authorize|\/consent/i,                class: "oauth" },
  { re: /\/login|\/signin|\/sign-in|\/log-in/i,          class: "login" },
  { re: /\/verify|\/mfa|\/2fa|\/recover|\/reset/i,       class: "login" },
  { re: /\/payment|\/pay|\/checkout|\/billing/i,         class: "payment" },
  { re: /\/admin|\/dashboard|\/console/i,                class: "admin" },
  { re: /\/download/i,                                   class: "download" },
];

// ---------- helpers ----------

// settings() — single source of truth for user preferences. ALL reads and
// writes across the extension (background.js, popup.js, blocked.js,
// isolate.js, options.js) MUST go through chrome.storage.local so updates
// in any surface are visible to every other surface.
//
// History: previously this code used chrome.storage.sync while options.js
// used chrome.storage.local — the two stores never communicated, so EVERY
// setting the user changed in Options was silently ignored. Found in the
// audit (FINDING #7). All references migrated below.
//
// Module-level cache (FINDING #22): every navigation previously caused a
// full chrome.storage.local.get round-trip. The MV3 service worker lives
// only ~30 s between events; a cache valid for that lifetime eliminates
// redundant reads without risking stale values surviving a restart.
let _settingsCache = null;
let _settingsCacheAt = 0;
const SETTINGS_CACHE_TTL_MS = 30 * 1000;

// Invalidate whenever the user changes any setting — storage.onChanged fires
// synchronously in the same SW activation as the write, so the next read
// after a settings change will always fetch fresh values.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") {
    _settingsCache = null;
  }
});

async function settings() {
  if (_settingsCache && Date.now() - _settingsCacheAt < SETTINGS_CACHE_TTL_MS) {
    return _settingsCache;
  }
  _settingsCache = await chrome.storage.local.get({
    apiBase:        DEFAULT_API,
    portalApiBase:  DEFAULT_PORTAL_API,
    enabled:        true,
    enforceWarn:    false,
    telemetry:      true,
    mode:           "safe",
    categories:     {
      adult: true, popunder: true, gambling: false, piracy: false,
      crack_keygen: false, malvertising: true, unknown_sensitive_isolate: false,
    },
    paranoidMode:   false, // legacy Executive Mode toggle (§4.4)
    userAllowlist:  "",    // permanent allowlist; see parseAllowlist()
  });
  _settingsCacheAt = Date.now();
  return _settingsCache;
}

async function sha256(text) {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function pageClassOf(url) {
  for (const { re, class: cls } of SENSITIVE_PATTERNS) {
    if (re.test(url)) return cls;
  }
  return "generic";
}

function isSensitive(url) {
  return pageClassOf(url) !== "generic";
}

// WELL_KNOWN_AUTH_HOSTS — high-trust authentication providers that we
// intentionally pass through without scanning. Two reasons:
//
//   1. These are the brands phishing campaigns IMPERSONATE. The real
//      hostnames (e.g. accounts.google.com) are inherently trusted; an
//      attacker hosting a fake Google login is on a *different* host
//      that we DO scan.
//
//   2. OAuth handshakes are timing- and state-sensitive. A holding-page
//      redirect between the OAuth init and the provider's challenge
//      page breaks flows where the parent window is waiting for a
//      specific popup-window state (Tailscale → Google, Slack → Apple,
//      etc.). The intermediate `tabs.update` to chrome-extension://
//      kills cross-window handles and prevents the parent from observing
//      the callback completing.
//
// We use full-hostname matches and explicit subdomain entries instead
// of suffix matching so an attacker can't register e.g.
// `accounts.google.com.evil.tld` and slip through.
const WELL_KNOWN_AUTH_HOSTS = new Set([
  // Google
  "accounts.google.com", "oauth2.googleapis.com", "myaccount.google.com",
  "ssl.gstatic.com",
  // Microsoft
  "login.microsoftonline.com", "login.live.com", "login.microsoft.com",
  "login.windows.net", "account.microsoft.com", "account.live.com",
  // Microsoft Safe Links — enterprise Outlook wraps every email link
  // through this service. Always redirects to the actual destination;
  // intercepting the wrapper just adds delay + breaks the redirect
  // chain. The destination URL itself is checked when the browser
  // follows the 302. ind01/eur02/nam02/etc. are regional prefixes.
  "safelinks.protection.outlook.com",
  "nam01.safelinks.protection.outlook.com",
  "nam02.safelinks.protection.outlook.com",
  "nam03.safelinks.protection.outlook.com",
  "nam04.safelinks.protection.outlook.com",
  "nam06.safelinks.protection.outlook.com",
  "nam10.safelinks.protection.outlook.com",
  "nam11.safelinks.protection.outlook.com",
  "nam12.safelinks.protection.outlook.com",
  "eur01.safelinks.protection.outlook.com",
  "eur02.safelinks.protection.outlook.com",
  "eur03.safelinks.protection.outlook.com",
  "eur04.safelinks.protection.outlook.com",
  "eur05.safelinks.protection.outlook.com",
  "ind01.safelinks.protection.outlook.com",
  "apc01.safelinks.protection.outlook.com",
  "jpn01.safelinks.protection.outlook.com",
  "aus01.safelinks.protection.outlook.com",
  "can01.safelinks.protection.outlook.com",
  "gbr01.safelinks.protection.outlook.com",
  // Microsoft invitations / B2B redeem flow (the destination of safelinks)
  "invitations.microsoft.com", "myapplications.microsoft.com",
  // Proofpoint URL Defense — used by enterprise mail filters; same flow
  // as safelinks. The destination is encoded in the URL parameter.
  "urldefense.proofpoint.com", "urldefense.com",
  // Cisco Secure Email (was IronPort) URL rewriting
  "secure-web.cisco.com", "linkprotect.cudasvc.com",
  // Symantec / Broadcom Email Security
  "clicktime.symantec.com", "click.email.symantec.com",
  // Mimecast email security
  "protect-eu.mimecast.com", "protect-us.mimecast.com",
  "protect-au.mimecast.com", "protect.mimecast.com",
  // Barracuda
  "linkprotect.cudasvc.com",
  // Sophos / Reflexion
  "url.emailprotection.link", "messages.reflexion.net",
  // Apple
  "appleid.apple.com", "idmsa.apple.com",
  // GitHub
  "github.com",       // /login/oauth/* — domain is trusted as a whole
  "api.github.com",
  // GitLab / Bitbucket / Atlassian
  "gitlab.com", "bitbucket.org", "id.atlassian.com", "auth.atlassian.com",
  // Okta / Auth0 / Duo / OneLogin (these are tenant-prefixed so we let
  // the trustreg + brand-host graph on the server decide; only block
  // page bypass on the canonical SSO domains here)
  "duosecurity.com", "duo.com", "duosecurity.net",
  // Slack, Discord, Notion, Linear, Figma, Vercel auth surfaces
  "slack.com", "discord.com", "notion.so", "linear.app", "figma.com",
  "vercel.com",
  // Cloud-provider consoles (these are not phishing targets at the
  // provider's own canonical domain; their tenant subdomains may be
  // and remain scanned at the brandgraph layer).
  "console.cloud.google.com", "console.aws.amazon.com",
  "portal.azure.com", "signin.aws.amazon.com",
]);

function isWellKnownAuthHost(hostname) {
  return WELL_KNOWN_AUTH_HOSTS.has(hostname);
}

function shouldSkipURL(url) {
  if (!/^https?:/.test(url)) return true;
  if (url.startsWith(chrome.runtime.getURL(""))) return true;
  // chrome-error://, chrome://, view-source:, about:, etc. — these are
  // internal browser pages. Crucially, chrome-error://chromewebdata/...
  // is what Chrome shows when DNS fails / connection refused. Without
  // this skip, our extension intercepts the error page itself, queues
  // a verdict request, then when the user retries we re-loop. Skipping
  // here breaks the cycle and lets Chrome's native error UI stand.
  if (/^chrome-?(error|search|untrusted|extension)?:|^view-source:|^about:|^edge:|^file:|^data:|^javascript:|^blob:|^opera:|^vivaldi:/i.test(url)) return true;
  try {
    const u = new URL(url);
    if (["localhost", "127.0.0.1", "::1"].includes(u.hostname)) return true;
    // Skip private network ranges so internal corp tools don't get held.
    if (/^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\./.test(u.hostname)) return true;
    // Pass well-known auth providers through untouched (see comment on
    // WELL_KNOWN_AUTH_HOSTS for the OAuth-flow rationale).
    if (isWellKnownAuthHost(u.hostname)) return true;
  } catch { return true; }
  return false;
}

// Two-tier verdict cache (audit FINDING #21):
//
//   Tier 1 — chrome.storage.session: fast, cleared on browser restart.
//   Tier 2 — chrome.storage.local for BLOCK verdicts only: persistent
//            across browser restarts so a known-bad URL stays blocked
//            for the full BLOCK_TTL_MS window even if the user restarts
//            Chrome mid-window.
//
// ALLOW/WARN/ISOLATE entries live only in session storage. Their TTLs are
// short enough (5min / 30min) that the post-restart re-check is fine.
// BLOCK entries (1h TTL) are mirrored to local so the protective decision
// survives restarts — phishing campaigns don't get a fresh shot every time
// the user closes their browser.
async function getCached(key) {
  const got = await chrome.storage.session.get(key);
  let e = got[key];
  if (!e) {
    // Tier-2 fallback: check persistent BLOCK cache.
    const localKey = "bl:" + key;
    const localGot = await chrome.storage.local.get(localKey);
    e = localGot[localKey];
    if (!e) return null;
  }
  let ttl;
  switch (e.v?.verdict) {
    case "BLOCK":   ttl = BLOCK_TTL_MS; break;
    case "WARN":
    case "ISOLATE": ttl = WARN_TTL_MS;  break;
    default:        ttl = ALLOW_TTL_MS;
  }
  if (Date.now() - e.t > ttl) {
    // Stale — best-effort cleanup of the persistent copy if present.
    chrome.storage.local.remove("bl:" + key).catch(() => {});
    return null;
  }
  return e.v;
}

async function setCached(key, verdict) {
  const entry = { v: verdict, t: Date.now() };
  await chrome.storage.session.set({ [key]: entry });
  // Mirror BLOCK verdicts to persistent storage (Tier-2).
  if (verdict?.verdict === "BLOCK") {
    await chrome.storage.local.set({ ["bl:" + key]: entry });
  }
}

// --- "just verified" pass-through ---
//
// Sensitive URLs (login, payment, oauth, admin) intentionally bypass the
// long-lived verdict cache so we re-evaluate every visit. But after the
// holding page applies an ALLOW verdict via tabs.update(target), Chrome
// fires onBeforeNavigate for `target` again — which would route us right
// back to holding, creating an infinite reload loop on every login page.
//
// Solution: when we APPLY an ALLOW verdict, stamp a short-lived (10s)
// pass token for the exact URL. onBeforeNavigate consumes it once and
// lets that single navigation through, then the token expires and normal
// re-verify behavior resumes for subsequent visits.
const JUST_VERIFIED_TTL_MS = 10 * 1000;

// normalizeForToken — strip fragment and trailing slash before hashing.
// Chrome's webNavigation events may strip the fragment, causing a mismatch
// between the URL stamped at apply time and the URL seen at navigate time
// (FINDING #24). Normalizing both sides ensures the token is always found.
function normalizeForToken(url) {
  try {
    const u = new URL(url);
    u.hash = "";
    return u.toString().replace(/\/+$/, "");
  } catch {
    return url.split("#")[0].replace(/\/+$/, "");
  }
}

async function stampJustVerified(url) {
  const key = "jv:" + (await sha256(normalizeForToken(url)));
  await chrome.storage.session.set({ [key]: Date.now() });
}

async function consumeJustVerified(url) {
  const key = "jv:" + (await sha256(normalizeForToken(url)));
  const got = await chrome.storage.session.get(key);
  const t = got[key];
  if (!t) return false;
  // One-shot: remove immediately so we re-verify next time.
  await chrome.storage.session.remove(key);
  return (Date.now() - t) <= JUST_VERIFIED_TTL_MS;
}

// --- Ultra mode: 24h ALLOW_TEMP per-host override ---
//
// When the user clicks "Allow for 24h" on the isolation page, the host
// is stored here. The 24h cache lives in chrome.storage.local so it
// survives browser restart. On every navigation we check this cache
// FIRST — if the host is on the allowlist and the TTL hasn't expired,
// we return ALLOW without calling verdict-api.
//
// Scope is per HOSTNAME (not per URL) — once a user trusts mybank.com,
// every path on mybank.com bypasses verdict during the window.
const ALLOW_TEMP_TTL_MS = 24 * 60 * 60 * 1000;

// --- User-managed permanent allowlist ---
//
// Comma/newline-separated entries the user added in Options. Supports four
// match types:
//   exact hostname:  "opencode.ai"
//   suffix match:    ".mycorp.com"   (matches any subdomain of mycorp.com)
//   exact IP:        "135.181.79.27" (port-agnostic)
//   CIDR block:      "10.0.0.0/8"
//
// Matched URLs bypass ALL scanning — no holding page, no verdict-api call,
// nothing. This is the relief valve for self-hosted / dev tools / corp
// intranets that the operator wants to permanently trust.
function parseAllowlist(raw) {
  if (!raw) return { hosts: new Set(), suffixes: [], ips: new Set(), cidrs: [] };
  const hosts = new Set();
  const suffixes = [];
  const ips = new Set();
  const cidrs = [];
  for (const line of raw.split(/[\r\n,]+/)) {
    const t = line.trim().toLowerCase();
    if (!t || t.startsWith("#")) continue;
    if (t.includes("/") && /^[\d.]+\/\d+$/.test(t)) {
      cidrs.push(t);
    } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
      ips.add(t);
    } else if (t.startsWith(".")) {
      suffixes.push(t);
    } else {
      hosts.add(t);
    }
  }
  return { hosts, suffixes, ips, cidrs };
}

function ipInCIDR(ip, cidr) {
  try {
    const [base, bitsStr] = cidr.split("/");
    const bits = parseInt(bitsStr, 10);
    if (!Number.isFinite(bits) || bits < 0 || bits > 32) return false;
    const toInt = (s) => s.split(".").reduce((a, o) => (a << 8) + (+o), 0) >>> 0;
    const ipi = toInt(ip);
    const basei = toInt(base);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (ipi & mask) === (basei & mask);
  } catch { return false; }
}

async function isUserAllowlisted(url) {
  let host;
  try { host = new URL(url).hostname.toLowerCase(); } catch { return false; }
  const cfg = await settings();
  const list = parseAllowlist(cfg.userAllowlist || "");
  if (list.hosts.has(host)) return true;
  for (const sfx of list.suffixes) {
    if (host === sfx.slice(1) || host.endsWith(sfx)) return true;
  }
  if (list.ips.has(host)) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    for (const c of list.cidrs) {
      if (ipInCIDR(host, c)) return true;
    }
  }
  return false;
}

async function isAllowTemp(url) {
  try {
    const host = new URL(url).hostname;
    if (!host) return false;
    const key = "at:" + host;
    const got = await chrome.storage.local.get(key);
    const t = got[key];
    if (!t) return false;
    if (Date.now() - t > ALLOW_TEMP_TTL_MS) {
      chrome.storage.local.remove(key).catch(() => {});
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function setAllowTemp(url) {
  try {
    const host = new URL(url).hostname;
    if (!host) return;
    await chrome.storage.local.set({ ["at:" + host]: Date.now() });
  } catch {}
}

// ---------- Phase B: browser remote-IP capture ----------
//
// Connection identity (docs/final-engine-architecture-plan.md §6-8) requires
// the *actual* IP the browser connected to — not what the backend resolver
// would have answered. Backend-only DNS misses local hijack, router
// compromise, VPN DNS override, hosts-file tampering, and browser DoH bypass.
//
// chrome.webRequest.onResponseStarted provides details.ip for the main_frame
// request, which is the IP the browser actually reached. We cache it keyed by
// host and read it back in fetchVerdict.
//
// Cache shape: { host: { ip, ts } }. Entries older than HOST_IP_TTL_MS are
// ignored. The map is bounded by HOST_IP_MAX_ENTRIES via FIFO eviction so a
// long-lived service worker can't grow it unbounded.
const HOST_IP_TTL_MS = 5 * 60 * 1000;
const HOST_IP_MAX_ENTRIES = 256;
const hostRemoteIP = new Map(); // insertion-ordered → FIFO eviction
function rememberHostIP(host, ip) {
  if (!host || !ip) return;
  if (hostRemoteIP.size >= HOST_IP_MAX_ENTRIES) {
    // Drop oldest entry.
    const oldest = hostRemoteIP.keys().next().value;
    if (oldest !== undefined) hostRemoteIP.delete(oldest);
  }
  // Re-insert to refresh insertion order.
  hostRemoteIP.delete(host);
  hostRemoteIP.set(host, { ip, ts: Date.now() });
}
function recentRemoteIP(host) {
  const e = hostRemoteIP.get(host);
  if (!e) return "";
  if (Date.now() - e.ts > HOST_IP_TTL_MS) {
    hostRemoteIP.delete(host);
    return "";
  }
  return e.ip || "";
}
try {
  // main_frame only — the IP we care about for connection identity is the
  // one serving the document the user is on. Subresource IPs are noise.
  chrome.webRequest.onResponseStarted.addListener(
    (details) => {
      try {
        if (details.type !== "main_frame") return;
        const host = new URL(details.url).hostname;
        if (details.ip) rememberHostIP(host, details.ip);
      } catch {}
    },
    { urls: ["<all_urls>"], types: ["main_frame"] }
  );
} catch {
  // webRequest may be unavailable in some test harnesses; degrade silently.
}

async function fetchVerdict(url, opener) {
  const cfg = await settings();
  // FAIL-SAFE scheme gate (audit FINDING #3). Reject any non-http(s)://
  // apiBase before it reaches fetch(). Without this, a malicious or
  // misconfigured value like javascript: or file:// could be used as the
  // request base, with surprising consequences.
  const apiBase = validateAPIBase(cfg.apiBase);
  if (!apiBase) {
    return { verdict: "ANALYZING", error: "invalid apiBase configured" };
  }
  warnIfInsecure(apiBase);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), VERDICT_TIMEOUT_MS);
  try {
    const r = await fetch(`${apiBase}/v1/check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        url,
        client_id: "extension/0.2.0",
        opener_url: opener || undefined,
        paranoid: (cfg.mode === "paranoid") || cfg.paranoidMode || undefined,
        mode: cfg.mode || "normal",
        categories: cfg.categories || undefined,
        browser_remote_ip: (() => {
          try { return recentRemoteIP(new URL(url).hostname) || undefined; }
          catch { return undefined; }
        })(),
      }),
      signal: ctrl.signal,
    });
    if (!r.ok) return { verdict: "ANALYZING", error: `upstream ${r.status}` };
    return await r.json();
  } catch (e) {
    return { verdict: "ANALYZING", error: String(e) };
  } finally {
    clearTimeout(timer);
  }
}

// ---------- routing ----------

function pageFor(verdict) {
  switch (verdict?.verdict) {
    case "BLOCK":   return "blocked.html";
    case "WARN":    return "warn.html";
    case "ISOLATE": return "isolate.html";
    default:        return null; // ALLOW or ANALYZING → release/keep holding
  }
}

function interstitialURL(page, target, verdict, opener) {
  const p = new URLSearchParams();
  p.set("u", target);
  if (verdict.verdict)           p.set("v", verdict.verdict);
  if (verdict.block_reason)      p.set("r", verdict.block_reason);
  if (verdict.evidence_id)       p.set("e", verdict.evidence_id);
  if (verdict.visual_top_brand)  p.set("b", verdict.visual_top_brand);
  if (verdict.visual_top_score)  p.set("s", String(verdict.visual_top_score));
  if (Array.isArray(verdict.reason_codes)) p.set("c", verdict.reason_codes.join(","));
  if (opener)                    p.set("op", opener);
  // Phase B.6: pass connection-identity facts as query params so the
  // blocked page can render them without a portal round-trip. The full
  // record (ASN, CNAME chain, ledger entries) stays in evidence storage;
  // these are just the headline facts we already have on hand.
  if (verdict.connection_identity) {
    const ci = verdict.connection_identity;
    if (ci.browser_remote_ip)  p.set("cip", ci.browser_remote_ip);
    if (Array.isArray(ci.xgg_resolver_ips_for_client) && ci.xgg_resolver_ips_for_client.length) {
      p.set("xip", ci.xgg_resolver_ips_for_client.join(","));
    }
    if (ci.dns_path_consistent) p.set("dpc", "1");
  }
  // Phase D.3: trust score + contributors. Score 0 means "not computed";
  // anything > 0 renders the trust panel. Contributors are encoded as
  // "label1:w1|label2:w2|..." — labels are short and stable so URL length
  // stays bounded.
  if (typeof verdict.trust_score === "number" && verdict.trust_score > 0) {
    p.set("ts", verdict.trust_score.toFixed(2));
    if (Array.isArray(verdict.trust_contributors) && verdict.trust_contributors.length) {
      const enc = verdict.trust_contributors
        .map(c => `${(c.label || "").replace(/\|/g, "/")}:${(c.weight || 0).toFixed(2)}`)
        .join("|");
      p.set("tc", enc);
    }
  }
  return chrome.runtime.getURL(`src/${page}`) + "?" + p.toString();
}

function holdingURL(target, opener, openerVerdict) {
  const p = new URLSearchParams();
  p.set("target", target);
  if (opener)        p.set("opener", opener);
  if (openerVerdict) p.set("opener_verdict", openerVerdict);
  return chrome.runtime.getURL("src/holding.html") + "?" + p.toString();
}

// v0.3.5 — holding-page retry guard. Defense-in-depth against any future
// extension loop bug like the ERR_NETWORK_ACCESS_DENIED loop in v0.3.3.
// Bounds: max RETRY_INTERCEPT_LIMIT intercepts of the same URL within
// RETRY_INTERCEPT_WINDOW_MS. When the limit trips, we STOP intercepting
// and let the navigation through with a logged warning. Better to let a
// borderline-suspicious URL pass than to trap the user in an infinite
// flip between holding → /v1/check → tab.update → re-fire.
const RETRY_INTERCEPT_LIMIT     = 3;
const RETRY_INTERCEPT_WINDOW_MS = 30_000;

async function shouldThrottleIntercept(target) {
  try {
    const key = "rt:" + (await sha256(normalizeForToken(target)));
    const now = Date.now();
    const obj = await chrome.storage.session.get({ [key]: { count: 0, windowStart: now } });
    let rec = obj[key];
    if (now - rec.windowStart > RETRY_INTERCEPT_WINDOW_MS) {
      rec = { count: 0, windowStart: now };
    }
    rec.count += 1;
    await chrome.storage.session.set({ [key]: rec });
    if (rec.count > RETRY_INTERCEPT_LIMIT) {
      console.warn("XGG: retry-intercept limit exceeded for", target,
        "count=" + rec.count, "— letting navigation through to break loop");
      return true;
    }
    return false;
  } catch {
    // session storage failure is best-effort; never block the navigation.
    return false;
  }
}

// applyVerdict — decides what to do with the tab once we have a verdict.
async function applyVerdict(tabId, target, verdict, opener) {
  const page = pageFor(verdict);
  if (!page) {
    // ALLOW or ANALYZING-with-cached-allow → release to the real URL.
    // Stamp a "just verified" pass token so the imminent onBeforeNavigate
    // for `target` (Chrome fires it again after tabs.update) lets that
    // single navigation through instead of looping back to holding. This
    // is the only thing that breaks the reload loop on sensitive URLs,
    // which intentionally bypass the long-lived verdict cache.
    await stampJustVerified(target);
    await chrome.tabs.update(tabId, { url: target });
    return;
  }
  // v0.3.3 — stash the full verdict in session storage keyed by target
  // URL so the warn/blocked/isolate page can pull the decision_trace +
  // reason codes + clearance checks for rendering. URL-param transport
  // can't carry the trace (length + nested structure), so this is the
  // wire between background.js and the interstitial pages.
  await stashVerdictForPage(target, verdict);
  await chrome.tabs.update(tabId, {
    url: interstitialURL(page, target, verdict, opener),
  });
}

// ---------- v0.3.3: verdict stash for interstitial pages ----------

// Cap how many verdicts we keep in session memory. Service-worker
// session storage is per-window-session; we only need the most recent
// few to back the visible warn/blocked tabs.
const VERDICT_STASH_LIMIT = 50;
const VERDICT_STASH_KEY = "verdictStash";

async function stashVerdictForPage(url, verdict) {
  try {
    const slim = {
      verdict: verdict.verdict,
      confidence: verdict.confidence,
      grade: verdict.grade,
      page_class: verdict.page_class,
      reason_codes: verdict.reason_codes || [],
      block_reason: verdict.block_reason || "",
      trust_score: verdict.trust_score || 0,
      trust_contributors: verdict.trust_contributors || [],
      clearance_checks: verdict.clearance_checks || {},
      decision_trace: verdict.decision_trace || [],
      // v0.3.5 — email-gateway wrapper hops (SafeLinks/Proofpoint/...).
      // Surfaced to the warn/block page so the user sees "this came in
      // through a SafeLinks wrapper that pointed at <target>" instead
      // of an opaque verdict on a host they don't recognise.
      wrapper_chain: verdict.wrapper_chain || [],
      evidence_id: verdict.evidence_id || "",
      scanned_at: verdict.scanned_at || new Date().toISOString(),
    };
    const cur = (await chrome.storage.session.get({ [VERDICT_STASH_KEY]: {} }))[VERDICT_STASH_KEY] || {};
    cur[url] = slim;
    // FIFO trim — drop oldest by scanned_at when over the cap.
    const keys = Object.keys(cur);
    if (keys.length > VERDICT_STASH_LIMIT) {
      keys.sort((a, b) => (cur[a].scanned_at || "").localeCompare(cur[b].scanned_at || ""));
      for (let i = 0; i < keys.length - VERDICT_STASH_LIMIT; i++) delete cur[keys[i]];
    }
    await chrome.storage.session.set({ [VERDICT_STASH_KEY]: cur });
  } catch (e) {
    // session storage is best-effort — fail silent so a stash failure
    // never breaks the user-visible navigation flow.
  }
}

// ---------- v0.3.3: telemetry overrides → /v1/telemetry/override ----------

// Posts to /v1/telemetry/override. Fire-and-forget; the server returns
// 204 either way (opt-in is enforced server-side). We never block the
// user-visible action on the network call — telemetry is best-effort.
async function postTelemetryOverride(action, payload) {
  try {
    const cfg = await settings();
    if (cfg.telemetry === false) return;        // user opted out
    const apiBase = validateAPIBase(cfg.apiBase);
    if (!apiBase) return;
    const body = {
      url: typeof payload.url === "string" ? payload.url : "",
      verdict: typeof payload.verdict === "string" ? payload.verdict : "",
      reason_codes: Array.isArray(payload.reason_codes) ? payload.reason_codes : [],
      action,
      source: "extension",
      client_id: cfg.clientId || "",
    };
    if (typeof payload.note === "string" && payload.note) body.note = payload.note;
    await fetch(`${apiBase}/v1/telemetry/override`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      // keepalive lets the POST survive even when the page is unloading
      // (override_warn click → location.href = target → page tears down).
      keepalive: true,
    });
  } catch {
    // network failures are fine — server has nothing to act on.
  }
}

// ---------- top-level navigation hook ----------

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (shouldSkipURL(details.url)) return;

  const cfg = await settings();
  if (!cfg.enabled) return;

  const url = details.url;

  // "Just verified" one-shot — consume the token and let this exact
  // navigation through. Applies to ALL URLs (sensitive included) because
  // the token was minted by applyVerdict immediately before tabs.update.
  // Without this, sensitive URLs reload-loop because they skip the
  // long-lived verdict cache.
  if (await consumeJustVerified(url)) return;

  // Ultra-mode user override: when the user clicked "Allow for 24h" on
  // the isolation page, every URL on that host bypasses verdict for the
  // window. Honored in all modes (not just Ultra) since the user is
  // explicit about it.
  if (await isAllowTemp(url)) return;

  // Permanent user allowlist (Options page): if the user explicitly trusts
  // this host/IP, bypass scanning entirely. Highest-priority short-circuit
  // (alongside the 24h temp allow). This is what the user uses to permanently
  // whitelist their own self-hosted infrastructure (e.g. 135.181.79.27) or
  // dev tools (e.g. opencode.ai) that the verdict-api would otherwise WARN
  // on due to credential-sink / hidden-link heuristics tuned for the wider
  // public web.
  if (await isUserAllowlisted(url)) return;

  const sensitive = isSensitive(url);
  const key = "v:" + (await sha256(url));

  // Fast path: cached ALLOW on a NON-sensitive URL → let it pass.
  if (!sensitive) {
    const cached = await getCached(key);
    if (cached && cached.verdict === "ALLOW") return;
    if (cached && cached.verdict === "BLOCK") {
      await chrome.tabs.update(details.tabId, {
        url: interstitialURL("blocked.html", url, cached, null),
      });
      return;
    }
  }

  // Everything else: swap to holding interstitial so user never sees the
  // raw page mid-decision. holding.html will poll and call back.
  //
  // Guarded: when the source frame is already chrome-error:// (e.g. user's
  // upstream DNS blocked the host before Chrome could resolve it), the
  // cross-origin redirect to chrome-extension:// is forbidden by Chrome.
  // In that case let Chrome's native error page stand rather than
  // surfacing an ambiguous extension-error to the user.
  //
  // v0.3.5 — retry guard: bail out if this URL has been intercepted
  // more than RETRY_INTERCEPT_LIMIT times in the rolling window.
  if (await shouldThrottleIntercept(url)) {
    return;
  }
  try {
    await chrome.tabs.update(details.tabId, {
      url: holdingURL(url, null, null),
    });
  } catch (e) {
    console.warn("[xgg] holding redirect rejected (likely network-level block on", url, "):", e?.message || e);
  }
});

// ---------- navigation failures (DNS / connection refused) ----------
//
// When the user's local DNS can't resolve a domain or the host actively
// refuses the connection, Chrome navigates to chrome-error://chromewebdata/
// and shows its native error page. WITHOUT this listener, the user would
// keep retrying and the extension would keep intercepting/holding/allowing
// in a loop because verdict-api thinks the domain is fine (different DNS
// vantage point) and we never know the navigation failed.
//
// Fix: when the navigation we just verdict'd FAILED with a DNS / connection
// error, swap the tab to a friendly "domain doesn't exist or has DNS issues"
// page that explains:
//   - the URL the user tried
//   - the specific error code (ERR_NAME_NOT_RESOLVED, etc.)
//   - that the failure is on THEIR side (the URL itself isn't malicious)
//
// The dnsfail.html page is web-accessible and shows the URL + error in
// a non-alarming way. User can hit "Try again" (which re-attempts directly
// without the extension intercepting) or "Go back".
const DNS_FAIL_ERRORS = new Set([
  "net::ERR_NAME_NOT_RESOLVED",
  "net::ERR_NAME_RESOLUTION_FAILED",
  "net::ERR_DNS_TIMED_OUT",
  "net::ERR_DNS_MALFORMED_RESPONSE",
  "net::ERR_DNS_SERVER_REQUIRES_TCP",
  "net::ERR_DNS_SERVER_FAILED",
  "net::ERR_DNS_SORT_ERROR",
]);
const CONN_FAIL_ERRORS = new Set([
  "net::ERR_CONNECTION_REFUSED",
  "net::ERR_CONNECTION_RESET",
  "net::ERR_CONNECTION_CLOSED",
  "net::ERR_CONNECTION_TIMED_OUT",
  "net::ERR_ADDRESS_UNREACHABLE",
  "net::ERR_NETWORK_CHANGED",
]);
// v0.3.4 — Chrome emits these when an upstream policy refuses the
// connection: enterprise rule, Cloudflare Family / NextDNS / ISP filter,
// browser-extension blocker, or response-body block. None of them are DNS
// or transport failures. Before v0.3.4 these codes weren't in any set,
// so `onErrorOccurred` returned silently, the holding-page → /v1/check →
// ALLOW path retried, the upstream blocked again, and the tab flipped
// 15–20 times before something broke the cycle. Treating them like a
// conn-fail (route to dnsfail.html with kind=policy) terminates the loop
// and gives the user a clear "blocked by network policy" message.
const POLICY_FAIL_ERRORS = new Set([
  "net::ERR_NETWORK_ACCESS_DENIED",
  "net::ERR_BLOCKED_BY_CLIENT",
  "net::ERR_BLOCKED_BY_RESPONSE",
  "net::ERR_BLOCKED_BY_ORB",
  "net::ERR_BLOCKED_BY_ADMINISTRATOR",
  "net::ERR_BLOCKED_BY_XSS_AUDITOR",
]);

chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const err = details.error || "";
  if (!DNS_FAIL_ERRORS.has(err) && !CONN_FAIL_ERRORS.has(err) && !POLICY_FAIL_ERRORS.has(err)) return;
  if (shouldSkipURL(details.url)) return;
  // Skip when the FAILED URL is our own interstitial (avoid recursion).
  if (details.url.startsWith(chrome.runtime.getURL(""))) return;
  // Drop any session-cache entry for this URL — it was wrong (we told
  // the user ALLOW but the page can't actually load). Critical for
  // policy failures: without this, the cached ALLOW would replay on
  // the next holding-page intercept and we'd loop again.
  try {
    const key = "v:" + (await sha256(normalizeForToken(details.url)));
    await chrome.storage.session.remove(key);
  } catch {}
  // Show the friendly explainer.
  const p = new URLSearchParams();
  p.set("u", details.url);
  p.set("e", err);
  const kind = DNS_FAIL_ERRORS.has(err) ? "dns"
             : CONN_FAIL_ERRORS.has(err) ? "conn"
             : "policy";
  p.set("k", kind);
  try {
    await chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL("src/dnsfail.html") + "?" + p.toString(),
    });
  } catch (e) {
    // If we can't redirect (tab closed, etc.), drop quietly.
  }
});

// ---------- popup / new-tab hook (the §3 differentiator) ----------

chrome.webNavigation.onCreatedNavigationTarget.addListener(async (details) => {
  // Fires for window.open, target=_blank links, middle-click new tabs.
  const target = details.url;
  if (shouldSkipURL(target)) return;

  const cfg = await settings();
  if (!cfg.enabled) return;

  // Resolve opener tab → URL → cached verdict.
  let opener = null;
  let openerVerdict = "UNKNOWN";
  try {
    const t = await chrome.tabs.get(details.sourceTabId);
    if (t?.url && /^https?:/.test(t.url)) {
      opener = t.url;
      const ok = "v:" + (await sha256(t.url));
      const ov = await getCached(ok);
      if (ov?.verdict) openerVerdict = ov.verdict;
    }
  } catch { /* opener tab may have been closed */ }

  // Decision matrix §3.1, short-circuit case: opener already BLOCKED.
  // We don't even scan the target — block on lineage alone.
  if (openerVerdict === "BLOCK") {
    try {
      await chrome.tabs.update(details.tabId, {
        url: interstitialURL("blocked.html", target, {
          block_reason: "Opened by a page that XGenGuardian had already blocked.",
          reason_codes: ["BLOCKED_OPENER_LINEAGE"],
        }, opener),
      });
    } catch (e) {
      console.warn("[xgg] blocked redirect rejected:", e?.message || e);
    }
    return;
  }

  // Every other case (suspicious opener + unknown target, clean opener + unknown
  // target, etc.) routes through holding.html which gets the full verdict with
  // opener context attached so verdict-api can apply UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER.
  try {
    await chrome.tabs.update(details.tabId, {
      url: holdingURL(target, opener, openerVerdict),
    });
  } catch (e) {
    console.warn("[xgg] popup-target redirect rejected:", e?.message || e);
  }
});

// ---------- messages from holding.html ----------

// isHttpURL — extension-side gate for URLs we hand to tabs.update etc.
// Used to reject attacker-supplied msg.target values pointing at
// javascript:/file:/chrome:/data: schemes (audit FINDING #1 — CRITICAL).
function isHttpURL(s) {
  if (typeof s !== "string") return false;
  return /^https?:\/\/[^\s]+$/i.test(s);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // SENDER VALIDATION (audit FINDING #2 — CRITICAL).
  // Without this, any other extension installed in the browser can send
  // { kind: "apply", tabId: victim, target: "file:///etc/passwd", ... }
  // and we would dutifully redirect the victim's tab. Restricting to our
  // own runtime id closes the cross-extension impersonation path.
  //
  // Content scripts have sender.id === chrome.runtime.id too (extension
  // scripts share the runtime id), so copy-guard.js continues to work.
  if (sender?.id && sender.id !== chrome.runtime.id) {
    return;
  }
  // Ultra mode: user clicked "Allow for 24h" on the isolation page.
  // Persist the host-level override and ack so the page can navigate.
  if (msg?.kind === "allow_temp") {
    if (!isHttpURL(msg.target)) {
      sendResponse({ ok: false, error: "invalid target scheme" });
      return false;
    }
    (async () => {
      await setAllowTemp(msg.target);
      sendResponse({ ok: true });
    })();
    return true;
  }
  if (msg?.kind === "resolve") {
    // Reject non-http(s) targets — fetchVerdict POSTs the URL as-is to
    // verdict-api; a chrome:// or file:// URL would be nonsense.
    if (!isHttpURL(msg.target)) {
      sendResponse({ verdict: { verdict: "ALLOW", reason: "non-http URL bypassed" } });
      return false;
    }
    // ALWAYS-RESPOND CONTRACT: every code path inside this IIFE MUST end
    // with a sendResponse call. Without this, an unhandled error (e.g.
    // chrome.storage throws on quota, sha256 errors on a weird URL,
    // fetchVerdict somehow rejects despite its try/catch) leaves the
    // holding page hanging until its hard deadline fires. The outer
    // try/catch is the safety net.
    (async () => {
      try {
        const verdict = await fetchVerdict(msg.target, msg.opener);
        try {
          const key = "v:" + (await sha256(normalizeForToken(msg.target)));
          if (verdict.verdict && verdict.verdict !== "ANALYZING" && !isSensitive(msg.target)) {
            await setCached(key, verdict);
          }
        } catch (e) {
          // Cache write failure is non-fatal — we still have a verdict.
          console.warn("[xgg] resolve: cache write failed:", e?.message || e);
        }
        sendResponse({ verdict });
      } catch (e) {
        console.warn("[xgg] resolve: handler crashed:", e?.message || e);
        // Fail-open with a clearly-labelled verdict so the holding page
        // routes the user somewhere instead of hanging.
        sendResponse({
          verdict: {
            verdict: "ALLOW",
            reason: "verification_error",
            error: String(e?.message || e).slice(0, 200),
          },
        });
      }
    })();
    return true; // async response
  }
  if (msg?.kind === "apply") {
    // Strict URL gate (audit FINDING #1). The apply path eventually calls
    // chrome.tabs.update(tabId, { url: msg.target }) — without this guard
    // a malicious caller could redirect the victim tab to chrome://,
    // file:// or data: URIs that Chrome will obediently navigate to.
    if (!isHttpURL(msg.target)) {
      sendResponse({ ok: false, error: "invalid target scheme" });
      return false;
    }
    // Verify the tab the caller wants to apply to is hosting one of OUR
    // interstitial pages — without this, a malicious caller could specify
    // any tab id in the browser and we'd redirect it.
    (async () => {
      try {
        const tab = await chrome.tabs.get(msg.tabId);
        const ourPrefix = chrome.runtime.getURL("");
        if (!tab?.url || !tab.url.startsWith(ourPrefix)) {
          sendResponse({ ok: false, error: "target tab is not an interstitial" });
          return;
        }
        await applyVerdict(msg.tabId, msg.target, msg.verdict, msg.opener);
        sendResponse({ ok: true });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();
    return true;
  }
  // copy-guard.js content script asking for a verdict on a copy event.
  if (msg?.type === "command-check") {
    (async () => {
      const verdict = await fetchCommandVerdict(msg.page_url, msg.command, msg.page_title);
      sendResponse(verdict);
    })();
    return true; // async response
  }
  // copy-guard.js telemetry — fire-and-forget aggregate.
  if (msg?.type === "copy-telemetry") {
    try { incrementCopyCounter(msg); } catch (_) { /* ignore */ }
    sendResponse({ ok: true });
    return false;
  }
  // v0.3.6 — Surface Shield. Content script on a trusted-surface host
  // (chat.openai.com, claude.ai, gmail.com, slack.com, etc.) found a
  // rendered link/image/iframe pointing at a third-party URL and is
  // asking us to vet it BEFORE the user clicks. Same endpoint, same
  // verdict shape — the engine doesn't know this is a different
  // sensor. Async response.
  if (msg?.kind === "surface_vet") {
    if (!isHttpURL(msg.url)) {
      sendResponse({ verdict: null });
      return false;
    }
    (async () => {
      try {
        const verdict = await fetchVerdictForSurfaceShield(msg.url, sender?.tab?.url || "");
        sendResponse({ verdict });
      } catch {
        sendResponse({ verdict: null });
      }
    })();
    return true; // async response
  }
  // v0.3.3 Phase G — user clicked "Proceed anyway" on the WARN page.
  if (msg?.kind === "warn_overridden") {
    if (isHttpURL(msg.url)) {
      postTelemetryOverride("override_warn", {
        url: msg.url,
        verdict: "WARN",
        reason_codes: Array.isArray(msg.codes) ? msg.codes : [],
      });
    }
    sendResponse({ ok: true });
    return false;
  }
  // v0.3.3 Phase G — user clicked "Proceed anyway" on the BLOCK page.
  if (msg?.kind === "block_overridden") {
    if (isHttpURL(msg.url)) {
      postTelemetryOverride("override_block", {
        url: msg.url,
        verdict: "BLOCK",
        reason_codes: Array.isArray(msg.codes) ? msg.codes : [],
      });
    }
    sendResponse({ ok: true });
    return false;
  }
  // v0.3.3 Phase G — user flagged a verdict as wrong from any interstitial.
  if (msg?.kind === "report_fp") {
    if (isHttpURL(msg.url)) {
      postTelemetryOverride("report_fp", {
        url: msg.url,
        verdict: msg.verdict || "",
        reason_codes: Array.isArray(msg.codes) ? msg.codes : [],
        note: msg.note || "",
      });
    }
    sendResponse({ ok: true });
    return false;
  }
});

// fetchCommandVerdict — async call to /v1/command-check on copy events.
// Budget: <100ms total round-trip. Fails OPEN (returns ALLOW) on any
// network error so a downed verdict-api never blocks user copies.
async function fetchCommandVerdict(pageURL, command, pageTitle) {
  const cfg = await settings();
  const apiBase = validateAPIBase(cfg.apiBase);
  if (!apiBase) {
    return { verdict: "ALLOW", reason_codes: [], explanation: "" };
  }
  warnIfInsecure(apiBase);
  const ctrl = new AbortController();
  // Tight timeout — copy-button mediation can't wait. The endpoint
  // measures <1ms server-side; 500ms covers network round-trip even on
  // a degraded connection.
  const timer = setTimeout(() => ctrl.abort(), 500);
  try {
    const r = await fetch(`${apiBase}/v1/command-check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        page_url: pageURL,
        command,
        page_title: pageTitle || "",
      }),
      signal: ctrl.signal,
    });
    if (!r.ok) return { verdict: "ALLOW", reason_codes: [], explanation: "" };
    return await r.json();
  } catch (_) {
    return { verdict: "ALLOW", reason_codes: [], explanation: "" };
  } finally {
    clearTimeout(timer);
  }
}

// Tiny aggregate counter — surfaced in the popup UI as "N shell-install
// commands copied today (X flagged)". Stored in chrome.storage.local
// (no PII; just URL host + verdict + timestamp).
async function incrementCopyCounter(msg) {
  const key = "copy-telemetry";
  const today = new Date().toISOString().slice(0, 10);
  const data = (await chrome.storage.local.get(key))[key] || {};
  if (!data[today]) data[today] = { total: 0, flagged: 0 };
  data[today].total += 1;
  // Prune to last 30 days.
  const cutoff = new Date(Date.now() - 30 * 86400e3).toISOString().slice(0, 10);
  for (const d of Object.keys(data)) if (d < cutoff) delete data[d];
  await chrome.storage.local.set({ [key]: data });
}

// ---------- tabnabbing re-check (§16.5) ----------
//
// Tabnabbing: an opener page silently rewrites window.opener.location while
// the user is on the popup. When the user returns focus to the original tab,
// the URL has changed but we never re-verdicted. Hook onActivated; if the
// active tab's URL differs from what we last cached, re-verdict.
//
// Persistence (FINDING #9): the MV3 service worker is unloaded after ~30 s
// of inactivity, losing any in-memory Map. We persist the last-seen URL per
// tab to chrome.storage.session (cleared on browser restart, survives SW
// restarts) so tabnabbing detection continues across idle cycles.

async function getLastSeen(tabId) {
  const got = await chrome.storage.session.get("lst:" + tabId);
  return got["lst:" + tabId] || null;
}

async function setLastSeen(tabId, url) {
  await chrome.storage.session.set({ ["lst:" + tabId]: url });
}

async function removeLastSeen(tabId) {
  await chrome.storage.session.remove("lst:" + tabId);
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab?.url || !/^https?:/.test(tab.url)) return;
    if (tab.url.startsWith(chrome.runtime.getURL(""))) return;
    // Read once at handler entry; subsequent logic uses the in-memory value
    // so we don't make redundant storage round-trips within this handler.
    const prev = await getLastSeen(tabId);
    if (prev && prev !== tab.url) {
      // URL changed since last activation → could be tabnabbing.
      const cfg = await settings();
      if (!cfg.enabled) {
        await setLastSeen(tabId, tab.url);
        return;
      }
      const key = "v:" + (await sha256(tab.url));
      const cached = await getCached(key);
      if (cached && cached.verdict === "BLOCK") {
        await chrome.tabs.update(tabId, {
          url: interstitialURL("blocked.html", tab.url, cached, prev),
        });
        return;
      }
      // Hand off to holding so the standard pipeline runs (it adds
      // UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER when prev was risky).
      await chrome.tabs.update(tabId, {
        url: holdingURL(tab.url, prev, "UNKNOWN"),
      });
    }
    await setLastSeen(tabId, tab.url);
  } catch { /* tab may have been closed */ }
});

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  // Persist the URL on every completed load so the last-seen entry stays
  // current across SW restarts — the badge handler already fires here, but
  // that path skips interstitial tabs and doesn't update lastSeen.
  if (info.status !== "complete" || !tab.url || !/^https?:/.test(tab.url)) return;
  if (tab.url.startsWith(chrome.runtime.getURL(""))) return;
  await setLastSeen(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await removeLastSeen(tabId);
});

// ---------- iframe verdict gating (§16.2) ----------
//
// Top-level third-party iframes on suspicious pages can pivot to malicious
// content (malvertising). We hook onCommitted at frameId !== 0 (sub-frame),
// and when the parent tab's cached verdict is WARN/ISOLATE, surface the
// iframe URL as its own check so the backend can decide.
//
// We do NOT replace the iframe (MV3 can't), but we send a check request
// so analytics + popup_edges record the parent→iframe lineage. Phase 2.5
// will surface a per-iframe block UX.

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId === 0) return; // top-level handled elsewhere
  if (shouldSkipURL(details.url)) return;
  try {
    const parent = await chrome.tabs.get(details.tabId);
    if (!parent?.url || !/^https?:/.test(parent.url)) return;
    const parentKey = "v:" + (await sha256(parent.url));
    const parentVerdict = await getCached(parentKey);
    if (!parentVerdict) return;
    if (parentVerdict.verdict === "WARN" || parentVerdict.verdict === "ISOLATE" || parentVerdict.verdict === "BLOCK") {
      // Fire-and-forget verdict request — server can attach popup_edges row.
      fetchVerdict(details.url, parent.url).catch(() => {});
    }
  } catch { /* parent tab may be gone */ }
});

// ---------- toolbar badge ----------

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== "complete" || !tab.url || !/^https?:/.test(tab.url)) return;
  if (tab.url.startsWith(chrome.runtime.getURL(""))) return; // on our interstitial
  const key = "v:" + (await sha256(tab.url));
  const v = await getCached(key);
  if (!v) return;
  const color =
    v.verdict === "BLOCK"   ? "#ff4d4f" :
    v.verdict === "WARN"    ? "#faad14" :
    v.verdict === "ISOLATE" ? "#5e8bff" :
    v.verdict === "ALLOW"   ? "#52c41a" : "#888";
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
  await chrome.action.setBadgeText({
    tabId,
    text: v.verdict === "ALLOW" ? "" : (v.verdict[0] || ""),
  });
});

// Policy refresh placeholder.
chrome.alarms.create("policy-refresh", { periodInMinutes: 360 });
chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name !== "policy-refresh") return;
  // Phase 2: pull dynamic declarativeNetRequest rules.
});

// ---------- v0.3.6 — Surface Shield helper ----------

// fetchVerdictForSurfaceShield asks /v1/check about a URL on behalf
// of a content script running on a trusted-surface host. Identical
// shape to the webNavigation hook's call — the engine can't tell
// the requests apart, which is the whole point.
//
// Returns a slim verdict object so content scripts don't need to
// understand the full response shape:
//   { verdict, reason_codes, block_reason }
//
// Returns null on any error. Surface Shield treats null as ALLOW
// (don't badge) — failing closed here would render warning chips on
// every link during a transient API hiccup. Fail open: only known-
// bad URLs get badged.
async function fetchVerdictForSurfaceShield(url, contextURL) {
  const cfg = await settings();
  const apiBase = validateAPIBase(cfg.apiBase);
  if (!apiBase) return null;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const r = await fetch(`${apiBase}/v1/check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      // OpenerURL passes the trusted-surface host so the engine can
      // see "this URL is being rendered INSIDE ChatGPT" as context
      // (today the field is informational; future policy rules may
      // act on it).
      body: JSON.stringify({
        url,
        opener_url: contextURL || "",
        client_id: cfg.clientId || "",
      }),
      signal: ctrl.signal,
      cache: "no-store",
    });
    clearTimeout(t);
    if (!r.ok) return null;
    const j = await r.json();
    return {
      verdict: j.verdict,
      reason_codes: j.reason_codes || [],
      block_reason: j.block_reason || "",
    };
  } catch {
    return null;
  }
}
