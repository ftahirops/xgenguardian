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
const DEFAULT_API   = "http://135.181.79.11:18080";
const ALLOW_TTL_MS  = 5 * 60 * 1000;
const BLOCK_TTL_MS  = 60 * 60 * 1000;
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

async function settings() {
  return chrome.storage.sync.get({
    apiBase:        DEFAULT_API,
    enabled:        true,
    enforceWarn:    false,
    telemetry:      true,
    paranoidMode:   false, // Executive Mode toggle (§4.4)
  });
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

function shouldSkipURL(url) {
  if (!/^https?:/.test(url)) return true;
  if (url.startsWith(chrome.runtime.getURL(""))) return true;
  try {
    const u = new URL(url);
    if (["localhost", "127.0.0.1", "::1"].includes(u.hostname)) return true;
    // Skip private network ranges so internal corp tools don't get held.
    if (/^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\./.test(u.hostname)) return true;
  } catch { return true; }
  return false;
}

async function getCached(key) {
  const got = await chrome.storage.session.get(key);
  const e = got[key];
  if (!e) return null;
  const ttl = e.v?.verdict === "BLOCK" ? BLOCK_TTL_MS : ALLOW_TTL_MS;
  if (Date.now() - e.t > ttl) return null;
  return e.v;
}

async function setCached(key, verdict) {
  await chrome.storage.session.set({ [key]: { v: verdict, t: Date.now() } });
}

async function fetchVerdict(url, opener) {
  const cfg = await settings();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), VERDICT_TIMEOUT_MS);
  try {
    const r = await fetch(`${cfg.apiBase}/v1/check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        url,
        client_id: "extension/0.2.0",
        opener_url: opener || undefined,
        paranoid: cfg.paranoidMode || undefined,
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
  if (verdict.block_reason)      p.set("r", verdict.block_reason);
  if (verdict.evidence_id)       p.set("e", verdict.evidence_id);
  if (verdict.visual_top_brand)  p.set("b", verdict.visual_top_brand);
  if (verdict.visual_top_score)  p.set("s", String(verdict.visual_top_score));
  if (Array.isArray(verdict.reason_codes)) p.set("c", verdict.reason_codes.join(","));
  if (opener)                    p.set("op", opener);
  return chrome.runtime.getURL(`src/${page}`) + "?" + p.toString();
}

function holdingURL(target, opener, openerVerdict) {
  const p = new URLSearchParams();
  p.set("target", target);
  if (opener)        p.set("opener", opener);
  if (openerVerdict) p.set("opener_verdict", openerVerdict);
  return chrome.runtime.getURL("src/holding.html") + "?" + p.toString();
}

// applyVerdict — decides what to do with the tab once we have a verdict.
async function applyVerdict(tabId, target, verdict, opener) {
  const page = pageFor(verdict);
  if (!page) {
    // ALLOW or ANALYZING-with-cached-allow → release to the real URL.
    await chrome.tabs.update(tabId, { url: target });
    return;
  }
  await chrome.tabs.update(tabId, {
    url: interstitialURL(page, target, verdict, opener),
  });
}

// ---------- top-level navigation hook ----------

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (shouldSkipURL(details.url)) return;

  const cfg = await settings();
  if (!cfg.enabled) return;

  const url = details.url;
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
  try {
    await chrome.tabs.update(details.tabId, {
      url: holdingURL(url, null, null),
    });
  } catch (e) {
    console.warn("[xgg] holding redirect rejected (likely network-level block on", url, "):", e?.message || e);
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

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.kind === "resolve") {
    (async () => {
      const verdict = await fetchVerdict(msg.target, msg.opener);
      const key = "v:" + (await sha256(msg.target));
      // Don't cache ANALYZING (transient) or sensitive-class results.
      if (verdict.verdict && verdict.verdict !== "ANALYZING" && !isSensitive(msg.target)) {
        await setCached(key, verdict);
      }
      sendResponse({ verdict });
    })();
    return true; // async response
  }
  if (msg?.kind === "apply") {
    (async () => {
      const sender = await chrome.tabs.get(msg.tabId);
      if (sender) await applyVerdict(msg.tabId, msg.target, msg.verdict, msg.opener);
      sendResponse({ ok: true });
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
});

// fetchCommandVerdict — async call to /v1/command-check on copy events.
// Budget: <100ms total round-trip. Fails OPEN (returns ALLOW) on any
// network error so a downed verdict-api never blocks user copies.
async function fetchCommandVerdict(pageURL, command, pageTitle) {
  const cfg = await settings();
  const ctrl = new AbortController();
  // Tight timeout — copy-button mediation can't wait. The endpoint
  // measures <1ms server-side; 500ms covers network round-trip even on
  // a degraded connection.
  const timer = setTimeout(() => ctrl.abort(), 500);
  try {
    const r = await fetch(`${cfg.apiBase}/v1/command-check`, {
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

const lastSeenByTab = new Map(); // tabId → last URL we verdicted

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab?.url || !/^https?:/.test(tab.url)) return;
    if (tab.url.startsWith(chrome.runtime.getURL(""))) return;
    const prev = lastSeenByTab.get(tabId);
    if (prev && prev !== tab.url) {
      // URL changed since last activation → could be tabnabbing.
      const cfg = await settings();
      if (!cfg.enabled) return;
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
    lastSeenByTab.set(tabId, tab.url);
  } catch { /* tab may have been closed */ }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  lastSeenByTab.delete(tabId);
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
