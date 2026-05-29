// isolate.js — runs inside src/isolate.html. Renders the URL in a sandboxed
// iframe that points at the remote-isolation gateway (UNIFIED-PLAN.md §8).
// In Phase 1 the gateway isn't built yet, so we render a placeholder and
// surface the proceed-without-isolation fallback. The gateway endpoint
// becomes /isolate/session in Phase 2.

// isHttpURL — gate location.href / iframe.src from attacker-controlled URL
// params. isolate.html is web-accessible so any page can construct
// chrome-extension://ID/src/isolate.html?u=javascript:... (audit FINDING #5).
function isHttpURL(s) {
  if (typeof s !== "string") return false;
  return /^https?:\/\/[^\s]+$/i.test(s);
}
// isHttpsURL — stricter check for the isolation gateway response, where
// we set an iframe.src. We require TLS because the iframe loads into the
// extension's own origin and any plaintext stream is MITM-able.
function isHttpsURL(s) {
  if (typeof s !== "string") return false;
  return /^https:\/\/[^\s]+$/i.test(s);
}

const p = new URLSearchParams(location.search);
const rawU = p.get("u") || "";
const url = isHttpURL(rawU) ? rawU : "";
const r     = p.get("r") || "";
const codes = (p.get("c") || "").split(",").filter(Boolean);

document.getElementById("url").textContent = url;
if (r) document.getElementById("reason").textContent = r;
if (codes.length) {
  document.getElementById("codesRow").hidden = false;
  const ul = document.getElementById("codes");
  for (const c of codes) {
    const li = document.createElement("li");
    li.textContent = c;
    ul.appendChild(li);
  }
}

async function tryConnectGateway() {
  // storage.local for consistency (audit FINDING #7).
  const cfg = await chrome.storage.local.get({
    isolationGateway: "", // empty until Phase 2 deploys it
  });
  const status = document.getElementById("status");
  const frame  = document.getElementById("frame");
  const placeholder = document.getElementById("placeholder");

  if (!cfg.isolationGateway) {
    status.textContent = "not yet available (Phase 2)";
    frame.hidden = true;
    return;
  }
  try {
    const r = await fetch(`${cfg.isolationGateway}/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!r.ok) throw new Error("gateway " + r.status);
    const j = await r.json();
    if (!j.stream_url) throw new Error("no stream_url in response");
    if (!isHttpsURL(j.stream_url)) {
      throw new Error("stream_url must be https://");
    }
    frame.src = j.stream_url;
    placeholder.hidden = true;
    status.textContent = "connected";
  } catch (e) {
    status.textContent = "unavailable (" + String(e).slice(0, 80) + ")";
    frame.hidden = true;
  }
}

tryConnectGateway();

// goBackBtn — safe navigation back (replaces inline javascript: href).
document.getElementById("goBackBtn")?.addEventListener("click", () => {
  history.back();
});

// allowTempBtn — Ultra-mode 24h per-host allowlist (Phase 5). User
// affirmatively trusts this hostname for the next 24 hours; the
// background script stores it in chrome.storage.local and onBeforeNavigate
// short-circuits the verdict pipeline for every URL on the host until
// the TTL expires.
document.getElementById("allowTempBtn")?.addEventListener("click", async () => {
  if (!isHttpURL(url)) return;
  let host;
  try { host = new URL(url).hostname; } catch { return; }
  if (!confirm(
    "Trust " + host + " for 24 hours?\n\n" +
    "Every page on " + host + " will skip verification until then. " +
    "If this site is compromised, this could let an attacker through."
  )) return;
  try {
    const ack = await chrome.runtime.sendMessage({ kind: "allow_temp", target: url });
    if (!ack?.ok) {
      alert("Could not save the override (" + (ack?.error || "unknown") + ").");
      return;
    }
  } catch (e) {
    alert("Could not save the override (" + String(e) + ").");
    return;
  }
  location.href = url;
});

document.getElementById("proceed").addEventListener("click", () => {
  if (!isHttpURL(url)) return;
  if (!confirm("Open this URL once without isolation? (won't be remembered)\n\n" + url)) return;
  try {
    chrome.runtime.sendMessage({ kind: "isolation_bypassed", url, codes });
  } catch {}
  location.href = url;
});
