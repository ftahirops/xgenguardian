// isolate.js — runs inside src/isolate.html. Renders the URL in a sandboxed
// iframe that points at the remote-isolation gateway (UNIFIED-PLAN.md §8).
// In Phase 1 the gateway isn't built yet, so we render a placeholder and
// surface the proceed-without-isolation fallback. The gateway endpoint
// becomes /isolate/session in Phase 2.

const p = new URLSearchParams(location.search);
const url   = p.get("u") || "";
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
  const cfg = await chrome.storage.sync.get({
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
    frame.src = j.stream_url;
    placeholder.hidden = true;
    status.textContent = "connected";
  } catch (e) {
    status.textContent = "unavailable (" + String(e).slice(0, 80) + ")";
    frame.hidden = true;
  }
}

tryConnectGateway();

document.getElementById("proceed").addEventListener("click", () => {
  if (!confirm("Open this URL directly without isolation?\n\n" + url)) return;
  try {
    chrome.runtime.sendMessage({ kind: "isolation_bypassed", url, codes });
  } catch {}
  location.href = url;
});
