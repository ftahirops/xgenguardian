// holding.js — runs inside src/holding.html.
// Reads ?target= and ?opener=&opener_verdict=, asks background for a verdict,
// and asks background to route the tab when one arrives. Hard 2s ceiling
// before showing the "open in isolation" fallback (UNIFIED-PLAN.md §3.3).

const params = new URLSearchParams(location.search);
const target          = params.get("target") || "";
const opener          = params.get("opener") || "";
const openerVerdict   = params.get("opener_verdict") || "";

document.getElementById("target").textContent = target || "(unknown URL)";
if (opener) {
  const el = document.getElementById("opener");
  el.hidden = false;
  el.textContent = "Opened from: " + opener;
}

const POLL_DEADLINE_MS = 2000;
const start = performance.now();
let resolved = false;

function elapsed() {
  return ((performance.now() - start) / 1000).toFixed(1) + "s";
}

async function resolveAndRoute() {
  // Single round-trip to the service worker which talks to verdict-api.
  const resp = await chrome.runtime.sendMessage({
    kind: "resolve",
    target,
    opener,
  });
  if (resolved) return;
  const verdict = resp?.verdict;
  if (!verdict || verdict.verdict === "ANALYZING") {
    // Stay on holding; we'll show the timeout fallback below.
    return;
  }
  resolved = true;
  const tab = await chrome.tabs.getCurrent();
  await chrome.runtime.sendMessage({
    kind: "apply",
    tabId: tab.id,
    target,
    verdict,
    opener,
  });
}

// Kick off immediately.
resolveAndRoute().catch(() => {});

// Deadline UI fallback. If no verdict by 2s, surface the manual choices.
setTimeout(async () => {
  if (resolved) return;
  document.getElementById("elapsed").textContent = elapsed();
  document.getElementById("timeout").style.display = "block";
}, POLL_DEADLINE_MS);

// Manual escape hatches.
document.getElementById("isolateBtn").addEventListener("click", async () => {
  resolved = true;
  const tab = await chrome.tabs.getCurrent();
  await chrome.runtime.sendMessage({
    kind: "apply",
    tabId: tab.id,
    target,
    verdict: {
      verdict: "ISOLATE",
      block_reason: "Verdict timed out — opening in isolation as a precaution.",
      reason_codes: ["UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER"],
    },
    opener,
  });
});

document.getElementById("backBtn").addEventListener("click", () => {
  history.back();
});
