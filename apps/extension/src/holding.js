// holding.js — runs inside src/holding.html.
//
// Reads ?target= and ?opener=&opener_verdict=, asks background for a verdict,
// then asks background to route the tab when one arrives.
//
// Sandbox-rendered URLs (shared hosting, dev-install lures, raw IPs, etc.)
// take 5-20s to verdict because of network + render + visual-match. The
// previous 2s deadline bailed before any of those completed and produced
// false "verdict timed out" prompts on real-world pages. New behavior:
//
//   - Poll budget: 25s total. Verdict arrival is async; once we have a
//     non-ANALYZING verdict we route immediately.
//   - Progress UI: update every 1s with elapsed time + "still analyzing"
//     subtitle so the user sees the wait is intentional, not a hang.
//   - Manual isolate fallback (button) uses VERIFICATION_TIMEOUT, not the
//     misleading UNKNOWN_TARGET_FROM_SUSPICIOUS_OPENER.

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

const POLL_DEADLINE_MS = 25000;  // 25s — covers p99 sandbox render times.
const PROGRESS_TICK_MS = 1000;   // update elapsed-time UI every second.

const start = performance.now();
let resolved = false;

function elapsedSec() {
  return ((performance.now() - start) / 1000).toFixed(1);
}

async function resolveAndRoute() {
  // Single round-trip to the service worker which talks to verdict-api.
  // The Chromium message channel keeps this promise alive until background.js
  // responds — even if background takes 15s, we still get the verdict here.
  const resp = await chrome.runtime.sendMessage({
    kind: "resolve",
    target,
    opener,
  });
  if (resolved) return;
  const verdict = resp?.verdict;
  if (!verdict || verdict.verdict === "ANALYZING") {
    // Stay on holding; the deadline UI will offer manual choices below.
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

// Progress ticker — keeps the UI honest about how long we've been waiting.
const progressEl = document.getElementById("elapsed");
const progressTicker = setInterval(() => {
  if (resolved) {
    clearInterval(progressTicker);
    return;
  }
  if (progressEl) {
    progressEl.textContent = elapsedSec() + "s";
  }
}, PROGRESS_TICK_MS);

// Deadline UI fallback. If no verdict by POLL_DEADLINE_MS, surface manual choices.
setTimeout(async () => {
  if (resolved) return;
  clearInterval(progressTicker);
  if (progressEl) progressEl.textContent = elapsedSec() + "s";
  document.getElementById("timeout").style.display = "block";
}, POLL_DEADLINE_MS);

// Manual escape hatches.
document.getElementById("isolateBtn").addEventListener("click", async () => {
  resolved = true;
  clearInterval(progressTicker);
  const tab = await chrome.tabs.getCurrent();
  await chrome.runtime.sendMessage({
    kind: "apply",
    tabId: tab.id,
    target,
    verdict: {
      verdict: "ISOLATE",
      block_reason: "Verdict service didn't respond in time — opening in isolation as a precaution.",
      reason_codes: ["VERIFICATION_TIMEOUT"],
    },
    opener,
  });
});

document.getElementById("backBtn").addEventListener("click", () => {
  clearInterval(progressTicker);
  history.back();
});
