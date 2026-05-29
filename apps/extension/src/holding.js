// holding.js — robust verdict resolution with fail-open watchdog.
//
// Design contract: this page MUST NEVER hang. Three independent timeouts
// each guarantee the user gets out within bounded time:
//
//   1. PER_ATTEMPT_MS (8s)  — single verdict-api round-trip budget. If
//      no response in 8s, retry once with the same payload.
//   2. RETRY_AFTER_MS (1s)  — wait before retry so transient slowness
//      doesn't immediately re-fire.
//   3. HARD_DEADLINE_MS (12s) — if STILL no verdict, FAIL OPEN with
//      an explicit "couldn't verify, choose how to proceed" UI. We
//      never silently strand the user on a holding spinner.
//
// Failure modes covered:
//   - Service worker dies mid-request (MV3 idle) → sendMessage rejects → retry
//   - verdict-api unreachable → fetchVerdict returns ANALYZING → retry
//   - background handler errors silently → response never arrives → hard deadline
//   - URL is malformed (bypassed at background) → ALLOW with reason="invalid"
//
// What the user sees while waiting:
//   - 0-2s:  "Checking site safety..."
//   - 2-5s:  "Looking up threat intelligence..."
//   - 5-8s:  "Rendering page in sandbox..."
//   - 8-12s: "Almost done..."
//   - 12s+:  manual choice UI (Allow once / Allow + remember 24h / Block / Go back)

const params = new URLSearchParams(location.search);
const target        = params.get("target") || "";
const opener        = params.get("opener") || "";
const openerVerdict = params.get("opener_verdict") || "";

document.getElementById("target").textContent = target || "(unknown URL)";
if (opener) {
  const el = document.getElementById("opener");
  el.hidden = false;
  el.textContent = "Opened from: " + opener;
}

const PER_ATTEMPT_MS = 8000;
const RETRY_AFTER_MS = 1000;
const HARD_DEADLINE_MS = 12000;
const PROGRESS_TICK_MS = 250;

const start = performance.now();
let resolved = false;
let attemptCount = 0;

const PROGRESS_STAGES = [
  { at:    0, text: "Checking site safety…" },
  { at: 2000, text: "Looking up threat intelligence…" },
  { at: 5000, text: "Rendering page in sandbox…" },
  { at: 8000, text: "Almost done…" },
  { at: 11000, text: "Taking longer than expected…" },
];

function elapsedMs()  { return performance.now() - start; }
function elapsedSec() { return (elapsedMs() / 1000).toFixed(1); }

function setStatus(text) {
  const subtitle = document.getElementById("subtitle");
  if (subtitle) subtitle.textContent = text;
}

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    promise.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });
}

async function sendResolve() {
  // chrome.runtime.sendMessage returns a Promise; we wrap with a manual
  // timeout because the service worker can sometimes accept the message
  // but never reply (e.g. mid-restart, handler error).
  return withTimeout(
    chrome.runtime.sendMessage({ kind: "resolve", target, opener }),
    PER_ATTEMPT_MS,
  );
}

async function attemptResolve() {
  attemptCount += 1;
  try {
    const resp = await sendResolve();
    if (resolved) return null;
    const v = resp?.verdict;
    if (!v) return null;                       // empty response → treat as miss
    if (v.verdict === "ANALYZING") return null; // server still working → miss
    return v;                                   // real verdict
  } catch (e) {
    console.warn("[xgg-holding] attempt", attemptCount, "failed:", e?.message || e);
    return null;
  }
}

async function applyVerdict(verdict) {
  resolved = true;
  let tab;
  try { tab = await chrome.tabs.getCurrent(); } catch { return; }
  try {
    await chrome.runtime.sendMessage({
      kind: "apply",
      tabId: tab.id,
      target,
      verdict,
      opener,
    });
  } catch (e) {
    console.warn("[xgg-holding] apply failed:", e?.message || e);
    // Last resort: nav directly so the user isn't trapped.
    location.href = target;
  }
}

// ---------- main routing ----------

async function resolveAndRoute() {
  // First attempt.
  let v = await attemptResolve();
  if (v) return applyVerdict(v);

  // Retry once after a short backoff.
  setStatus("Retrying…");
  await new Promise((r) => setTimeout(r, RETRY_AFTER_MS));
  if (resolved) return;

  v = await attemptResolve();
  if (v) return applyVerdict(v);

  // Still no verdict — surface the manual choice UI ahead of the hard
  // deadline so the user has time to react.
  showTimeoutUI();
}

resolveAndRoute().catch((e) => {
  console.warn("[xgg-holding] resolveAndRoute crashed:", e?.message || e);
  showTimeoutUI();
});

// ---------- progress UI ----------

const progressEl = document.getElementById("elapsed");
const progressTicker = setInterval(() => {
  if (resolved) {
    clearInterval(progressTicker);
    return;
  }
  if (progressEl) progressEl.textContent = elapsedSec() + "s";
  const e = elapsedMs();
  for (const stage of PROGRESS_STAGES) {
    if (e >= stage.at) {
      setStatus(stage.text);
    } else break;
  }
}, PROGRESS_TICK_MS);

// ---------- hard deadline ----------

const hardDeadlineTimer = setTimeout(() => {
  if (resolved) return;
  showTimeoutUI();
}, HARD_DEADLINE_MS);

function showTimeoutUI() {
  if (resolved) return;
  clearInterval(progressTicker);
  clearTimeout(hardDeadlineTimer);
  if (progressEl) progressEl.textContent = elapsedSec() + "s";
  const node = document.getElementById("timeout");
  if (node) node.style.display = "block";
  setStatus("Couldn't verify in time.");
}

// ---------- manual escape hatches ----------

document.getElementById("isolateBtn")?.addEventListener("click", () => {
  applyVerdict({
    verdict: "ISOLATE",
    block_reason: "Verdict service didn't respond in time — opening in isolation as a precaution.",
    reason_codes: ["VERIFICATION_TIMEOUT"],
  });
});

document.getElementById("backBtn")?.addEventListener("click", () => {
  resolved = true;
  clearInterval(progressTicker);
  clearTimeout(hardDeadlineTimer);
  history.back();
});

// Additional escape buttons (added in holding.html below).
document.getElementById("allowOnceBtn")?.addEventListener("click", () => {
  applyVerdict({
    verdict: "ALLOW",
    reason_codes: ["VERIFICATION_TIMEOUT_USER_BYPASSED"],
  });
});

document.getElementById("allowRememberBtn")?.addEventListener("click", async () => {
  // Stamp the 24h ALLOW_TEMP via background's message handler so it
  // persists like any other isolation-page override.
  try {
    await chrome.runtime.sendMessage({ kind: "allow_temp", target });
  } catch {}
  applyVerdict({
    verdict: "ALLOW",
    reason_codes: ["USER_TRUSTED_24H"],
  });
});
