// Popup — shows the verdict for the current tab and exposes a quick toggle.

async function sha256(text) {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function badgeClass(v) {
  if (v === "BLOCK") return "block";
  if (v === "WARN")  return "warn";
  if (v === "CLEAN") return "clean";
  return "unk";
}

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;
  document.getElementById("url").textContent = tab.url;

  // Pull cached verdict the background SW set.
  const key = "v:" + (await sha256(tab.url));
  const got = await chrome.storage.session.get(key);
  const v = got[key]?.v;

  if (v) {
    const b = document.getElementById("badge");
    b.textContent = v.verdict.toLowerCase();
    b.className = "pill " + badgeClass(v.verdict);
    document.getElementById("conf").textContent =
      v.confidence ? `confidence ${(v.confidence * 100).toFixed(0)}%` : "";
    if (v.visual_top_brand) {
      document.getElementById("brandRow").hidden = false;
      document.getElementById("brand").textContent = v.visual_top_brand;
      document.getElementById("score").textContent =
        (v.visual_top_score * 100).toFixed(0) + "%";
    }
    document.getElementById("evidence").href = v.evidence_id
      ? `https://report.xgenguardian.com/report/${v.evidence_id}`
      : `https://report.xgenguardian.com/?url=${encodeURIComponent(tab.url)}`;
  } else {
    document.getElementById("evidence").href =
      `https://report.xgenguardian.com/?url=${encodeURIComponent(tab.url)}`;
  }

  // Read/write to storage.local to stay consistent with options.js and
  // background.js — see FINDING #7 / #15 in the audit. Using storage.sync
  // here meant the popup's "enabled" toggle and the Options page's "enabled"
  // toggle lived in different stores and silently disagreed.
  const cfg = await chrome.storage.local.get({ enabled: true });
  const cb = document.getElementById("enabled");
  cb.checked = cfg.enabled;
  cb.addEventListener("change", async () => {
    await chrome.storage.local.set({ enabled: cb.checked });
  });

  document.getElementById("options").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
})();
