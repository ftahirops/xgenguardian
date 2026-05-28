// warn.js — runs inside src/warn.html. Renders the warn interstitial and
// gates the "proceed anyway" button behind a 5-second countdown to defeat
// muscle-memory click-through.

const p = new URLSearchParams(location.search);
const url   = p.get("u") || "";
const r     = p.get("r") || "";
const brand = p.get("b") || "";
const score = p.get("s") || "";
const codes = (p.get("c") || "").split(",").filter(Boolean);

document.getElementById("url").textContent = url;
if (r) document.getElementById("reason").textContent = r;
if (brand) {
  document.getElementById("brandRow").hidden = false;
  document.getElementById("brand").textContent = brand;
  document.getElementById("score").textContent = score
    ? Math.round(parseFloat(score) * 100) + "%"
    : "—";
}
if (codes.length) {
  document.getElementById("codesRow").hidden = false;
  const ul = document.getElementById("codes");
  for (const c of codes) {
    const li = document.createElement("li");
    li.textContent = c;
    ul.appendChild(li);
  }
}

// 5-second countdown gate (UNIFIED-PLAN.md §7.1 "requires 2-click").
let remaining = 5;
const btn = document.getElementById("proceed");
const cd  = document.getElementById("cd");
const tick = setInterval(() => {
  remaining -= 1;
  if (remaining <= 0) {
    clearInterval(tick);
    cd.textContent = "";
    btn.disabled = false;
    btn.classList.remove("primary");
    btn.classList.add("danger");
  } else {
    cd.textContent = "(" + remaining + ")";
  }
}, 1000);

btn.addEventListener("click", () => {
  if (btn.disabled) return;
  // Telemetry hook (best-effort).
  try {
    chrome.runtime.sendMessage({ kind: "warn_overridden", url, codes });
  } catch {}
  location.href = url;
});
