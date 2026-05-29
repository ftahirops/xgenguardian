// dnsfail.js — runs inside src/dnsfail.html.
//
// Reads ?u=<url>&e=<error>&k=<dns|conn> from the URL and renders an
// honest explainer. Uses textContent only — never innerHTML — because
// the URL and error params come from chrome.webNavigation but could in
// principle be crafted by an attacker hitting the web-accessible page
// directly.

function isHttpURL(s) {
  if (typeof s !== "string") return false;
  return /^https?:\/\/[^\s]+$/i.test(s);
}

const p = new URLSearchParams(location.search);
const rawU = p.get("u") || "";
const url  = isHttpURL(rawU) ? rawU : "";
const err  = (p.get("e") || "").slice(0, 200);
const kind = p.get("k") === "conn" ? "conn" : "dns";

document.getElementById("url").textContent = url || "(unknown)";
document.getElementById("err").textContent = err || "(unknown)";

if (kind === "conn") {
  document.getElementById("pill").textContent = "Connection failure";
  document.getElementById("title").textContent = "This site refused the connection.";
  document.getElementById("summary").textContent =
    "The browser found the domain but couldn't establish a connection to the server.";
  document.getElementById("whyDNS").hidden = true;
  document.getElementById("whyConn").hidden = false;
}

document.getElementById("retryBtn").addEventListener("click", () => {
  if (!isHttpURL(url)) {
    history.back();
    return;
  }
  // Direct navigation back to the URL. The extension will intercept
  // again, but if DNS is now working the user gets through. If DNS still
  // fails, the cycle ends right back here — which is the correct,
  // bounded behavior.
  location.href = url;
});

document.getElementById("backBtn").addEventListener("click", () => {
  history.back();
});
