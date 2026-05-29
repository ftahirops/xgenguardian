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
const kindRaw = p.get("k") || "dns";
const kind = (kindRaw === "conn" || kindRaw === "policy") ? kindRaw : "dns";

document.getElementById("url").textContent = url || "(unknown)";
document.getElementById("err").textContent = err || "(unknown)";

if (kind === "conn") {
  document.getElementById("pill").textContent = "Connection failure";
  document.getElementById("title").textContent = "This site refused the connection.";
  document.getElementById("summary").textContent =
    "The browser found the domain but couldn't establish a connection to the server.";
  document.getElementById("whyDNS").hidden = true;
  document.getElementById("whyConn").hidden = false;
} else if (kind === "policy") {
  // v0.3.4 — upstream policy block (Cloudflare Family / NextDNS / enterprise
  // rule / response filter). Not a DNS failure, not an XGG block. Tell the
  // user honestly that something on their network is refusing it so they
  // don't keep retrying.
  document.getElementById("pill").textContent = "Blocked by network policy";
  document.getElementById("title").textContent = "Your network or browser blocked this site.";
  document.getElementById("summary").textContent =
    "A DNS provider, parental-control filter, browser policy, or content blocker on your network refused the connection. This is not an XGenGuardian block — it happened before our engine saw the page.";
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
