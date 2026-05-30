// surface-shield.js — Trusted-Surface Content Vetting (v0.3.6).
//
// What this is: a host-agnostic content script that pre-vets every
// link, image, and iframe rendered into a "trusted surface" — UI
// containers where third-party content gets surfaced as first-class
// clickable elements inside the host's own chrome. Examples: ChatGPT
// answers, Claude responses, Gmail rendered email bodies, Slack
// message text, Discord message content, Notion page content,
// GitHub Markdown blocks.
//
// Why a host-agnostic script: ChatGPhish (2026), Permiso XPIA on
// Copilot (2024), Discord link-unfurl phishing (2018+), HTML email
// remote images (1990s+) are all the SAME class of attack —
// "trusted-surface content injection." A per-product shield is
// point defense; this is category defense.
//
// Architecture invariant: this script is a SENSOR. It does not
// duplicate any engine logic. Every URL it finds goes to the
// existing /v1/check endpoint via the same background.js → fetch
// path the webNavigation hook uses. Zero server changes.
//
// Config-driven: trusted-surfaces.json names the host + the
// CSS selector for the container that holds third-party content.
// Adding a new surface = adding 1 row of JSON. No code change.

(function () {
  "use strict";

  // ----- Bail if this host isn't a configured surface --------------------

  const SURFACES = (typeof XGG_TRUSTED_SURFACES === "object" && XGG_TRUSTED_SURFACES?.surfaces) || [];
  const host = location.hostname.toLowerCase();
  const cfg = SURFACES.find((s) => s.host.toLowerCase() === host);
  if (!cfg) return;

  // ----- Settings cache and pre-vet de-duplication -----------------------

  // Limit concurrent /v1/check calls so a 30-link ChatGPT response
  // doesn't burst-fire 30 requests at the rate-limiter.
  const MAX_CONCURRENT_VETS = 4;
  let inflight = 0;
  const pending = [];

  // URL → result cache. The verdict for a given URL is stable for the
  // life of the page; we never re-check the same URL twice. Backed by
  // a Map (per-content-script-instance) — chrome.storage.session is
  // not available to content scripts in MV3.
  const cache = new Map();
  // Skip set: URLs we've already badged or already navigated through
  // the holding page recently. Same-tab dedup.
  const processed = new WeakSet();

  // Hosts whose own UI links should NEVER be flagged (would break the
  // product). The shield's job is to vet THIRD-PARTY content; in-product
  // navigation isn't third-party.
  const SAME_HOST_ALLOW = new Set([
    location.hostname,
    "www." + location.hostname.replace(/^www\./, ""),
  ]);

  // ----- Wait for the surface container ----------------------------------

  // Container may not exist at document-idle time (SPA chat loads
  // asynchronously). Poll briefly until we find it.
  let surfaceContainer = null;
  let attempts = 0;
  const maxAttempts = 30; // 30 * 500ms = 15s
  const tryAttach = () => {
    attempts++;
    surfaceContainer = document.querySelector(cfg.selector);
    if (surfaceContainer) {
      attach(surfaceContainer);
      return;
    }
    if (attempts < maxAttempts) {
      setTimeout(tryAttach, 500);
    }
    // After 15s without a container, the surface either isn't loaded
    // (user is on a different sub-page) or the selector is stale.
    // Either way: defensive bail-out, no errors.
  };
  tryAttach();

  // Also attach a body-level observer to catch container swaps in
  // SPA navigations.
  const bodyObs = new MutationObserver(() => {
    const c = document.querySelector(cfg.selector);
    if (c && c !== surfaceContainer) {
      surfaceContainer = c;
      attach(c);
    }
  });
  if (document.body) {
    bodyObs.observe(document.body, { childList: true, subtree: true });
  }

  // ----- Attach observer to the surface container ------------------------

  function attach(container) {
    // Scan whatever's already in there.
    scanSubtree(container);

    // Watch for new content (ChatGPT streams answers; Gmail re-renders
    // when opening a thread; Slack adds new messages).
    new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const n of m.addedNodes) {
          if (n.nodeType === Node.ELEMENT_NODE) {
            scanSubtree(n);
          }
        }
      }
    }).observe(container, { childList: true, subtree: true });
  }

  function scanSubtree(root) {
    // Links — the headline vector. ChatGPT-rendered Markdown links
    // become real <a href> elements inside the response container.
    const links = root.querySelectorAll ? root.querySelectorAll("a[href]") : [];
    for (const a of links) {
      if (processed.has(a)) continue;
      processed.add(a);
      preVetLink(a);
    }
    // Images — the auto-fetch / QR-code vector. Image src exfiltrates
    // IP/UA/Referer (ChatGPhish). Image content may BE a QR code that
    // the user is meant to scan with their phone (quishing).
    const imgs = root.querySelectorAll ? root.querySelectorAll("img") : [];
    for (const i of imgs) {
      if (processed.has(i)) continue;
      processed.add(i);
      preVetImage(i);
    }
    // Iframes — Markdown can render <iframe> on some hosts (Notion,
    // GitHub, Confluence). When the iframe src is on a fresh-domain
    // host it's typically a credential-mirror staging surface.
    const frames = root.querySelectorAll ? root.querySelectorAll("iframe[src]") : [];
    for (const f of frames) {
      if (processed.has(f)) continue;
      processed.add(f);
      preVetIframe(f);
    }
  }

  // ----- Per-element pre-vet routines ------------------------------------

  function preVetLink(a) {
    const href = a.getAttribute("href") || "";
    if (!isHTTPUrl(href)) return;
    if (sameHost(href)) return; // in-product nav: skip
    queue(href, (verdict) => {
      if (!verdict) return;
      const v = (verdict.verdict || "").toUpperCase();
      if (v === "ALLOW" || v === "CLEAN") return;
      annotateLink(a, verdict);
    });
  }

  function preVetImage(img) {
    const src = img.getAttribute("src") || img.currentSrc || "";
    if (!isHTTPUrl(src)) return;
    if (sameHost(src)) return;
    // We don't BLOCK image rendering (would break legit content). We
    // submit the image's host for verdict; on non-clean verdict, an
    // overlay warning is drawn on top of the image so the user sees
    // "this image was fetched from a suspicious host" before they
    // trust whatever the image depicts (QR codes especially).
    queue(src, (verdict) => {
      if (!verdict) return;
      const v = (verdict.verdict || "").toUpperCase();
      if (v === "ALLOW" || v === "CLEAN") return;
      annotateImage(img, verdict);
    });
  }

  function preVetIframe(f) {
    const src = f.getAttribute("src") || "";
    if (!isHTTPUrl(src)) return;
    if (sameHost(src)) return;
    queue(src, (verdict) => {
      if (!verdict) return;
      const v = (verdict.verdict || "").toUpperCase();
      if (v === "ALLOW" || v === "CLEAN") return;
      annotateIframe(f, verdict);
    });
  }

  // ----- Queueing + caching ----------------------------------------------

  function queue(url, cb) {
    const key = normaliseURL(url);
    if (cache.has(key)) {
      cb(cache.get(key));
      return;
    }
    const job = { url, cb };
    pending.push(job);
    drain();
  }

  function drain() {
    while (inflight < MAX_CONCURRENT_VETS && pending.length > 0) {
      const job = pending.shift();
      inflight++;
      checkURL(job.url).then((v) => {
        const key = normaliseURL(job.url);
        cache.set(key, v);
        try { job.cb(v); } catch {}
      }).finally(() => {
        inflight--;
        drain();
      });
    }
  }

  function checkURL(url) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ kind: "surface_vet", url }, (resp) => {
          // chrome.runtime.lastError on missing background → silent fail
          if (chrome.runtime.lastError || !resp) {
            resolve(null);
            return;
          }
          resolve(resp.verdict || null);
        });
      } catch {
        resolve(null);
      }
    });
  }

  // ----- Annotation helpers ---------------------------------------------

  function badgeColor(verdict) {
    const v = (verdict.verdict || "").toUpperCase();
    if (v === "BLOCK")   return { bg: "#3a1014", fg: "#ff6b6b", label: "blocked" };
    if (v === "ISOLATE") return { bg: "#241a36", fg: "#c990ff", label: "isolate" };
    return { bg: "#3a2a0c", fg: "#faad14", label: "warn" };
  }

  function tooltipFor(verdict) {
    const codes = Array.isArray(verdict.reason_codes) ? verdict.reason_codes : [];
    const reason = verdict.block_reason || "";
    let tip = "XGenGuardian: " + (verdict.verdict || "?");
    if (codes.length) tip += "\n• " + codes.slice(0, 5).join("\n• ");
    if (reason) tip += "\n\n" + reason;
    tip += "\n\nSurface: " + (cfg.name || cfg.host);
    return tip;
  }

  function annotateLink(a, verdict) {
    const c = badgeColor(verdict);
    const badge = document.createElement("span");
    badge.textContent = " ⚠ " + c.label + " ";
    badge.style.cssText = [
      "display: inline-block",
      "margin: 0 4px",
      "padding: 1px 6px",
      "border-radius: 999px",
      "font-size: 11px",
      "font-weight: 700",
      "font-family: ui-monospace, SFMono-Regular, Menlo, monospace",
      "text-transform: uppercase",
      "letter-spacing: 0.5px",
      "background: " + c.bg,
      "color: " + c.fg,
      "vertical-align: baseline",
    ].join(";");
    badge.title = tooltipFor(verdict);
    badge.setAttribute("data-xgg-surface", cfg.host);
    badge.setAttribute("data-xgg-verdict", verdict.verdict || "");
    // Insert AFTER the link so we don't interfere with link-text styling.
    a.insertAdjacentElement("afterend", badge);
    // Mark the link itself for inspectors.
    a.setAttribute("data-xgg-verdict", verdict.verdict || "");
    a.setAttribute("data-xgg-reason", (verdict.reason_codes || []).join(","));
  }

  function annotateImage(img, verdict) {
    // Wrap the image in a span and overlay a small ⚠ chip in the top-
    // right corner. Image keeps rendering — we don't break the page.
    // The badge tells the user "the host this came from is suspect."
    if (img.parentElement && img.parentElement.getAttribute("data-xgg-wrap") === "1") {
      return; // already wrapped
    }
    const c = badgeColor(verdict);
    const wrap = document.createElement("span");
    wrap.setAttribute("data-xgg-wrap", "1");
    wrap.style.cssText = "position: relative; display: inline-block;";
    img.parentElement?.insertBefore(wrap, img);
    wrap.appendChild(img);
    const chip = document.createElement("span");
    chip.textContent = "⚠ XGG " + c.label;
    chip.style.cssText = [
      "position: absolute",
      "top: 4px",
      "right: 4px",
      "padding: 2px 6px",
      "font: 700 10px ui-monospace, monospace",
      "border-radius: 4px",
      "background: " + c.bg,
      "color: " + c.fg,
      "letter-spacing: 0.5px",
      "z-index: 9999",
      "pointer-events: auto",
    ].join(";");
    chip.title = tooltipFor(verdict) + "\n\n(If this image is a QR code, do NOT scan it with your phone.)";
    wrap.appendChild(chip);
  }

  function annotateIframe(f, verdict) {
    const c = badgeColor(verdict);
    const banner = document.createElement("div");
    banner.textContent = "⚠ XGG " + c.label + " — embedded iframe to " + (new URL(f.src)).hostname + " was flagged. Tooltip for details.";
    banner.style.cssText = [
      "padding: 6px 10px",
      "background: " + c.bg,
      "color: " + c.fg,
      "font: 700 12px ui-monospace, monospace",
      "border-radius: 4px",
      "margin: 6px 0",
    ].join(";");
    banner.title = tooltipFor(verdict);
    f.insertAdjacentElement("beforebegin", banner);
  }

  // ----- Helpers ---------------------------------------------------------

  function isHTTPUrl(s) {
    if (typeof s !== "string") return false;
    return /^https?:\/\/[^\s]+$/i.test(s);
  }

  function sameHost(u) {
    try {
      const h = new URL(u, location.href).hostname.toLowerCase();
      return SAME_HOST_ALLOW.has(h);
    } catch {
      return false;
    }
  }

  function normaliseURL(u) {
    try {
      const x = new URL(u, location.href);
      x.hash = "";
      // Strip tracking-only query params before caching so equivalent
      // links don't double-vet.
      const drop = ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"];
      for (const k of drop) x.searchParams.delete(k);
      return x.toString();
    } catch {
      return u;
    }
  }
})();
