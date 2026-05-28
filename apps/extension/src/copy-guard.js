// copy-guard.js — content script for XGenGuardian copy-button mediation.
//
// The Straiker "Fake Claude Code" attack class works because the malicious
// payload is text on a docs page. The user copies it, pastes it into a
// terminal, gets owned. This script intercepts the copy event BEFORE the
// clipboard fills, ships the selected text + page URL to the background
// worker for a verdict, and shows a warning modal on anything non-ALLOW.
//
// Architecture decision from the agreed plan: fast local precheck in JS,
// background worker handles the API call (so the verdict-api call doesn't
// block the copy event handler thread). Decision must surface in <100ms;
// our verdict-api /v1/command-check measures <1ms server-side.

(function () {
  'use strict';

  if (location.protocol === 'chrome-extension:') return;

  const MIN_CMD_LENGTH = 8;

  // Cache recent verdicts so the same command on the same page doesn't
  // re-roundtrip on every accidental copy. 60s TTL.
  const verdictCache = new Map();
  const CACHE_TTL_MS = 60 * 1000;

  function shortHash(s) {
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h * 16777619) >>> 0;
    }
    return h.toString(16);
  }

  function getCachedVerdict(url, cmd) {
    const key = url + '\x00' + shortHash(cmd);
    const hit = verdictCache.get(key);
    if (hit && Date.now() - hit.ts < CACHE_TTL_MS) return hit.verdict;
    return null;
  }

  function setCachedVerdict(url, cmd, verdict) {
    const key = url + '\x00' + shortHash(cmd);
    verdictCache.set(key, { ts: Date.now(), verdict });
    if (verdictCache.size > 100) {
      const first = verdictCache.keys().next().value;
      verdictCache.delete(first);
    }
  }

  function getSelectionText() {
    const sel = window.getSelection();
    return sel ? sel.toString() : '';
  }

  function askVerdict(pageURL, command) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(
          { type: 'command-check', page_url: pageURL, command, page_title: document.title },
          (response) => {
            if (chrome.runtime.lastError || !response) {
              // Fail open on transport errors.
              resolve({ verdict: 'ALLOW', reason_codes: [], explanation: '' });
              return;
            }
            resolve(response);
          }
        );
      } catch (e) {
        resolve({ verdict: 'ALLOW', reason_codes: [], explanation: '' });
      }
    });
  }

  // Build the modal with safe DOM APIs. Every value from the API response
  // (explanation, reason_codes, the command itself) is inserted via
  // textContent so a malicious site can't smuggle HTML into our chrome.
  function buildModal(shadow, verdict, command, response) {
    const color = verdict === 'BLOCK' ? '#d32f2f'
      : verdict === 'REQUIRE_APPROVAL' ? '#f57c00'
      : '#fbc02d';
    const titleText = verdict === 'BLOCK' ? 'Copy blocked — malicious command'
      : verdict === 'REQUIRE_APPROVAL' ? 'Suspicious command — confirm before paste'
      : 'Caution — review before pasting';

    // CSS is a fixed string we control — safe to set as a stylesheet.
    const style = document.createElement('style');
    style.textContent = `
      :host{all:initial;}
      .box{background:#fff;max-width:560px;width:92%;padding:24px 28px;border-radius:8px;box-shadow:0 12px 48px rgba(0,0,0,.3);font-family:system-ui,sans-serif;color:#222;}
      h2{margin:0 0 8px;font-size:18px;color:${color};display:flex;align-items:center;gap:8px;}
      .reason{margin:12px 0;padding:12px;background:#f5f5f5;border-radius:4px;font-size:13px;line-height:1.5;}
      pre{margin:12px 0;padding:12px;background:#1e1e1e;color:#e0e0e0;border-radius:4px;font-size:12px;overflow:auto;max-height:160px;white-space:pre-wrap;word-break:break-all;}
      .codes{font-size:11px;color:#777;margin:8px 0;}
      .codes span{display:inline-block;background:#eee;padding:2px 6px;border-radius:3px;margin:0 4px 4px 0;font-family:monospace;}
      .btns{display:flex;gap:8px;justify-content:flex-end;margin-top:16px;}
      button{font-family:inherit;font-size:14px;padding:8px 16px;border:none;border-radius:4px;cursor:pointer;}
      .primary{background:#1976d2;color:#fff;}
      .danger{background:${color};color:#fff;}
      .secondary{background:#eee;color:#222;}
    `;
    shadow.appendChild(style);

    const box = document.createElement('div');
    box.className = 'box';

    const h2 = document.createElement('h2');
    h2.textContent = '⚠ ' + titleText;
    box.appendChild(h2);

    const reason = document.createElement('div');
    reason.className = 'reason';
    reason.textContent = response.explanation || 'XGenGuardian flagged this command.';
    box.appendChild(reason);

    const pre = document.createElement('pre');
    pre.textContent = command.length > 600 ? command.slice(0, 600) + '\n…' : command;
    box.appendChild(pre);

    const codes = document.createElement('div');
    codes.className = 'codes';
    for (const c of (response.reason_codes || [])) {
      const span = document.createElement('span');
      span.textContent = c;
      codes.appendChild(span);
    }
    box.appendChild(codes);

    const btns = document.createElement('div');
    btns.className = 'btns';
    const cancel = document.createElement('button');
    cancel.className = 'secondary';
    cancel.textContent = 'Cancel copy';
    cancel.dataset.act = 'cancel';
    btns.appendChild(cancel);
    if (verdict !== 'BLOCK') {
      const proceed = document.createElement('button');
      proceed.className = 'danger';
      proceed.textContent = 'I know what I am doing — copy anyway';
      proceed.dataset.act = 'proceed';
      btns.appendChild(proceed);
    }
    box.appendChild(btns);

    shadow.appendChild(box);
    return box;
  }

  function showWarning(verdict, command, response) {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;';
    const shadow = overlay.attachShadow({ mode: 'closed' });
    const box = buildModal(shadow, verdict, command, response);
    document.documentElement.appendChild(overlay);

    return new Promise((resolve) => {
      box.addEventListener('click', (e) => {
        const act = e.target?.dataset?.act;
        if (!act) return;
        overlay.remove();
        resolve(act === 'proceed');
      });
    });
  }

  // Cheap precheck — only call background when the selection looks like
  // a shell command. Avoids round-tripping for every paragraph copy.
  const SHELL_HINT_RE = /\b(curl|wget|irm|iwr|powershell|bash|sh|zsh|mshta|rundll32|npm\s+(install|i)|pip3?\s+install|brew\s+(install|tap)|apt(-get)?\s+install|yum\s+install|dnf\s+install|cargo\s+install|go\s+install|choco\s+install|scoop\s+install|code\s+--install-extension|\|\s*(bash|sh|zsh|iex)|base64\s+-d|-EncodedCommand|FromBase64String)\b/i;

  document.addEventListener('copy', async (e) => {
    const selectionText = getSelectionText();
    if (!selectionText || selectionText.length < MIN_CMD_LENGTH) return;
    if (!SHELL_HINT_RE.test(selectionText)) return;

    const cached = getCachedVerdict(location.href, selectionText);
    let response;
    if (cached) {
      response = cached;
    } else {
      response = await askVerdict(location.href, selectionText);
      setCachedVerdict(location.href, selectionText, response);
    }

    const v = response.verdict;
    if (v === 'ALLOW') return;

    // Non-ALLOW: stop the copy and ask the user.
    e.preventDefault();
    e.stopPropagation();
    const proceed = await showWarning(v, selectionText, response);
    if (proceed) {
      try {
        await navigator.clipboard.writeText(selectionText);
      } catch (_) { /* ignore */ }
    }
  }, { capture: true });

  // Telemetry: report every shell-hint copy to background for aggregation.
  document.addEventListener('copy', () => {
    try {
      const sel = getSelectionText();
      if (sel && sel.length >= MIN_CMD_LENGTH && SHELL_HINT_RE.test(sel)) {
        chrome.runtime.sendMessage({
          type: 'copy-telemetry',
          page_url: location.href,
          page_title: document.title,
          length: sel.length,
        });
      }
    } catch (_) { /* ignore */ }
  });
})();
