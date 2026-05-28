# XGenGuardian Browser Extension (Chrome MV3)

Phase-2 v0. Sends the URL of every top-level navigation to the verdict API, swaps the navigation target with an evidence-rich block page when the verdict is BLOCK (and optionally WARN).

## Files

- `manifest.json` — MV3, minimal permissions (storage, tabs, webNavigation, declarativeNetRequest, alarms).
- `src/background.js` — service worker. Hooks `webNavigation.onBeforeNavigate`, hashes URL, queries verdict-api, caches in `chrome.storage.session`.
- `src/blocked.html` — interstitial. Reads query params (URL, reason, evidence_id, brand, score). Links to the Transparency Portal for full evidence + false-positive report.
- `src/popup.html/.js` — popup showing current-tab verdict + protection toggle.
- `src/options.html/.js` — settings page (API endpoint, enforcement level, telemetry).
- `src/rules/trackers.json` — declarativeNetRequest tracker blocklist (10 starter rules; Phase 2 expands).
- `_locales/en/messages.json` — i18n strings.

## Load locally
```
chrome://extensions → Developer mode → Load unpacked → select apps/extension/
```

## Phase-2 TODO
- Replace tracker blocklist with auto-updated dynamic rules pulled from policy server.
- Add Firefox port (largely compatible; needs the few API shims documented at MDN).
- Add Safari port (App Store WebExtension build).
- Add report-phishing context menu.
- Add per-tab evidence inspector panel.
- Integrate with personal dashboard (`/account/history`).

## Permissions Justification

| Permission | Why |
|---|---|
| `storage` | Cache verdicts (session) + user settings (sync). |
| `tabs` | Redirect a tab to the block interstitial. |
| `webNavigation` | Hook navigation before page load so we can stop bad ones. |
| `declarativeNetRequest` | Block tracker requests at the network layer without seeing user traffic. |
| `alarms` | Periodic policy refresh. |
| `<all_urls>` host permission | Required to check arbitrary user-visited URLs against our verdict API. We do not read page content. |
