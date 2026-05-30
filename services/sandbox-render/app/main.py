"""XGenGuardian — sandbox-render service.

POST /render {url} → renders the URL in a headless Chromium VM and returns
screenshot URL, DOM, favicon URL, and extracted form actions. Phase-1 uses
a single egress; multi-egress + cloaking diff lands in Phase 2 (#18).

Storage backend is S3-compatible (MinIO in dev). Evidence URLs are signed.
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any  # noqa: F401

import boto3
import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, Response as FastAPIResponse
from playwright.async_api import async_playwright, Browser, Playwright
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel, HttpUrl

from .challenge import detect_challenge
from .dom_inventory import (
    _DOM_INVENTORY_JS,
    IFrameFinding,
    LinkFinding,
    HiddenElementFinding,
    SuspiciousJSFinding,
    OverlayFinding,
    parse_inventory,
)
from .downloads import FileFinding, fetch_and_hash, discover_links
from .yara_scan import default_scanner, matches_to_dicts
from .shellcmd import scan_commands as scan_shell_commands

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

render_total = Counter(
    "xgg_render_total",
    "Render outcomes labeled by result.",
    ["result"],
)

render_latency = Histogram(
    "xgg_render_latency_seconds",
    "Render duration from request start to response.",
    buckets=[0.5, 1, 2, 5, 10, 20, 30, 45, 60],
)

render_inflight = Gauge(
    "xgg_render_semaphore_inflight",
    "Number of renders currently in-flight (holding a semaphore slot).",
)

render_yara_matches = Counter(
    "xgg_render_yara_matches_total",
    "YARA rule matches during render, labeled by rule name.",
    ["rule"],
)

# playwright-stealth — drops Playwright's automation tells (navigator.webdriver,
# WebGL fingerprint, plugin list, etc.) so cloaking-aware kits and basic
# Cloudflare bot detection are less likely to serve us a fake clean page.
# UNIFIED-PLAN.md §18.2. Optional import: if the package isn't installed the
# sandbox still works, just without stealth.
try:
    from playwright_stealth import stealth_async   # type: ignore
    _STEALTH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _STEALTH_AVAILABLE = False
    async def stealth_async(_page):  # type: ignore
        return None

# Inter-service shared-secret authentication (Architecture Audit Finding #3).
# Read once at module import; an empty value disables the check (dev mode).
_INTERNAL_TOKEN: str = os.getenv("XGG_INTERNAL_TOKEN", "")
if not _INTERNAL_TOKEN:
    import logging
    logging.getLogger(__name__).warning(
        "XGG_INTERNAL_TOKEN is not set — inter-service auth DISABLED (dev mode)"
    )

S3_ENDPOINT = os.getenv("S3_ENDPOINT", "http://localhost:9000")
S3_BUCKET = os.getenv("S3_BUCKET", "xgg-evidence")
S3_KEY = os.getenv("S3_ACCESS_KEY", "xggadmin")
S3_SECRET = os.getenv("S3_SECRET_KEY", "xggadmin123")
S3_PUBLIC_BASE = os.getenv("S3_PUBLIC_BASE", "http://localhost:9000/xgg-evidence")
RENDER_TIMEOUT_MS = int(os.getenv("RENDER_TIMEOUT_MS", "5000"))

# Global concurrency caps. Chromium is heavy; without these a burst from
# fp-bench or a malicious site forcing many popups can OOM the host (we
# observed 500+ leaked renderers under load before the try/finally fix).
# Two pools so a long crawl/aggressive-scan can't starve user-facing /v1/check
# calls coming through extension or verdict-api.
MAX_CONCURRENT_RENDERS_SYNC  = int(os.getenv("MAX_CONCURRENT_RENDERS_SYNC", "10"))
MAX_CONCURRENT_RENDERS_ASYNC = int(os.getenv("MAX_CONCURRENT_RENDERS_ASYNC", "4"))

# Wave 3 Phase 2 — cap on document.body.innerText captured per render.
# 50 KB is enough for the phrase-scoring use case (support-scam,
# payment-scam, crypto-drainer) without bloating the response or the
# evidence row. Runaway pages get truncated, not failed.
VISIBLE_TEXT_MAX_BYTES = int(os.getenv("VISIBLE_TEXT_MAX_BYTES", "51200"))
RENDER_QUEUE_TIMEOUT_S       = float(os.getenv("RENDER_QUEUE_TIMEOUT_S", "10"))

# Created in lifespan() so they're bound to the loop.
_sync_sem:  asyncio.Semaphore | None = None
_async_sem: asyncio.Semaphore | None = None

_pw: Playwright | None = None
_browser: Browser | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pw, _browser, _sync_sem, _async_sem
    _sync_sem  = asyncio.Semaphore(MAX_CONCURRENT_RENDERS_SYNC)
    _async_sem = asyncio.Semaphore(MAX_CONCURRENT_RENDERS_ASYNC)
    _pw = await async_playwright().start()
    # DNS bypass: force Chromium to resolve via Cloudflare DoH directly,
    # ignoring the host OS resolver. On hosts running NextDNS / Pi-hole /
    # CleanBrowsing the OS resolver returns a "blocked" page for every
    # malicious URL, making sandbox-render see only the block page and
    # never the real malicious content — defeats visual-match + YARA +
    # credential-sink detection. We *need* to see the real page to verdict it.
    args = [
        "--no-sandbox",
        "--enable-features=DnsOverHttps",
        "--dns-over-https-templates=https://cloudflare-dns.com/dns-query",
        "--host-resolver-rules=EXCLUDE localhost,EXCLUDE 127.0.0.1",
    ]
    _browser = await _pw.chromium.launch(headless=True, args=args)
    yield
    if _browser:
        await _browser.close()
    if _pw:
        await _pw.stop()


app = FastAPI(title="xgg-sandbox-render", lifespan=lifespan)


@app.get("/metrics")
async def metrics_endpoint() -> FastAPIResponse:
    """Prometheus metrics scrape endpoint. No authentication required."""
    return FastAPIResponse(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.middleware("http")
async def internal_auth_middleware(request: Request, call_next) -> Response:
    """Validate X-Internal-Token on every request except /healthz.

    When XGG_INTERNAL_TOKEN is unset the check is skipped (dev mode).
    When set, any missing or mismatched token returns 401 Unauthorized.
    Uses secrets.compare_digest to prevent timing-oracle attacks.
    """
    if request.url.path not in ("/healthz", "/metrics") and _INTERNAL_TOKEN:
        import secrets

        provided = request.headers.get("X-Internal-Token", "")
        if not secrets.compare_digest(provided, _INTERNAL_TOKEN):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)


s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_KEY,
    aws_secret_access_key=S3_SECRET,
    region_name="us-east-1",
)


class RenderRequest(BaseModel):
    url: HttpUrl
    viewport: tuple[int, int] = (1440, 900)
    wait_until: str = "networkidle"  # 'load' | 'domcontentloaded' | 'networkidle'
    # Pool selector. "sync" is the default for /v1/check from extension and
    # verdict-api (user-blocking). "async" is for crawl, aggressive-scan,
    # multi-vantage diff — slower work that mustn't starve user requests.
    pool: str = "sync"  # 'sync' | 'async'


class FormAction(BaseModel):
    action: str
    action_origin: str | None = None
    has_password: bool
    has_email: bool
    is_cross_origin: bool


class DownloadFinding(BaseModel):
    url: str
    extension: str | None = None
    content_type: str | None = None
    size_hint: int | None = None
    sha256: str | None = None
    risky: bool = False
    error: str | None = None


class YaraMatchOut(BaseModel):
    rule: str
    namespace: str
    severity: str
    reason_code: str
    description: str
    tags: list[str] = []


class RenderResponse(BaseModel):
    evidence_id: str
    screenshot_url: str
    dom_url: str
    har_url: str | None = None
    favicon_url: str | None
    final_url: str
    title: str
    forms: list[FormAction]
    redirect_chain: list[str]
    downloads: list[DownloadFinding] = []
    render_ms: int
    # Set true when the page we landed on is a bot-protection challenge
    # (Cloudflare Turnstile / "Just a moment", reCAPTCHA wall, Akamai/Imperva
    # / DataDome challenge, etc.). verdict-api treats this as "couldn't scan"
    # and forces ISOLATE for unknown URLs rather than CLEAN. See
    # UNIFIED-PLAN.md §16.1 / §15 server-side-cloaking.
    is_challenge_page: bool = False
    challenge_kind: str | None = None  # "cloudflare" | "recaptcha" | "datadome" | "akamai" | "generic"
    # YARA signature matches against the rendered HTML + inline JS.
    # See services/sandbox-render/rules/ and UNIFIED-PLAN.md §18.2.
    yara_matches: list[YaraMatchOut] = []
    yara_ms: int = 0
    # Behavioral abuse counters captured via page-injected instrumentation.
    # See UNIFIED-PLAN.md §5.2. Verdict-api maps non-zero counts to reason
    # codes (POPUP_STORM_DETECTED, ALERT_LOOP_DETECTED, FULLSCREEN_TRAP_DETECTED,
    # BEFOREUNLOAD_ABUSE, CLIPBOARD_HIJACK_ATTEMPT, AUTO_DOWNLOAD_TRIGGER,
    # FAKE_SUPPORT_SCAREWARE when ≥3 trip simultaneously).
    behavior: dict[str, int] = {}
    # postMessage observation — count of cross-origin postMessage calls
    # initiated by the page during render.
    post_message_count: int = 0
    # Credential-sink runtime data (Package 4 / dev spec §3).
    # Tracks where the page would actually send credential-bearing requests:
    # fetch / XHR / sendBeacon / WebSocket destinations + pre-submit-capture
    # flags + hidden-mirror detection.
    sink: dict[str, Any] = {}
    # Shell-command IOCs found in <pre>/<code> blocks on the rendered page.
    # Catches the Straiker-class attack where the docs page IS the weapon:
    # rundll32 over UNC, mshta + remote HTA, the `&` separator trick, base64
    # piped to zsh, PowerShell IEX cradles. Empty dict on clean pages.
    shellcmd: dict[str, Any] = {}
    # DOM inventory — comprehensive link, iframe, hidden-element, suspicious-JS,
    # and overlay/clickjack findings extracted in a single in-page JS pass after
    # render settles. See UNIFIED-PLAN.md §18.3.
    links: list[LinkFinding] = []
    iframes: list[IFrameFinding] = []
    hidden_elements: list[HiddenElementFinding] = []
    suspicious_js: list[SuspiciousJSFinding] = []
    overlays: list[OverlayFinding] = []
    # Wave 3 Phase 2 — visible page text (document.body.innerText).
    # Capped at VISIBLE_TEXT_MAX_BYTES so a runaway page doesn't bloat
    # the response. Consumed by internal/supportscam and internal/
    # paymentscam (and internal/cryptodrainer when it ships). NOT
    # sanitised — verdict-api treats this as untrusted text and never
    # echoes it back to the user without escaping. Phase 3 will add
    # ocr_text alongside this from screenshot OCR.
    visible_text: str = ""


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/render", response_model=RenderResponse)
async def render(req: RenderRequest) -> RenderResponse:
    if _browser is None:
        raise HTTPException(503, "browser not ready")

    # Concurrency gate. Pool selected via req.pool ("sync" or "async").
    # "sync" pool serves user-blocking traffic (extension + verdict-api).
    # "async" pool serves crawl / multi-vantage / aggressive-scan jobs.
    # Acquire with timeout: returns 429 rather than queueing indefinitely
    # so misbehaving callers get fast backpressure.
    sem = _async_sem if req.pool == "async" else _sync_sem
    if sem is None:
        raise HTTPException(503, "browser not ready")
    try:
        await asyncio.wait_for(sem.acquire(), timeout=RENDER_QUEUE_TIMEOUT_S)
    except asyncio.TimeoutError:
        render_total.labels(result="failure").inc()
        raise HTTPException(
            status_code=429,
            detail=f"render queue full (pool={req.pool})",
            headers={"X-Render-Queue-Full": req.pool},
        )
    render_inflight.inc()
    _t0 = time.time()
    try:
        result = await _do_render(req)
        render_total.labels(result="success").inc()
        render_latency.observe(time.time() - _t0)
        # Count YARA matches by rule name.
        for match in result.yara_matches:
            render_yara_matches.labels(rule=match.rule).inc()
        return result
    except Exception:
        render_total.labels(result="failure").inc()
        render_latency.observe(time.time() - _t0)
        raise
    finally:
        render_inflight.dec()
        sem.release()


async def _do_render(req: RenderRequest) -> RenderResponse:
    t0 = time.time()
    evidence_id = str(uuid.uuid4())
    # Playwright records every request/response into a HAR file natively —
    # no mitmproxy/cert-mounting needed for the 80% case. mitmproxy stays
    # on the Phase 2 roadmap for the cases where we need decrypted bodies
    # of fetches initiated by service workers etc.
    har_path = f"/tmp/{evidence_id}.har"
    ctx = await _browser.new_context(
        viewport={"width": req.viewport[0], "height": req.viewport[1]},
        # Security scanner: we MUST see pages with invalid / self-signed /
        # expired certs — phishing infra routinely has bad certs. Refusing
        # to render them would blind us to a significant slice of malicious
        # content. The browser is isolated already (no user data, fresh
        # context per request).
        ignore_https_errors=True,
        # Realistic UA + locale so bot detectors don't auto-cloak us. Stealth
        # plugin handles the harder fingerprints (webdriver, WebGL, plugins).
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
        locale="en-US",
        timezone_id="America/Los_Angeles",
        record_har_path=har_path,
        record_har_content="omit",  # keep response bodies out — too large; URLs/headers are what we need
    )
    # try/finally guarantees ctx.close() runs even when an
    # exception escapes any of the post-creation steps below
    # (page.goto, page.evaluate, screenshot, YARA scan, S3 upload,
    # HAR flush). Without this, every render error leaked one
    # Chromium renderer process — verified to OOM the host at
    # ~500 leaked procs under fp-bench load on flaky phishing URLs.
    try:
        page = await ctx.new_page()
        if _STEALTH_AVAILABLE:
            try:
                await stealth_async(page)
            except Exception:  # pragma: no cover - best-effort
                pass

        # Behavioural instrumentation. Injected before the page executes so it
        # observes the page's first JS too. Hooks high-signal scam/scareware APIs
        # and stashes counters in window.__xgg_behavior, which we read out via
        # page.evaluate() after the render settles. Auto-dismisses alert/confirm/
        # prompt dialogs (the sandbox shouldn't block on them; they'd time out
        # the render).
        await ctx.add_init_script("""(() => {
          const b = { popup_open: 0, alert: 0, confirm: 0, prompt: 0,
                      fullscreen_req: 0, beforeunload: 0,
                      clipboard_write: 0, notification_perm: 0,
                      auto_download: 0, service_worker: 0,
                      postmessage_cross_origin: 0,
                      popup_targets: [] };
          window.__xgg_behavior = b;
          try {
            const _open = window.open;
            window.open = function(...a) { b.popup_open++;
              if (a[0] && b.popup_targets.length < 20) b.popup_targets.push(String(a[0]));
              return _open.apply(this, a); };
          } catch (e) {}
          try { window.alert   = function() { b.alert++; }; } catch (e) {}
          try { window.confirm = function() { b.confirm++; return false; }; } catch (e) {}
          try { window.prompt  = function() { b.prompt++; return null; }; } catch (e) {}
          try {
            const proto = Element.prototype;
            const _rfs = proto.requestFullscreen;
            if (_rfs) {
              proto.requestFullscreen = function(...a) { b.fullscreen_req++; return _rfs.apply(this, a); };
            }
          } catch (e) {}
          try {
            window.addEventListener('beforeunload', () => { b.beforeunload++; }, true);
            const _aelOrig = window.addEventListener;
            window.addEventListener = function(t, ...rest) {
              if (t === 'beforeunload') b.beforeunload++;
              return _aelOrig.call(this, t, ...rest);
            };
          } catch (e) {}
          try {
            if (navigator.clipboard) {
              const _wt = navigator.clipboard.writeText.bind(navigator.clipboard);
              navigator.clipboard.writeText = function(s) { b.clipboard_write++; return _wt(s); };
            }
          } catch (e) {}
          try {
            if (Notification && Notification.requestPermission) {
              const _rp = Notification.requestPermission.bind(Notification);
              Notification.requestPermission = function(...a) { b.notification_perm++; return _rp(...a); };
            }
          } catch (e) {}
          try {
            if (navigator.serviceWorker && navigator.serviceWorker.register) {
              const _sw = navigator.serviceWorker.register.bind(navigator.serviceWorker);
              navigator.serviceWorker.register = function(...a) { b.service_worker++; return _sw(...a); };
            }
          } catch (e) {}
          try {
            // Programmatic-anchor download detection (HTML smuggling). We can't
            // intercept HTMLAnchorElement.prototype.click cleanly across all
            // engines, so we observe click events on anchors carrying `download`.
            document.addEventListener('click', (e) => {
              const t = e.target;
              if (t && t.tagName === 'A' && t.hasAttribute('download')) {
                if (!e.isTrusted) b.auto_download++;
              }
            }, true);
          } catch (e) {}
          try {
            const _pm = window.postMessage;
            window.postMessage = function(msg, target, ...rest) {
              try {
                if (target && target !== '*' && target !== window.location.origin) {
                  b.postmessage_cross_origin++;
                }
              } catch (_) {}
              return _pm.call(this, msg, target, ...rest);
            };
          } catch (e) {}
        })();""")

        # Credential-sink instrumentation (Package 4 / dev spec §3).
        # Tracks where credential-bearing data would actually be sent: fetch,
        # XHR, sendBeacon, WebSocket. Also flags keystroke listeners on
        # sensitive fields (pre-submit capture) and DOM mutations that swap a
        # visible input for a hidden one (overlay attack).
        #
        # Privacy: we record metadata only — destination origin, method, byte
        # count — never the body contents. The page can still see its own data
        # exactly as it would without us; we're just reading the call graph.
        await ctx.add_init_script("""(() => {
          const s = {
            destinations: [],            // ordered list of {origin, method, capture_mode}
            cross_origin: false,
            pre_submit_capture: false,
            multi_destination: false,
            hidden_mirror: false,
            invisible_credential_field: false,
            pointer_events_trick: false,
            capture_modes: {},
            sensitive_listeners: 0,
            mutation_replaced_input: 0,
          };
          window.__xgg_sink = s;

          const _pageOrigin = (() => {
            try { return window.location.origin; } catch (_) { return ''; }
          })();

          // Sensitive-field heuristic: <input type=password>, or input whose
          // name/id/autocomplete strongly suggests credentials/OTP/payment.
          const SENSITIVE_NAME_RE =
            /(passwd|password|passcode|pin|otp|2fa|mfa|totp|seed|recovery|secret|cvv|cvc|cardnum|card[\\-_]?number|ccnum)/i;
          function isSensitiveInput(el) {
            if (!el || !el.tagName || el.tagName !== 'INPUT') return false;
            if ((el.type || '').toLowerCase() === 'password') return true;
            const v = (el.name || '') + ' ' + (el.id || '') + ' ' +
                      (el.getAttribute('autocomplete') || '') + ' ' +
                      (el.getAttribute('aria-label') || '');
            return SENSITIVE_NAME_RE.test(v);
          }

          function originOf(url) {
            try {
              const u = new URL(url, window.location.href);
              return u.origin;
            } catch (_) { return ''; }
          }
          function note(origin, method, mode) {
            if (!origin || origin === 'null') return;
            const isCross = _pageOrigin && origin !== _pageOrigin;
            if (isCross) s.cross_origin = true;
            s.capture_modes[mode] = (s.capture_modes[mode] || 0) + 1;
            if (s.destinations.length < 50) {
              s.destinations.push({ origin, method, mode, cross: isCross });
            }
            // multi-destination = two or more *distinct* cross-origin sinks.
            if (isCross) {
              const seen = new Set();
              for (const d of s.destinations) {
                if (d.cross) seen.add(d.origin);
              }
              if (seen.size >= 2) s.multi_destination = true;
            }
          }

          // --- fetch ---
          try {
            const _fetch = window.fetch;
            window.fetch = function(input, init) {
              try {
                const url = typeof input === 'string' ? input : (input && input.url) || '';
                const method = (init && init.method) || (input && input.method) || 'GET';
                note(originOf(url), String(method).toUpperCase(), 'fetch');
              } catch (_) {}
              return _fetch.apply(this, arguments);
            };
          } catch (_) {}

          // --- XHR ---
          try {
            const _open = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
              try { note(originOf(url), String(method || 'GET').toUpperCase(), 'xhr'); } catch (_) {}
              return _open.apply(this, arguments);
            };
          } catch (_) {}

          // --- sendBeacon ---
          try {
            if (navigator.sendBeacon) {
              const _sb = navigator.sendBeacon.bind(navigator);
              navigator.sendBeacon = function(url, data) {
                try { note(originOf(url), 'POST', 'beacon'); } catch (_) {}
                return _sb(url, data);
              };
            }
          } catch (_) {}

          // --- WebSocket ---
          try {
            const _WS = window.WebSocket;
            window.WebSocket = function(url, protocols) {
              try { note(originOf(url), 'WS', 'websocket'); } catch (_) {}
              return new _WS(url, protocols);
            };
            window.WebSocket.prototype = _WS.prototype;
          } catch (_) {}

          // --- addEventListener spy: catch keystroke listeners on sensitive fields ---
          try {
            const _addEL = EventTarget.prototype.addEventListener;
            const SENSITIVE_EVENTS = new Set(['keyup', 'keydown', 'keypress', 'input', 'change', 'blur']);
            EventTarget.prototype.addEventListener = function(type, listener, options) {
              try {
                if (SENSITIVE_EVENTS.has(type) && isSensitiveInput(this)) {
                  s.sensitive_listeners++;
                  // Wrap listener so calls inside it count as "presubmit" candidates.
                  if (typeof listener === 'function') {
                    const _orig = listener;
                    listener = function(ev) {
                      // Mark window so subsequent fetch/XHR within the same
                      // microtask is attributed to keystroke-capture.
                      const prev = window.__xgg_in_sensitive_listener;
                      window.__xgg_in_sensitive_listener = true;
                      try { return _orig.call(this, ev); }
                      finally { window.__xgg_in_sensitive_listener = prev; }
                    };
                  }
                }
              } catch (_) {}
              return _addEL.call(this, type, listener, options);
            };
          } catch (_) {}

          // Wrap fetch/XHR/sendBeacon notes to also flip pre_submit_capture
          // when called from inside a sensitive-field listener.
          const _origNote = note;
          // (Already inlined into the hooks above by checking the flag here.)
          const _markPresubmit = () => { if (window.__xgg_in_sensitive_listener) s.pre_submit_capture = true; };
          try {
            const _f2 = window.fetch;
            window.fetch = function() { _markPresubmit(); return _f2.apply(this, arguments); };
          } catch (_) {}
          try {
            const _o2 = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.send = function() { _markPresubmit(); return _o2.apply(this, arguments); };
          } catch (_) {}
          try {
            if (navigator.sendBeacon) {
              const _b2 = navigator.sendBeacon.bind(navigator);
              navigator.sendBeacon = function() { _markPresubmit(); return _b2.apply(this, arguments); };
            }
          } catch (_) {}

          // --- DOM scan + mutation observer ---
          function scanInputs(root) {
            try {
              root.querySelectorAll('input').forEach((el) => {
                if (!isSensitiveInput(el)) return;
                // Invisible / 1px credential field
                try {
                  const rect = el.getBoundingClientRect();
                  const style = window.getComputedStyle(el);
                  const isHidden =
                    el.type === 'hidden' ||
                    style.display === 'none' ||
                    style.visibility === 'hidden' ||
                    parseFloat(style.opacity) === 0 ||
                    (rect.width <= 2 && rect.height <= 2);
                  if (isHidden) s.invisible_credential_field = true;
                  // Pointer-events: none on a visible field is a redirect trick
                  // (the user types but the click goes elsewhere).
                  if (!isHidden && style.pointerEvents === 'none') {
                    s.pointer_events_trick = true;
                  }
                } catch (_) {}
              });
            } catch (_) {}
          }

          // Run once after load + once on every meaningful mutation.
          function once() {
            scanInputs(document);
            // Hidden-mirror: a visible password + a hidden field with same/similar name.
            try {
              const visibles = [];
              const hiddens = [];
              document.querySelectorAll('input').forEach((el) => {
                const sens = isSensitiveInput(el);
                const style = window.getComputedStyle(el);
                const hidden = el.type === 'hidden' || style.display === 'none' ||
                               style.visibility === 'hidden';
                if (sens && hidden) hiddens.push(el);
                else if (sens) visibles.push(el);
              });
              if (visibles.length && hiddens.length) s.hidden_mirror = true;
            } catch (_) {}
          }
          // First pass after DOM ready
          if (document.readyState === 'complete' || document.readyState === 'interactive') {
            setTimeout(once, 0);
          } else {
            document.addEventListener('DOMContentLoaded', once);
          }
          try {
            const obs = new MutationObserver((muts) => {
              let triggered = false;
              for (const m of muts) {
                if (m.type === 'childList') {
                  for (const n of m.removedNodes) {
                    if (n.tagName === 'INPUT' && isSensitiveInput(n)) {
                      s.mutation_replaced_input++;
                      triggered = true;
                    }
                  }
                }
              }
              if (triggered) once();
            });
            obs.observe(document.documentElement, { childList: true, subtree: true });
          } catch (_) {}
        })();""")

        # Auto-dismiss any native dialog that slips past our hook (some pages
        # call dialog.show() on subdocuments where Element-level overrides
        # don't apply).
        page.on("dialog", lambda d: __dismiss(d))

        redirect_chain: list[str] = []
        page.on("response", lambda r: redirect_chain.append(r.url) if r.status in (301, 302, 303, 307, 308) else None)

        try:
            await page.goto(str(req.url), wait_until=req.wait_until, timeout=RENDER_TIMEOUT_MS)
        except Exception as e:
            # CRITICAL: close the context before raising. Without this, every
            # failed navigation leaks one browser context = one chromium renderer
            # process. fp-bench against flaky phishing infra accumulated 500+
            # leaked renderers in 1 hour, OOMing the host and degrading mailcow.
            try:
                await ctx.close()
            except Exception:
                pass
            raise HTTPException(502, f"navigation failed: {e}") from e

        title = await page.title()
        final_url = page.url
        html = await page.content()
        screenshot_bytes = await page.screenshot(full_page=False, type="png")

        # Wave 3 Phase 2 — visible_text capture for support-scam / payment-scam /
        # crypto-drainer scoring. document.body.innerText is what the user
        # actually sees rendered (skips CSS-display:none + <script> + <style>).
        # Cap at VISIBLE_TEXT_MAX_BYTES so a runaway page doesn't bloat the
        # response. Empty string on extraction failure — scorer treats absent
        # text as "no signal," not as "clean."
        visible_text = ""
        try:
            raw = await page.evaluate(
                "() => (document.body && document.body.innerText) || ''"
            )
            visible_text = (raw or "")[:VISIBLE_TEXT_MAX_BYTES]
        except Exception:
            visible_text = ""

        # Bot-protection challenge detection. Run BEFORE form/download extraction
        # because nothing else on a challenge page is meaningful.
        is_challenge, challenge_kind = detect_challenge(title, html, final_url)

        # Extract favicon URL.
        favicon_url = await page.evaluate(
            """() => {
                const l = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"]');
                return l ? l.href : null;
            }"""
        )

        # Extract form actions.
        raw_forms: list[dict[str, Any]] = await page.evaluate(
            """() => {
                const out = [];
                for (const f of document.forms) {
                    out.push({
                        action: f.action || location.href,
                        has_password: !!f.querySelector('input[type="password"]'),
                        has_email: !!f.querySelector('input[type="email"], input[name*="email" i]'),
                    });
                }
                return out;
            }"""
        )

        page_origin = origin_of(final_url)
        forms: list[FormAction] = []
        for f in raw_forms:
            action = f.get("action") or ""
            ao = origin_of(action) if action else None
            forms.append(
                FormAction(
                    action=action,
                    action_origin=ao,
                    has_password=bool(f.get("has_password")),
                    has_email=bool(f.get("has_email")),
                    is_cross_origin=bool(ao and ao != page_origin),
                )
            )

        # Upload artifacts. boto3 is synchronous; wrap in to_thread so multi-MB
        # screenshot/DOM uploads don't block the event loop (Finding #10).
        ss_key  = f"{evidence_id}/screenshot.png"
        dom_key = f"{evidence_id}/dom.html"
        await asyncio.to_thread(
            s3.put_object, Bucket=S3_BUCKET, Key=ss_key,
            Body=screenshot_bytes, ContentType="image/png",
        )
        await asyncio.to_thread(
            s3.put_object, Bucket=S3_BUCKET, Key=dom_key,
            Body=html.encode("utf-8"), ContentType="text/html",
        )

        # Generate 15-minute pre-signed GET URLs (Audit Finding #2 — no public bucket).
        # Verdict-api stores these URLs in evidence.screenshot_url / dom_url.
        # They expire after 900s; portal-api re-signs at view time using the
        # s3:// URI stored in those fields (see portal-api TODO comment).
        # generate_presigned_url is synchronous (local signing, no network I/O
        # with most SDK versions) but wrap in to_thread for consistency and
        # safety against future SDK versions that may call the endpoint.
        _presign_ttl = 900
        screenshot_url = await asyncio.to_thread(
            s3.generate_presigned_url,
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": ss_key},
            ExpiresIn=_presign_ttl,
        )
        dom_url = await asyncio.to_thread(
            s3.generate_presigned_url,
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": dom_key},
            ExpiresIn=_presign_ttl,
        )

        # Discover downloadable / risky links via DOM eval and regex fallback.
        discovered = await page.evaluate(
            """() => {
                const out = new Set();
                for (const a of document.querySelectorAll('a[href]')) {
                    if (a.hasAttribute('download')) { out.add(a.href); continue; }
                    if (/\\.(exe|msi|scr|bat|cmd|ps1|vbs|jar|apk|dmg|iso|zip|rar|7z|doc[xm]?|xls[xm]?|ppt[xm]?|pdf|lnk)(\\?|#|$)/i.test(a.href)) {
                        out.add(a.href);
                    }
                }
                return Array.from(out);
            }"""
        )
        discovered_set = set(discovered or []) | set(discover_links(html, final_url))
        discovered_list = list(discovered_set)[:20]  # hard cap per page

        downloads: list[DownloadFinding] = []
        if discovered_list:
            async with httpx.AsyncClient() as dlc:
                findings = await asyncio.gather(
                    *(fetch_and_hash(u, dlc) for u in discovered_list),
                    return_exceptions=True,
                )
            for f in findings:
                if isinstance(f, FileFinding):
                    downloads.append(DownloadFinding(**f.__dict__))

        # Read the behavioural-instrumentation counters before closing the
        # context. Wrapped in try because the page may have navigated away or
        # the script may have failed (CSP, etc.) — in either case we degrade
        # to an empty behavior dict rather than aborting.
        behavior: dict[str, int] = {}
        try:
            behavior = await page.evaluate(
                "() => window.__xgg_behavior ? "
                "Object.fromEntries(Object.entries(window.__xgg_behavior)"
                ".filter(([k, v]) => typeof v === 'number')) : {}"
            ) or {}
        except Exception:
            behavior = {}
        pm_count = int(behavior.get("postmessage_cross_origin", 0))

        # Credential-sink snapshot (Package 4). Same defensive pattern.
        sink_raw: dict[str, Any] = {}
        try:
            sink_raw = await page.evaluate(
                "() => window.__xgg_sink ? JSON.parse(JSON.stringify(window.__xgg_sink)) : {}"
            ) or {}
        except Exception:
            sink_raw = {}

        # DOM inventory — links, iframes, hidden elements, suspicious JS, overlays.
        # Single page.evaluate() running the pre-built JS; result is parsed into
        # typed Pydantic models. Bypassed on challenge pages (body is just the
        # captcha wall; nothing meaningful to inventory). Wrapped in try so any
        # JS exception or Playwright error degrades to empty lists, not a crash.
        inventory_raw: dict[str, Any] = {}
        if not is_challenge:
            try:
                inventory_raw = await page.evaluate(_DOM_INVENTORY_JS) or {}
            except Exception:
                inventory_raw = {}
        inventory = parse_inventory(inventory_raw)

        # Belt-and-suspenders close — if anything in the screenshot/sink/YARA
        # path raised before this point, the request handler will propagate the
        # exception and ctx must still be released. Wrapping the whole post-goto
        # section in try/finally is the cleanest fix but requires a large diff;
        # this catches the explicit-success path and is idempotent for the
        # navigation-error path above (already closed).
        try:
            await ctx.close()
        except Exception:
            pass

        # HAR was being written for the lifetime of the context; close above
        # flushes it. Upload to S3, surface the URL on the response.
        har_url = ""
        try:
            with open(har_path, "rb") as fh:
                har_bytes = fh.read()
            har_key = f"{evidence_id}/network.har"
            # HAR files can be large (many network requests); upload off-thread
            # for the same reason as screenshot/DOM (Finding #10).
            await asyncio.to_thread(
                s3.put_object, Bucket=S3_BUCKET, Key=har_key,
                Body=har_bytes, ContentType="application/json",
            )
            har_url = await asyncio.to_thread(
                s3.generate_presigned_url,
                "get_object",
                Params={"Bucket": S3_BUCKET, "Key": har_key},
                ExpiresIn=_presign_ttl,
            )
            os.unlink(har_path)
        except FileNotFoundError:
            pass

        # YARA scan against the captured HTML. Skipped on challenge pages because
        # the body is just the captcha, not the real site.
        yara_matches: list[dict] = []
        yara_ms = 0
        if not is_challenge:
            scanner = default_scanner()
            raw, yara_ms = scanner.scan(html)
            yara_matches = matches_to_dicts(raw)

        # Shell-command IOC scan. Extracts <pre> / <code> / inline-code text from
        # the post-JS DOM and flags malicious-install patterns (the `&`-separator
        # trick, mshta + remote-HTA, rundll32 over UNC, base64 piped to zsh,
        # PowerShell IEX cradle, raw.githubusercontent of an installer). Catches
        # the Straiker-class "docs page IS the weapon" attack that visual-match,
        # YARA, credential-sink, and behavior counters all miss.
        shellcmd_result: dict[str, Any] = {}
        if not is_challenge:
            try:
                blocks = _extract_code_blocks(html)
                findings = scan_shell_commands(blocks)
                if findings.reason_codes or findings.has_hard_fail:
                    shellcmd_result = findings.to_dict()
            except Exception:  # pragma: no cover — defensive
                shellcmd_result = {}

        return RenderResponse(
            evidence_id=evidence_id,
            screenshot_url=screenshot_url,
            dom_url=dom_url,
            har_url=har_url or None,
            favicon_url=favicon_url,
            final_url=final_url,
            title=title,
            forms=forms,
            redirect_chain=redirect_chain,
            downloads=downloads,
            render_ms=int((time.time() - t0) * 1000),
            is_challenge_page=is_challenge,
            challenge_kind=challenge_kind,
            yara_matches=[YaraMatchOut(**m) for m in yara_matches],
            yara_ms=yara_ms,
            behavior=behavior,
            post_message_count=pm_count,
            sink=sink_raw,
            shellcmd=shellcmd_result,
            links=inventory["links"],
            iframes=inventory["iframes"],
            hidden_elements=inventory["hidden_elements"],
            suspicious_js=inventory["suspicious_js"],
            overlays=inventory["overlays"],
            visible_text=visible_text,
        )
    finally:
        try:
            await ctx.close()
        except Exception:
            pass


# Pre-compiled patterns for code-block extraction. Lightweight regex is
# enough for our IOC needs — full HTML parsing would be overkill here,
# and the patterns deliberately tolerate broken markup.
_CODE_BLOCK_RE = __import__("re").compile(
    r"<(?:pre|code)[^>]*>(.*?)</(?:pre|code)>",
    __import__("re").IGNORECASE | __import__("re").DOTALL,
)
_TAG_STRIP_RE = __import__("re").compile(r"<[^>]+>")
_HTML_ENT_RE = __import__("re").compile(r"&(?:amp|lt|gt|quot|#39|nbsp|#x?[0-9a-f]+);", __import__("re").IGNORECASE)


def _extract_code_blocks(html: str) -> list[tuple[str, str]]:
    """Extract text content of every <pre>/<code> block in the page.

    Returns a list of (block_id, decoded_text) tuples. block_id is the
    1-indexed position so analysts can correlate findings to the page.
    Decoded text strips inner tags (so <span> highlighting doesn't break
    pattern matching) and decodes a small set of common HTML entities.
    """
    import html as _html_mod  # local — used once
    out: list[tuple[str, str]] = []
    for i, m in enumerate(_CODE_BLOCK_RE.finditer(html or ""), 1):
        inner = m.group(1)
        # Strip nested tags (syntax highlighters wrap each token in a span).
        plain = _TAG_STRIP_RE.sub("", inner)
        # Decode HTML entities.
        try:
            plain = _html_mod.unescape(plain)
        except Exception:
            pass
        plain = plain.strip()
        if plain:
            out.append((f"block-{i}", plain))
    return out


async def __dismiss(dialog) -> None:  # noqa: ANN001
    try:
        await dialog.dismiss()
    except Exception:
        pass


def origin_of(url: str) -> str | None:
    from urllib.parse import urlparse

    try:
        u = urlparse(url)
        if not u.scheme or not u.netloc:
            return None
        return f"{u.scheme}://{u.netloc}"
    except Exception:
        return None
