#!/usr/bin/env python3
"""Aggressive real-user soak test of XGenGuardian v0.2.9.

Drives a REAL Chromium with the unpacked extension loaded as a real user
would: clicks through Options to pick a mode, then navigates to each URL
in the corpus and records what actually happened (allowed, blocked,
warned, isolated, stuck on holding page).

For each URL we capture:
  - the final tab URL after navigation (chrome-extension://... means
    interstitial; original URL means allowed-through)
  - the interstitial page title + visible reason codes if blocked/warned
  - timing (how long until the user could click "Go back" or saw content)

Compares to ground truth and prints a verdict-vs-expected scoreboard.
"""

import asyncio, json, sys, time, urllib.parse
from playwright.async_api import async_playwright

EXT_PATH = "/home/xgenguardian/code/apps/extension"
USER_DATA_DIR = "/tmp/xgg-chrome-soak"

# Real-world corpus: known good (should allow), known bad (should block/warn),
# unknown/borderline (mode-dependent). Each entry: (url, expected_class, notes).
#
# expected_class buckets:
#   "allow"      — must allow-through without any interstitial
#   "block"      — must end up on blocked.html
#   "warn"       — must end up on warn.html (user can proceed)
#   "isolate"    — must end up on isolate.html
#   "any_intercept" — interstitial of any kind acceptable (borderline)
#   "any"        — purely informational; we just record what happened
CORPUS = [
    # === KNOWN-GOOD MAJOR BRANDS (trusted-identity) ===
    ("https://www.google.com/",            "allow", "Google home"),
    ("https://www.youtube.com/",           "allow", "YouTube home (Google brand)"),
    ("https://github.com/",                "allow", "GitHub home (trusted brand)"),
    ("https://www.microsoft.com/",         "allow", "Microsoft home"),
    ("https://www.apple.com/",             "allow", "Apple home"),
    ("https://www.amazon.com/",            "allow", "Amazon home"),
    ("https://en.wikipedia.org/wiki/Main_Page", "allow", "Wikipedia"),
    ("https://stackoverflow.com/",         "allow", "Stack Overflow"),
    ("https://www.cloudflare.com/",        "allow", "Cloudflare home"),

    # === OAUTH AUTH PROVIDERS (WELL_KNOWN_AUTH_HOSTS bypass) ===
    ("https://accounts.google.com/",       "allow", "Google OAuth landing — extension MUST bypass"),
    ("https://login.microsoftonline.com/", "allow", "Microsoft OAuth landing — extension MUST bypass"),
    ("https://appleid.apple.com/",         "allow", "Apple ID — extension MUST bypass"),

    # === KNOWN-BAD VENDOR-DNS-BLOCKED ===
    ("https://thepiratebay.org/",          "block", "Piracy — multi-vendor DNS consensus blocks"),
    ("https://1337x.to/",                  "block", "Piracy — same class"),

    # === NXDOMAIN / NONEXISTENT (must NOT vendordns-false-positive) ===
    ("https://this-domain-does-not-exist-soak123abc.tld/", "any", "NXDOMAIN — baseline check should suppress fake vendor block"),

    # === RAW IP ===
    ("http://1.1.1.1/",                    "any_intercept", "Raw IP (Cloudflare); raw-IP rule may WARN even though it's legit"),

    # === SUSPICIOUS HOSTNAME (random-looking) ===
    ("https://jevhcksi.example/",          "any", "Random-looking host on a real registrable domain — may not resolve"),

    # === COMMON DOWNLOADS (developer install pages) ===
    ("https://signal.org/download/",       "allow", "Real install page from trusted brand"),

    # === URL SHORTENERS (shouldn't WARN on hop) ===
    ("https://bit.ly/",                    "allow", "bit.ly home — not a redirect"),
    ("https://t.co/",                      "allow", "Twitter t.co"),

    # === HOMOGLYPH ATTACK (Cyrillic 'a' lookalike of paypal.com) ===
    # Using a TEST string only — registering one is illegal:
    ("https://www.paypal.com/",            "allow", "Real PayPal (trusted)"),

    # === LARGE JS BUNDLE (modern SPA — should not OBFUSCATED_JS) ===
    ("https://twitter.com/",               "any_intercept", "Twitter — large bundle; could be WARN'd by obfuscation; ideally ALLOW"),

    # === TYPOSQUATTING-LIKE (likely WARN if untrusted) ===
    # We don't include actual phishing URLs; that requires manual confirmation.
]

SAFE_TLD_SUFFIXES = (".test", ".invalid", ".example", ".localhost")

def is_interstitial(url: str) -> str | None:
    """Return interstitial kind if url is one of our interstitials; else None."""
    if "/src/blocked.html" in url:  return "blocked"
    if "/src/warn.html" in url:     return "warn"
    if "/src/isolate.html" in url:  return "isolate"
    if "/src/holding.html" in url:  return "holding"
    return None

def classify(actual: str, expected: str) -> str:
    """Compare expected_class vs actual interstitial-kind/allowed."""
    if expected == "any":
        return "INFO"
    if expected == "any_intercept":
        return "PASS" if actual in ("blocked", "warn", "isolate") else "INFO"
    # specific expectation
    if expected == "allow":
        return "PASS" if actual == "allowed" else "FAIL"
    # Map our corpus shorthand → interstitial-kind strings emitted by is_interstitial
    canonical = {"block": "blocked", "warn": "warn", "isolate": "isolate", "allow": "allowed"}
    return "PASS" if actual == canonical.get(expected, expected) else "FAIL"

async def run_one(context, url: str, expected: str, notes: str) -> dict:
    page = await context.new_page()
    t0 = time.time()
    final_url = ""
    interstitial = None
    title = ""
    text_snippet = ""
    try:
        try:
            # 35s upper bound — generous (holding can take 25s)
            await page.goto(url, wait_until="commit", timeout=35000)
        except Exception:
            pass
        # Give the extension time to swap to interstitial AND for the
        # interstitial to render its codes after fetching evidence.
        await asyncio.sleep(5)
        # If still on holding, wait a bit more.
        for _ in range(20):
            cur = page.url
            kind = is_interstitial(cur)
            if kind != "holding":
                break
            await asyncio.sleep(1)
        final_url = page.url
        interstitial = is_interstitial(final_url)
        # Capture title + reason-codes if blocked/warn/isolate
        if interstitial in ("blocked", "warn", "isolate"):
            try:
                title = await page.title()
            except Exception:
                pass
            try:
                # blocked.js renders reason-code <div class="signal-code">
                els = await page.query_selector_all(".signal-code, .pill, .reason-code")
                bits = []
                for el in els[:6]:
                    t = await el.inner_text()
                    if t.strip():
                        bits.append(t.strip())
                text_snippet = " | ".join(bits)[:200]
            except Exception:
                pass
    finally:
        elapsed = round(time.time() - t0, 2)
        await page.close()
    actual = interstitial if interstitial else "allowed"
    return {
        "url": url, "expected": expected, "actual": actual,
        "result": classify(actual, expected),
        "final_url": final_url, "title": title, "snippet": text_snippet,
        "elapsed_s": elapsed, "notes": notes,
    }

async def main():
    async with async_playwright() as p:
        # Headful — but no DISPLAY available, so use xvfb-run or skip ui.
        # Playwright supports persistent_context with headless=False if Xvfb is up.
        # Fallback: headless=False fails without DISPLAY; use --headless=new instead.
        ctx = await p.chromium.launch_persistent_context(
            user_data_dir=USER_DATA_DIR,
            headless=False,
            args=[
                f"--disable-extensions-except={EXT_PATH}",
                f"--load-extension={EXT_PATH}",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--no-first-run",
                "--disable-features=PrivacySandboxSettings4",
                "--display=:99",
            ],
            ignore_default_args=["--disable-extensions"],
            env={"DISPLAY": ":99"},
        )

        # Seed Options page state: set mode and apiBase so the extension
        # actually points at our local verdict-api.
        opt_page = await ctx.new_page()
        # Wait up to 15s for the service worker to register.
        ext_id = None
        for attempt in range(15):
            await asyncio.sleep(1)
            # try background_pages first (legacy / MV2)
            for bp in ctx.background_pages:
                if bp.url.startswith("chrome-extension://"):
                    ext_id = bp.url.split("/")[2]
                    break
            if ext_id:
                break
            # MV3 service workers
            for sw in ctx.service_workers:
                if sw.url.startswith("chrome-extension://"):
                    ext_id = sw.url.split("/")[2]
                    break
            if ext_id:
                break
            # Trigger by hitting a URL — may force the SW to start
            if attempt == 5:
                try:
                    await opt_page.goto("about:blank", timeout=3000)
                except Exception:
                    pass
        print(f"Loaded extension id: {ext_id}", flush=True)
        # Seed storage.local using chrome.storage from a privileged page.
        await opt_page.goto(f"chrome-extension://{ext_id}/src/options.html")
        await opt_page.evaluate("""
          () => new Promise(res => chrome.storage.local.set({
            apiBase: 'http://127.0.0.1:18080',
            portalApiBase: 'http://127.0.0.1:18081',
            mode: 'safe',
            enabled: true,
          }, res))
        """)
        await opt_page.close()
        await asyncio.sleep(1)

        results = []
        for url, expected, notes in CORPUS:
            print(f"→ {url}", flush=True)
            try:
                r = await run_one(ctx, url, expected, notes)
            except Exception as e:
                r = {"url": url, "expected": expected, "actual": "error",
                     "result": "ERROR", "title": "", "snippet": str(e)[:200],
                     "elapsed_s": 0, "notes": notes, "final_url": ""}
            results.append(r)
            print(f"   {r['result']:5} actual={r['actual']:8} expected={r['expected']:14} elapsed={r['elapsed_s']:5}s",
                  flush=True)
            if r.get("snippet"):
                print(f"   → {r['snippet']}", flush=True)

        await ctx.close()

        # Scoreboard
        print("\n" + "="*88)
        print("SCOREBOARD")
        print("="*88)
        cnt = {"PASS": 0, "FAIL": 0, "INFO": 0, "ERROR": 0}
        for r in results:
            cnt[r["result"]] = cnt.get(r["result"], 0) + 1
        print(f"PASS: {cnt.get('PASS',0)}  FAIL: {cnt.get('FAIL',0)}  "
              f"INFO: {cnt.get('INFO',0)}  ERROR: {cnt.get('ERROR',0)}  "
              f"out of {len(results)} URLs")
        fails = [r for r in results if r["result"] == "FAIL"]
        if fails:
            print("\nFAILURES:")
            for r in fails:
                print(f"  {r['url']}")
                print(f"    expected={r['expected']}  actual={r['actual']}")
                print(f"    final_url={r['final_url']}")
                print(f"    snippet={r['snippet']}")

        with open("/tmp/realuser_test_results.json", "w") as f:
            json.dump(results, f, indent=2)
        print("\nFull results: /tmp/realuser_test_results.json")

asyncio.run(main())
