"""Bot-protection challenge detection — pure-function module.

Extracted from main.py so tests can import it without dragging the whole
FastAPI / Playwright / boto3 stack along for the ride.

Detects Cloudflare Turnstile / classic challenge, DataDome, Akamai/Imperva,
reCAPTCHA walls, and a generic small-iframe-only fallback. Strict by design:
title alone gives too many false positives, so most rules require both a
title hint AND a body marker (or a self-strong body marker like Turnstile).
"""
from __future__ import annotations

_CLOUDFLARE_MARKERS = (
    "cf-browser-verification",
    "cf-challenge-running",
    "cf_chl_opt",
    "/cdn-cgi/challenge-platform/",
    "challenges.cloudflare.com/turnstile/",
    "Checking if the site connection is secure",
    "Verify you are human by completing the action below",
)
_RECAPTCHA_MARKERS = (
    "google.com/recaptcha/api2/anchor",
    "Verify you are human",
    'class="g-recaptcha"',
)
_DATADOME_MARKERS = (
    "geo.captcha-delivery.com",
    "datadome.co/captcha",
)
_AKAMAI_MARKERS = (
    "_abck",
    "akam-",
    "/_Incapsula_Resource",  # Imperva folded into this bucket
)


def detect_challenge(title: str, html: str, final_url: str) -> tuple[bool, str | None]:
    """Return (is_challenge_page, challenge_kind)."""
    if not html:
        return False, None
    title_l = (title or "").lower()
    html_l  = html.lower()

    # Cloudflare — strong if Turnstile script seen anywhere.
    if "challenges.cloudflare.com/turnstile/" in html_l:
        return True, "cloudflare"
    if any(m.lower() in html_l for m in _CLOUDFLARE_MARKERS):
        cf_title_hint = (
            "just a moment" in title_l
            or "attention required" in title_l
            or "checking your browser" in title_l
        )
        if cf_title_hint or "cf-challenge-running" in html_l:
            return True, "cloudflare"

    if any(m.lower() in html_l for m in _DATADOME_MARKERS):
        return True, "datadome"

    if "/_incapsula_resource" in html_l:
        return True, "akamai"

    if any(m.lower() in html_l for m in _RECAPTCHA_MARKERS):
        if "verify" in title_l or "robot" in title_l or "human" in title_l:
            return True, "recaptcha"

    # Generic last-resort: empty title + very small body + iframe present.
    if not title_l and len(html_l) < 4000 and "<iframe" in html_l:
        return True, "generic"

    return False, None
