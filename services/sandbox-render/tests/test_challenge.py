"""Bot-protection challenge detector tests.

We only test the pure-function detect_challenge() — Playwright integration is
out of scope for unit tests.
"""
from app.challenge import detect_challenge


def test_cloudflare_turnstile():
    html = '<html><body><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></body></html>'
    ok, kind = detect_challenge("Just a moment...", html, "https://example.com/")
    assert ok is True
    assert kind == "cloudflare"


def test_cloudflare_classic_challenge():
    html = '<html><body><div id="cf-challenge-running"></div></body></html>'
    ok, kind = detect_challenge("Attention Required! | Cloudflare", html, "https://x.test/")
    assert ok is True
    assert kind == "cloudflare"


def test_datadome_captcha():
    html = '<html><body><iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=…"></iframe></body></html>'
    ok, kind = detect_challenge("Captcha", html, "https://x.test/")
    assert ok is True
    assert kind == "datadome"


def test_recaptcha_with_title_hint():
    html = '<html><body><div class="g-recaptcha"></div></body></html>'
    ok, kind = detect_challenge("Verify you are human", html, "https://x.test/")
    assert ok is True
    assert kind == "recaptcha"


def test_recaptcha_without_title_hint_is_not_challenge():
    # Some legitimate sites embed reCAPTCHA on their actual content pages.
    # Without a title hint we shouldn't flag.
    html = '<html><body><h1>Welcome</h1><div class="g-recaptcha"></div></body></html>'
    ok, _ = detect_challenge("Welcome to Acme", html, "https://acme.test/")
    assert ok is False


def test_legit_page_with_title_only_match_is_not_challenge():
    # "Just a moment" can appear legitimately.
    html = '<html><body><h1>News</h1><p>content content content content content content content content content content content content content content content content</p></body></html>' * 40
    ok, _ = detect_challenge("Just a moment of your time", html, "https://acme.test/")
    assert ok is False


def test_empty_inputs():
    assert detect_challenge("", "", "") == (False, None)
    assert detect_challenge("title", "", "") == (False, None)
