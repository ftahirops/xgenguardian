"""Shell-command IOC scanner for rendered docs/install pages.

Why this exists: the 2026-05-27 Straiker report on the "Fake Claude Code"
campaign documented attacks where the malicious payload is just *text in
the page* — a docs-style HTML block with a shell command containing the
`&` separator trick, base64+zsh decode, mshta+remote-HTA, GitHub-hosted
script, or JS-injected cloaked commands. None of these are caught by
visual brand match, credential-sink, behavior, or YARA. The page itself
is the weapon.

This module runs after page render, walks every <code>, <pre>, and
inline-rendered shell snippet, and flags suspicious patterns. The verdict
service uses the resulting reason codes to elevate verdicts on what would
otherwise look like a benign docs page.

Scope: heuristic only. Designed to be cheap and high-precision. Misses
are acceptable; false positives are NOT (a docs page that genuinely shows
a `curl ... | bash` install is everywhere). To keep FP low we require
*combinations* of red flags — single signals are advisory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


# --- IOC pattern definitions (compiled once at import) ---

# Hard fails — patterns that are near-impossible to see on a legitimate
# install page. Any single match here flips the page to suspicious.
HARD_FAIL_PATTERNS: list[tuple[str, re.Pattern]] = [
    # rundll32 loading a DLL from a UNC path (Straiker's WebDAV technique).
    ("RUNDLL32_UNC_PATH", re.compile(
        r"\brundll32(?:\.exe)?\s+\\\\[^\s\"';|&]+", re.IGNORECASE)),
    # mshta.exe fetching a remote HTA. The Variant B chain.
    ("MSHTA_REMOTE_HTA", re.compile(
        r"\bmshta(?:\.exe)?\s+https?://", re.IGNORECASE)),
    # PowerShell IEX (invoke-expression) on a remote download — classic
    # malware staging cradle. Includes IEX, Invoke-Expression, irm | iex.
    ("POWERSHELL_IEX_REMOTE", re.compile(
        r"\b(?:IEX|Invoke-Expression|iwr|irm)\b[^\n]{0,200}\bhttps?://",
        re.IGNORECASE)),
    # certutil downloading and decoding — common malware staging.
    ("CERTUTIL_URLCACHE", re.compile(
        r"\bcertutil\b.*-(?:urlcache|decode)", re.IGNORECASE)),
    # WMIC remote process (less common, but always suspicious in docs).
    ("WMIC_REMOTE_PROCESS", re.compile(
        r"\bwmic\s+/node:", re.IGNORECASE)),
]

# Soft signals — common in malicious chains, also occasionally legitimate.
# Each one alone is advisory; combinations promote.
SOFT_SIGNAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    # The `&` trick — bash command-separator that backgrounds the decoy
    # and foregrounds the payload. Real install scripts use `&&` (AND),
    # not bare `&`. We require it specifically next to curl/wget/irm.
    ("SHELL_AMPERSAND_TRICK", re.compile(
        r"\b(?:curl|wget|irm|iwr)\s[^\n;]*\s&\s+(?:bash|sh|zsh|powershell|rundll32|mshta)",
        re.IGNORECASE)),
    # Base64 decoded then piped to a shell. Used to hide the actual C2 URL.
    ("BASE64_PIPED_TO_SHELL", re.compile(
        r"\bbase64\b[^\n|]*\s*[|]\s*(?:bash|sh|zsh)", re.IGNORECASE)),
    # echo/printf of obvious base64 then piped — same family.
    ("ECHO_BASE64_PIPED", re.compile(
        r"\becho\s+['\"][A-Za-z0-9+/=]{40,}['\"][^|]*[|]\s*(?:base64|bash|sh|zsh)",
        re.IGNORECASE)),
    # Curl/wget piping directly to a shell — used legitimately for some
    # installers, but a major red flag when combined with other signals.
    ("CURL_PIPE_SHELL", re.compile(
        r"\b(?:curl|wget)\s[^\n|;]*[|]\s*(?:bash|sh|zsh)", re.IGNORECASE)),
    # Fetch from raw.githubusercontent of an installer — Straiker's GitHub
    # variant. Suspicious when the org/repo isn't the documented vendor.
    ("RAW_GITHUB_INSTALLER", re.compile(
        r"raw\.githubusercontent\.com/[^/\s\"']+/[^/\s\"']*(?:install|setup|loader|bootstrap)",
        re.IGNORECASE)),
    # Hidden network paths in commands (UNC, file://).
    ("UNC_PATH_IN_COMMAND", re.compile(
        r"\\\\[a-z0-9_.-]+\.(?:com|net|org|io|app|cloud|me|to|in|digital|cfd|click)\\",
        re.IGNORECASE)),
    # PowerShell with -EncodedCommand (always base64-encoded payload).
    ("POWERSHELL_ENCODED_COMMAND", re.compile(
        r"\bpowershell(?:\.exe)?\s+(?:-\w+\s+)*-(?:e|enc|encodedcommand)\b",
        re.IGNORECASE)),
    # Bypass execution policy + run from URL.
    ("POWERSHELL_BYPASS_POLICY", re.compile(
        r"-ExecutionPolicy\s+Bypass", re.IGNORECASE)),
]


@dataclass
class ShellCmdFindings:
    """Per-page extraction result. Empty when no shell commands found."""
    # List of (code_id, full_command_text) tuples — for analyst drilldown.
    commands_seen: list[tuple[str, str]] = field(default_factory=list)
    # Reason codes that fired. Wire-stable strings consumed by verdict-api.
    reason_codes: list[str] = field(default_factory=list)
    # Hard-fail flag — any pattern in HARD_FAIL_PATTERNS matched.
    has_hard_fail: bool = False
    # Soft-signal count — used by policy to decide if 2+ soft signals
    # combine into a verdict elevation.
    soft_signal_count: int = 0

    def to_dict(self) -> dict:
        return {
            "commands_seen": [
                {"id": cid, "text": txt[:500]} for cid, txt in self.commands_seen[:20]
            ],
            "reason_codes": self.reason_codes,
            "has_hard_fail": self.has_hard_fail,
            "soft_signal_count": self.soft_signal_count,
        }


def scan_commands(commands: Iterable[tuple[str, str]]) -> ShellCmdFindings:
    """Scan a sequence of (code_id, command_text) and return findings.

    code_id is an opaque identifier so analyst tooling can point at the
    specific <code> block that triggered the match. command_text is the
    raw text content of the block.

    Beyond IOC pattern matching, this also surfaces *shell-looking* blocks
    (commands that contain curl/wget/irm/brew/npm install/pip install/etc)
    in commands_seen even when no IOC pattern fires. The downstream
    installreg.MatchCommand uses this to award OfficialMatch when a page
    publishes a recognized canonical install command. Surfacing happens
    regardless of pattern match so the positive-trust path has data.
    """
    out = ShellCmdFindings()
    seen_codes: set[str] = set()
    surfaced_ids: set[str] = set()
    for cid, text in commands:
        if not text or len(text) < 8:
            continue
        # Cap per-block scan size — pathological pages won't bloat us.
        snippet = text[:8192]
        block_codes: list[str] = []

        for code, pat in HARD_FAIL_PATTERNS:
            if pat.search(snippet):
                block_codes.append(code)
                out.has_hard_fail = True

        for code, pat in SOFT_SIGNAL_PATTERNS:
            if pat.search(snippet):
                block_codes.append(code)
                out.soft_signal_count += 1

        if block_codes:
            out.commands_seen.append((cid, text[:1000]))
            surfaced_ids.add(cid)
            for c in block_codes:
                if c not in seen_codes:
                    seen_codes.add(c)
                    out.reason_codes.append(c)
            continue

        # Positive-trust surfacing: include shell-install commands even
        # when no IOC pattern fired. Bounded to top 10 to avoid bloating
        # the response on a doc page with many code blocks.
        if cid not in surfaced_ids and len(out.commands_seen) < 10:
            if SHELL_INSTALL_HINT.search(snippet):
                out.commands_seen.append((cid, text[:1000]))
                surfaced_ids.add(cid)

    return out


# Lightweight hint pattern — does this code block look like an install
# command at all? Cheaper than the full IOC scan and runs only when a
# block didn't already hit one. Catches the templates installreg knows
# about (curl|sh, npm install, pip install, brew install, etc.).
SHELL_INSTALL_HINT = re.compile(
    r"""\b(?:
            curl\s+[^\n]*\|\s*(?:bash|sh|zsh)
          | wget\s+[^\n]*\|\s*(?:bash|sh|zsh)
          | irm\s+[^\n]*\|\s*iex
          | npm\s+(?:install|i)\s+\S
          | yarn\s+(?:add|global\s+add)\s+\S
          | pnpm\s+(?:install|add|i)\s+\S
          | pip\s+install\s+\S
          | pip3\s+install\s+\S
          | brew\s+install\s+\S
          | brew\s+tap\s+\S
          | apt(?:-get)?\s+install\s+\S
          | dnf\s+install\s+\S
          | yum\s+install\s+\S
          | pacman\s+-S\s+\S
          | choco\s+install\s+\S
          | scoop\s+install\s+\S
          | cargo\s+install\s+\S
          | go\s+install\s+\S
          | code\s+--install-extension\s+\S
          | /bin/bash\s+-c
        )\b""",
    re.IGNORECASE | re.VERBOSE,
)
