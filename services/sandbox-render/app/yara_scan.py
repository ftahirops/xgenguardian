"""YARA signature scanning for rendered pages.

Loads every `.yar` / `.yara` file under `YARA_RULES_DIR` (default
`<repo>/services/sandbox-render/rules/`) at startup, compiles them once, and
exposes a single `scan(content_bytes)` entrypoint. Per-rule meta is preserved
so callers can read `reason_code`, `severity`, `description`.

Optional import: if `yara-python` (and the underlying `libyara`) isn't
installed the module loads in a disabled state — `scan()` returns an empty
list. Sandbox-render keeps working; verdict-api just doesn't get YARA
signals. This matches our playwright-stealth pattern.
"""
from __future__ import annotations

import dataclasses
import logging
import os
import pathlib
import time
from typing import Iterable

log = logging.getLogger(__name__)

try:
    import yara  # type: ignore
    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on libyara presence
    _YARA_AVAILABLE = False
    yara = None  # type: ignore


DEFAULT_RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"
MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5 MB cap per page
MATCH_LIMIT    = 32               # surface at most this many matches per scan


@dataclasses.dataclass
class YaraMatch:
    rule:        str
    namespace:   str
    severity:    str  # 'low' | 'medium' | 'high' | 'critical'
    reason_code: str  # canonical code; 'YARA_SIGNATURE_MATCH' if rule didn't set one
    description: str
    tags:        list[str]


class YaraScanner:
    def __init__(self, rules_dir: pathlib.Path | None = None):
        self.rules_dir = pathlib.Path(rules_dir or os.getenv("YARA_RULES_DIR") or DEFAULT_RULES_DIR)
        self._rules = None
        self._rule_count = 0
        if not _YARA_AVAILABLE:
            log.warning("yara-python not installed; YARA scanning disabled")
            return
        try:
            self._load_rules()
        except Exception as e:  # pragma: no cover
            log.warning("yara: rule compile failed: %s — disabling", e)
            self._rules = None

    def _load_rules(self) -> None:
        if not self.rules_dir.exists():
            log.warning("yara: rules dir %s missing — no rules loaded", self.rules_dir)
            return
        sources: dict[str, str] = {}
        # Per-file compile so a single broken file doesn't disable the lot.
        for path in sorted(self.rules_dir.glob("*.yar")) + sorted(self.rules_dir.glob("*.yara")):
            try:
                with path.open("r", encoding="utf-8") as f:
                    yara.compile(source=f.read())  # validate
                sources[path.stem] = str(path)
            except Exception as e:
                log.warning("yara: skipping %s — compile error: %s", path.name, e)
        if not sources:
            log.warning("yara: no compilable rules found in %s", self.rules_dir)
            return
        self._rules = yara.compile(filepaths=sources)
        self._rule_count = len(sources)
        log.info("yara: %d rule file(s) compiled from %s", self._rule_count, self.rules_dir)

    @property
    def enabled(self) -> bool:
        return self._rules is not None

    @property
    def rule_count(self) -> int:
        return self._rule_count

    def scan(self, content: bytes | str) -> tuple[list[YaraMatch], int]:
        """Return (matches, elapsed_ms). Safe to call when disabled."""
        if not self.enabled:
            return [], 0
        if isinstance(content, str):
            content = content.encode("utf-8", errors="replace")
        if len(content) > MAX_SCAN_BYTES:
            content = content[:MAX_SCAN_BYTES]
        t0 = time.time()
        try:
            raw = self._rules.match(data=content, timeout=5)  # type: ignore[union-attr]
        except Exception as e:  # pragma: no cover
            log.warning("yara: scan error: %s", e)
            return [], int((time.time() - t0) * 1000)

        out: list[YaraMatch] = []
        for m in raw[:MATCH_LIMIT]:
            meta = _ensure_dict(m.meta)
            out.append(
                YaraMatch(
                    rule=m.rule,
                    namespace=m.namespace,
                    severity=str(meta.get("severity", "medium")).lower(),
                    reason_code=str(meta.get("reason_code", "YARA_SIGNATURE_MATCH")),
                    description=str(meta.get("description", "")),
                    tags=list(m.tags or []),
                )
            )
        return out, int((time.time() - t0) * 1000)


def _ensure_dict(meta: object) -> dict[str, object]:
    """yara-python returns meta as a list of (k,v) on some versions."""
    if isinstance(meta, dict):
        return meta
    out: dict[str, object] = {}
    try:
        for k, v in meta:  # type: ignore[misc]
            out[str(k)] = v
    except Exception:
        pass
    return out


# Module-level singleton for the FastAPI app.
_default: YaraScanner | None = None


def default_scanner() -> YaraScanner:
    global _default
    if _default is None:
        _default = YaraScanner()
    return _default


def matches_to_dicts(matches: Iterable[YaraMatch]) -> list[dict[str, object]]:
    return [dataclasses.asdict(m) for m in matches]
