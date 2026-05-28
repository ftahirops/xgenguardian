"""File-download discovery and SHA-256 fingerprinting.

For every downloadable artifact linked from a rendered page (anchor with
download attribute, direct binary content-types, suspicious extensions),
we fetch a small head sample, hash it, and report metadata. The verdict-api
then correlates the hashes against multi-AV / VirusTotal feeds.

Internal-testing relevant: when the operator visits a "malware download"
site, we want to log the file that *would* have been downloaded — without
ever executing it — and surface it in the live activity feed.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass

import httpx

# Extensions that frequently deliver malware. The presence of a link to one
# of these is itself a signal worth surfacing in the verdict, even before we
# pull the bytes.
RISKY_EXT = {
    "exe", "msi", "scr", "bat", "cmd", "com", "pif",
    "ps1", "vbs", "js", "jse", "wsf",
    "jar",
    "dll",
    "apk", "ipa",
    "dmg", "pkg",
    "iso", "img",
    "rar", "7z", "zip", "tar", "gz", "ace",
    "doc", "docm", "xls", "xlsm", "xlsb", "ppt", "pptm",
    "pdf",
    "lnk",
    "html", "htm",  # HTML smuggling
}

# Hard cap so a malicious server can't OOM us by streaming a huge file.
MAX_FETCH_BYTES = 4 * 1024 * 1024  # 4 MiB; enough for header + first chunk


@dataclass
class FileFinding:
    url: str
    extension: str | None
    content_type: str | None
    size_hint: int | None
    sha256: str | None
    risky: bool
    error: str | None = None


def discover_links(dom_html: str, page_url: str) -> list[str]:
    """Cheap regex-based discovery — full DOM-driven extraction lives in
    Playwright. This is a fallback / supplementary path."""
    urls: set[str] = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', dom_html):
        u = m.group(1)
        if u.startswith("javascript:") or u.startswith("#"):
            continue
        if u.startswith("//"):
            u = "https:" + u
        urls.add(u)
    for m in re.finditer(r'src=["\']([^"\']+\.(?:exe|msi|zip|rar|7z|iso|dmg))["\']', dom_html, re.I):
        urls.add(m.group(1))
    return list(urls)[:50]  # cap to avoid blowups


async def fetch_and_hash(url: str, client: httpx.AsyncClient) -> FileFinding:
    """Stream up to MAX_FETCH_BYTES; compute SHA-256 of what we got plus a
    size_hint from Content-Length. Never executes the file."""
    ext = _extension(url)
    risky = ext in RISKY_EXT if ext else False
    try:
        async with client.stream("GET", url, timeout=10, follow_redirects=True) as r:
            ct = r.headers.get("content-type")
            cl = r.headers.get("content-length")
            size_hint = int(cl) if cl and cl.isdigit() else None
            h = hashlib.sha256()
            got = 0
            async for chunk in r.aiter_bytes(chunk_size=65536):
                h.update(chunk)
                got += len(chunk)
                if got >= MAX_FETCH_BYTES:
                    break
            return FileFinding(
                url=url,
                extension=ext,
                content_type=ct,
                size_hint=size_hint or got,
                sha256=h.hexdigest(),
                risky=risky or _ct_is_binary(ct),
            )
    except Exception as e:
        return FileFinding(
            url=url,
            extension=ext,
            content_type=None,
            size_hint=None,
            sha256=None,
            risky=risky,
            error=str(e),
        )


def _extension(url: str) -> str | None:
    m = re.search(r"\.([A-Za-z0-9]{1,8})(?:[?#]|$)", url)
    if not m:
        return None
    return m.group(1).lower()


def _ct_is_binary(ct: str | None) -> bool:
    if not ct:
        return False
    ct = ct.lower()
    return (
        ct.startswith("application/octet-stream")
        or ct.startswith("application/x-msdownload")
        or ct.startswith("application/x-msdos-program")
        or ct.startswith("application/x-executable")
        or ct.startswith("application/vnd.android.package-archive")
    )
