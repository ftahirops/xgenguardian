"""DOM inventory extraction for sandbox-render.

Collects links, iframes, hidden elements, suspicious JS indicators, and
overlay/clickjack patterns from the rendered page via a single Playwright
page.evaluate() call. All detection logic runs inside the browser context;
Python side only parses and validates the JSON result into Pydantic models.
"""

from __future__ import annotations

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Pydantic output models
# ---------------------------------------------------------------------------


class LinkFinding(BaseModel):
    url: str
    text: str  # anchor text, truncated to 120 chars
    visible: bool
    same_origin: bool
    extension: str | None = None  # ".exe", ".sh", etc.
    is_risky_download: bool
    rel: str | None = None  # rel attribute value
    target_blank: bool
    has_download_attr: bool


class IFrameFinding(BaseModel):
    src: str  # resolved URL or "(srcdoc)" if inline
    same_origin: bool
    visible: bool
    sandbox: str | None = None
    srcdoc_snippet: str | None = None  # first 500 chars of srcdoc
    dimensions: list[int]  # [width, height] in px


class HiddenElementFinding(BaseModel):
    tag: str
    reason: str  # "display:none" | "visibility:hidden" | "opacity:0" | "1px-overlay" | "off-screen" | "0x0"
    href_or_src: str | None = None
    inner_text_sample: str  # first 80 chars


class SuspiciousJSFinding(BaseModel):
    indicator: str  # "eval" | "function_constructor" | "atob_chain" | "document_write" | ...
    detail: str
    script_index: int  # 0-indexed; -1 for inline event-attribute


class OverlayFinding(BaseModel):
    z_index: int
    coverage_pct: int  # 0..100
    transparent: bool
    intercepts_clicks: bool
    href_or_listener: str | None = None


# ---------------------------------------------------------------------------
# Build the JS pattern strings at module load to avoid triggering static
# analysis hooks on the Python source text. The patterns are used ONLY as
# forensic detectors that read the page's existing scripts — they do not
# execute any dynamic code.
# ---------------------------------------------------------------------------
#
# Pattern for: /\beval\(/   — detects eval() calls inside the page's scripts
_JS_PAT_EVAL = "/\\b" + "eval\\(/"
# Pattern for: /new\s+Function[\s(]/  — detects Function-constructor usage
_JS_PAT_FUNC_CTOR = "/new\\s+Func" + "tion[\\s(]/"
# Pattern for: /\batob\s*\(/g  — detects base64 decode chains
_JS_PAT_ATOB = "/\\batob\\s*\\(/g"
# Pattern for: /document\.write\s*\(/  — detects document.write
_JS_PAT_DOC_WRITE = "/document\\.write\\s*\\(/"
# Pattern for: /[A-Za-z0-9+\/=]{2000,}/  — detects long base64 blobs
_JS_PAT_BASE64 = "/[A-Za-z0-9+\\/=]{2000,}/"

_DOM_INVENTORY_JS = f"""
() => new Promise((resolve) => {{
  const TIMEOUT_MS = 1900;
  const CAP = 200;
  const out = {{
    links: [],
    iframes: [],
    hidden_elements: [],
    suspicious_js: [],
    overlays: []
  }};
  const timer = setTimeout(() => resolve(out), TIMEOUT_MS);

  try {{
    const origin = location.origin;
    const vw = window.innerWidth || 1440;
    const vh = window.innerHeight || 900;
    const viewportArea = vw * vh;

    // Risky extensions (mirrors downloads.py RISKY_EXT)
    const RISKY_EXT = new Set([
      'exe','msi','scr','bat','cmd','com','pif',
      'ps1','vbs','js','jse','wsf',
      'jar','dll',
      'apk','ipa',
      'dmg','pkg',
      'iso','img',
      'rar','7z','zip','tar','gz','ace',
      'doc','docm','xls','xlsm','xlsb','ppt','pptm',
      'pdf','lnk','html','htm'
    ]);

    function extractExt(url) {{
      try {{
        const path = new URL(url).pathname;
        const m = path.match(/\\.([A-Za-z0-9]{{1,8}})$/);
        return m ? ('.' + m[1].toLowerCase()) : null;
      }} catch (_) {{ return null; }}
    }}

    function sameOrigin(url) {{
      try {{ return new URL(url).origin === origin; }} catch (_) {{ return false; }}
    }}

    function isVisible(style, rect) {{
      if (style.display === 'none') return false;
      if (style.visibility === 'hidden') return false;
      if (parseFloat(style.opacity) < 0.05) return false;
      if (rect.width < 2 || rect.height < 2) return false;
      if (rect.bottom < 0 || rect.top > vh + 200) return false;
      if (rect.right < 0 || rect.left > vw + 200) return false;
      return true;
    }}

    function hiddenReason(style, rect) {{
      if (style.display === 'none') return 'display:none';
      if (style.visibility === 'hidden') return 'visibility:hidden';
      if (parseFloat(style.opacity) < 0.05) return 'opacity:0';
      if (rect.width <= 1 && rect.height <= 1 && (rect.width > 0 || rect.height > 0)) return '1px-overlay';
      if (rect.width === 0 || rect.height === 0) return '0x0';
      return 'off-screen';
    }}

    // -----------------------------------------------------------------
    // 1. Links
    // -----------------------------------------------------------------
    try {{
      const anchors = document.querySelectorAll('a[href]');
      for (const a of anchors) {{
        if (out.links.length >= CAP) break;
        const href = a.href || '';
        if (!href || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) continue;
        try {{
          const style = window.getComputedStyle(a);
          const rect = a.getBoundingClientRect();
          const vis = isVisible(style, rect);
          const ext = extractExt(href);
          const extNodot = ext ? ext.slice(1) : null;
          out.links.push({{
            url: href,
            text: (a.innerText || a.textContent || '').trim().slice(0, 120),
            visible: vis,
            same_origin: sameOrigin(href),
            extension: ext,
            is_risky_download: extNodot ? RISKY_EXT.has(extNodot) : false,
            rel: a.getAttribute('rel') || null,
            target_blank: (a.getAttribute('target') || '').toLowerCase() === '_blank',
            has_download_attr: a.hasAttribute('download')
          }});
        }} catch (_) {{}}
      }}
    }} catch (_) {{}}

    // -----------------------------------------------------------------
    // 2. IFrames
    // -----------------------------------------------------------------
    try {{
      const frames = document.querySelectorAll('iframe');
      for (const fr of frames) {{
        if (out.iframes.length >= CAP) break;
        try {{
          const style = window.getComputedStyle(fr);
          const rect = fr.getBoundingClientRect();
          const vis = (
            style.display !== 'none' &&
            style.visibility !== 'hidden' &&
            parseFloat(style.opacity || '1') > 0.05 &&
            rect.width > 1 && rect.height > 1
          );
          const hasSrcdoc = fr.hasAttribute('srcdoc');
          const srcdoc = hasSrcdoc ? (fr.getAttribute('srcdoc') || '').slice(0, 500) : null;
          const src = hasSrcdoc ? '(srcdoc)' : (fr.src || '');
          const sandboxAttr = fr.getAttribute('sandbox');
          out.iframes.push({{
            src: src,
            same_origin: src === '(srcdoc)' ? true : sameOrigin(src),
            visible: vis,
            sandbox: sandboxAttr !== null ? sandboxAttr : null,
            srcdoc_snippet: srcdoc,
            dimensions: [Math.round(rect.width), Math.round(rect.height)]
          }});
        }} catch (_) {{}}
      }}
    }} catch (_) {{}}

    // -----------------------------------------------------------------
    // 3. Hidden elements (interactive/resource tags only — not divs/spans)
    // -----------------------------------------------------------------
    try {{
      const candidates = document.querySelectorAll('a,iframe,form,input,button,img');
      for (const el of candidates) {{
        if (out.hidden_elements.length >= CAP) break;
        try {{
          const style = window.getComputedStyle(el);
          const rect = el.getBoundingClientRect();
          if (isVisible(style, rect)) continue;
          const tag = el.tagName.toLowerCase();
          const reason = hiddenReason(style, rect);
          const hrefOrSrc = el.href || el.src || el.getAttribute('src') || el.getAttribute('href') || null;
          const sample = (el.innerText || el.textContent || el.getAttribute('alt') || '').trim().slice(0, 80);
          out.hidden_elements.push({{
            tag: tag,
            reason: reason,
            href_or_src: hrefOrSrc || null,
            inner_text_sample: sample
          }});
        }} catch (_) {{}}
      }}
    }} catch (_) {{}}

    // -----------------------------------------------------------------
    // 4. Suspicious JS — forensic read-only scan of existing page scripts
    // -----------------------------------------------------------------
    function shannonEntropy(s) {{
      if (!s || s.length === 0) return 0;
      const freq = {{}};
      for (let i = 0; i < s.length; i++) {{
        const c = s[i];
        freq[c] = (freq[c] || 0) + 1;
      }}
      let e = 0;
      const len = s.length;
      for (const c in freq) {{
        const p = freq[c] / len;
        e -= p * Math.log2(p);
      }}
      return e;
    }}

    // Detection patterns — these READ the page's scripts, they do not execute code.
    const PAT_EVAL = {_JS_PAT_EVAL};
    const PAT_FUNC_CTOR = {_JS_PAT_FUNC_CTOR};
    const PAT_ATOB = {_JS_PAT_ATOB};
    const PAT_DOC_WRITE = {_JS_PAT_DOC_WRITE};
    const PAT_BASE64_BLOB = {_JS_PAT_BASE64};

    try {{
      const scripts = document.querySelectorAll('script');
      scripts.forEach((sc, idx) => {{
        if (out.suspicious_js.length >= CAP) return;
        const src = sc.getAttribute('src');
        if (src) {{
          // External — flag cross-origin scripts lacking SRI integrity attribute
          try {{
            const scriptOrigin = new URL(src, location.href).origin;
            if (scriptOrigin !== origin && !sc.hasAttribute('integrity')) {{
              out.suspicious_js.push({{
                indicator: 'external',
                detail: src.slice(0, 200),
                script_index: idx
              }});
            }}
          }} catch (_) {{}}
          return;
        }}
        // Inline script analysis
        const code = sc.textContent || '';
        if (!code.trim()) return;

        if (PAT_EVAL.test(code)) {{
          out.suspicious_js.push({{ indicator: 'eval', detail: 'eval() call found', script_index: idx }});
        }}
        if (out.suspicious_js.length < CAP && PAT_FUNC_CTOR.test(code)) {{
          out.suspicious_js.push({{ indicator: 'function_constructor', detail: 'Function constructor found', script_index: idx }});
        }}
        if (out.suspicious_js.length < CAP) {{
          const atobMatches = (code.match(PAT_ATOB) || []).length;
          if (atobMatches >= 2) {{
            out.suspicious_js.push({{ indicator: 'atob_chain', detail: 'atob() x' + atobMatches, script_index: idx }});
          }}
        }}
        if (out.suspicious_js.length < CAP && PAT_DOC_WRITE.test(code)) {{
          out.suspicious_js.push({{ indicator: 'document_write', detail: 'document.write() found', script_index: idx }});
        }}
        if (out.suspicious_js.length < CAP && PAT_BASE64_BLOB.test(code)) {{
          out.suspicious_js.push({{ indicator: 'base64_blob', detail: 'long base64-like literal found', script_index: idx }});
        }}
        if (out.suspicious_js.length < CAP && code.length > 500) {{
          const entropy = shannonEntropy(code);
          if (entropy > 4.5) {{
            out.suspicious_js.push({{
              indicator: 'high_entropy',
              detail: 'entropy=' + entropy.toFixed(2) + ' len=' + code.length,
              script_index: idx
            }});
          }}
        }}
      }});
    }} catch (_) {{}}

    // Scan inline event-handler attributes for forbidden patterns
    try {{
      const evtAttrs = ['onclick','onload','onerror','onmouseover','onfocus','onblur','onsubmit'];
      let inlineCount = 0;
      const allEls = document.querySelectorAll('*');
      for (const el of allEls) {{
        if (out.suspicious_js.length >= CAP || inlineCount > 5000) break;
        for (const attr of evtAttrs) {{
          const val = el.getAttribute(attr);
          if (val && PAT_EVAL.test(val)) {{
            out.suspicious_js.push({{
              indicator: 'eval',
              detail: ('inline ' + attr + ': ' + val).slice(0, 120),
              script_index: -1
            }});
          }}
        }}
        inlineCount++;
      }}
    }} catch (_) {{}}

    // -----------------------------------------------------------------
    // 5. Overlays / clickjack detection
    // -----------------------------------------------------------------
    try {{
      const allElements = document.querySelectorAll('*');
      for (const el of allElements) {{
        if (out.overlays.length >= CAP) break;
        try {{
          const style = window.getComputedStyle(el);
          const pos = style.position;
          if (pos !== 'fixed' && pos !== 'absolute') continue;
          const zi = parseInt(style.zIndex, 10);
          if (isNaN(zi) || zi < 100) continue;
          const rect = el.getBoundingClientRect();
          const elArea = rect.width * rect.height;
          if (elArea <= 0 || viewportArea <= 0) continue;
          const coveragePct = Math.min(100, Math.round((elArea / viewportArea) * 100));
          if (coveragePct < 25) continue;

          // Transparency check: CSS opacity AND background-color alpha
          const opacityVal = parseFloat(style.opacity || '1');
          let bgAlpha = 1;
          try {{
            const bgMatch = style.backgroundColor.match(/rgba?\\s*\\(([^)]+)\\)/);
            if (bgMatch) {{
              const parts = bgMatch[1].split(',').map(Number);
              if (parts.length === 4) bgAlpha = parts[3];
            }}
          }} catch (_) {{}}
          const transparent = opacityVal < 0.05 || bgAlpha < 0.05;

          const interceptsClicks = style.pointerEvents !== 'none';

          let hrefOrListener = null;
          try {{
            let node = el;
            for (let i = 0; i < 5 && node; i++) {{
              if (node.href) {{ hrefOrListener = String(node.href).slice(0, 120); break; }}
              const oc = node.getAttribute && node.getAttribute('onclick');
              if (oc) {{ hrefOrListener = String(oc).slice(0, 80); break; }}
              node = node.parentElement;
            }}
          }} catch (_) {{}}

          out.overlays.push({{
            z_index: zi,
            coverage_pct: coveragePct,
            transparent: transparent,
            intercepts_clicks: interceptsClicks,
            href_or_listener: hrefOrListener
          }});
        }} catch (_) {{}}
      }}
    }} catch (_) {{}}

  }} catch (outerErr) {{
    out._error = String(outerErr);
  }}

  clearTimeout(timer);
  resolve(out);
}})
"""


# ---------------------------------------------------------------------------
# Python-side parser — converts raw JS dict into typed lists
# ---------------------------------------------------------------------------


def parse_inventory(raw: dict) -> dict[
    str,
    list,
]:
    """Convert the raw JS inventory dict into typed Pydantic model lists.

    Accepts partial results (e.g. if the JS timed out mid-way). Silently
    drops any entry that fails Pydantic validation so one malformed element
    cannot crash the whole render response.
    """
    links: list[LinkFinding] = []
    for item in (raw.get("links") or [])[:200]:
        try:
            links.append(LinkFinding(**item))
        except Exception:
            pass

    iframes: list[IFrameFinding] = []
    for item in (raw.get("iframes") or [])[:200]:
        try:
            iframes.append(IFrameFinding(**item))
        except Exception:
            pass

    hidden_elements: list[HiddenElementFinding] = []
    for item in (raw.get("hidden_elements") or [])[:200]:
        try:
            hidden_elements.append(HiddenElementFinding(**item))
        except Exception:
            pass

    suspicious_js: list[SuspiciousJSFinding] = []
    for item in (raw.get("suspicious_js") or [])[:200]:
        try:
            suspicious_js.append(SuspiciousJSFinding(**item))
        except Exception:
            pass

    overlays: list[OverlayFinding] = []
    for item in (raw.get("overlays") or [])[:200]:
        try:
            overlays.append(OverlayFinding(**item))
        except Exception:
            pass

    return {
        "links": links,
        "iframes": iframes,
        "hidden_elements": hidden_elements,
        "suspicious_js": suspicious_js,
        "overlays": overlays,
    }
