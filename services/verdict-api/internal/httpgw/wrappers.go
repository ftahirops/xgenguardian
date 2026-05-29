// wrappers.go — email-gateway URL unwrappers.
//
// Enterprise mail gateways rewrite every link in inbound email so a click
// goes through the gateway's safety-check service first. The browser
// shows a wrapper URL like:
//
//   https://ind01.safelinks.protection.outlook.com/?url=https%3A%2F%2Flogin.microsoftonline.com%2F...&data=...
//
// XGenGuardian needs to verdict the *real* target, not the wrapper. Two
// reasons it matters end-to-end:
//
//   1. Verdict accuracy — a wrapper URL alone tells us nothing about
//      the actual landing page. The trustreg + brandgraph + sandbox
//      analysis must run against the unwrapped URL.
//   2. Phishing-through-wrapper — attackers abuse the trusted
//      Microsoft/Proofpoint/Mimecast wrapper hostname to bypass user
//      suspicion. The wrapped target is often a phishing kit. Unwrap
//      surfaces the actual host so brand-impersonation / fresh-domain /
//      feed-hit / sink rules can act on it.
//
// What's NOT handled here:
//   - Shorteners (bit.ly, t.co, ow.ly) → see shorteners.go. Those are
//     resolved by following the 301/302, not by parsing the URL.
//   - In-page redirect chains → handled by the sandbox-render `final_url`.
//
// What IS handled (DT-2 Wave 1):
//   - Microsoft SafeLinks (Office 365 / Defender for Office)
//   - Proofpoint URL Defense (TAP)
//   - Mimecast click-tracking
//   - Cisco Secure Email (formerly IronPort)
//   - Barracuda Email Gateway
//   - Symantec / Broadcom Click-Time URL Protection
//   - Google Mail link-redirect wrapper
package httpgw

import (
	"net/url"
	"strings"
)

// UnwrapResult describes the result of trying to unwrap a URL.
//
// When Found is false, Wrapper and URL are zero and callers continue with
// the original URL unchanged. When Found is true, URL is the canonical
// landing-page URL (still subject to the rest of the pipeline) and
// Wrapper is a short stable identifier suitable for telemetry, the
// decision trace, and the response's wrapper_chain field.
type UnwrapResult struct {
	Found   bool
	URL     string // unwrapped target; empty when Found=false
	Wrapper string // "safelinks" | "proofpoint" | "mimecast" | "cisco" | "barracuda" | "symantec" | "gmail"
}

// unwrapEmailGateway tries each known wrapper detector in order. The
// first match wins. Detectors are pure functions over the parsed URL —
// no network, no redirects, no allocation churn.
func unwrapEmailGateway(rawURL string) UnwrapResult {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil || u.Host == "" {
		return UnwrapResult{}
	}
	// Strip a trailing dot from FQDN form (`mimecast.com.` is valid DNS
	// and resolves identically to `mimecast.com`, so it must hit the
	// same allowlist check).
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")

	if t := unwrapSafeLinks(u, host); t != "" {
		return UnwrapResult{Found: true, URL: t, Wrapper: "safelinks"}
	}
	if t := unwrapProofpoint(u, host); t != "" {
		return UnwrapResult{Found: true, URL: t, Wrapper: "proofpoint"}
	}
	if t := unwrapMimecast(u, host); t != "" {
		return UnwrapResult{Found: true, URL: t, Wrapper: "mimecast"}
	}
	if t := unwrapCisco(u, host); t != "" {
		return UnwrapResult{Found: true, URL: t, Wrapper: "cisco"}
	}
	if t := unwrapBarracuda(u, host); t != "" {
		return UnwrapResult{Found: true, URL: t, Wrapper: "barracuda"}
	}
	if t := unwrapSymantec(u, host); t != "" {
		return UnwrapResult{Found: true, URL: t, Wrapper: "symantec"}
	}
	if t := unwrapGmail(u, host); t != "" {
		return UnwrapResult{Found: true, URL: t, Wrapper: "gmail"}
	}
	return UnwrapResult{}
}

// --- Microsoft SafeLinks ----------------------------------------------------
//
// Pattern: https://<region>.safelinks.protection.outlook.com/?url=<wrapped>&data=...
//
// SafeLinks rewrites every link in Office 365 / Defender-for-Office mail.
// Region prefix is `ind01`, `eur01`, `nam01`, etc. — match on the
// `.safelinks.protection.outlook.com` suffix to cover all of them.
func unwrapSafeLinks(u *url.URL, host string) string {
	if !strings.HasSuffix(host, ".safelinks.protection.outlook.com") &&
		host != "safelinks.protection.outlook.com" {
		return ""
	}
	return pickQueryParam(u, "url")
}

// --- Proofpoint URL Defense (TAP) -------------------------------------------
//
// Three live formats in the wild:
//
//   v1: https://urldefense.proofpoint.com/v1/url?u=<wrapped>&k=...
//   v2: https://urldefense.proofpoint.com/v2/url?u=<wrapped>&d=...&c=...
//   v3: https://urldefense.com/v3/__<wrapped>__;<token>!!...$
//
// v1/v2 use a `u=` query param. v3 wraps the URL inside the path
// between `__` markers — that needs a path parser, not a query param.
func unwrapProofpoint(u *url.URL, host string) string {
	pp := host == "urldefense.proofpoint.com" || host == "urldefense.com"
	if !pp {
		return ""
	}
	// v3 path format: /v3/__<wrapped>__;<base64>!!
	if strings.HasPrefix(u.Path, "/v3/__") {
		rest := u.Path[len("/v3/__"):]
		end := strings.Index(rest, "__;")
		if end > 0 {
			candidate := rest[:end]
			if isHTTPishURL(candidate) {
				return candidate
			}
		}
	}
	// v1/v2 query format
	if u := pickQueryParam(u, "u"); u != "" {
		// Proofpoint v1/v2 sometimes substitute "_" for "/" and "-" for "_"
		// in the wrapped URL. Apply the inverse before returning.
		decoded := strings.NewReplacer("-", "%", "_", "/").Replace(u)
		if dec, err := url.QueryUnescape(decoded); err == nil && isHTTPishURL(dec) {
			return dec
		}
		if isHTTPishURL(u) {
			return u
		}
	}
	return ""
}

// --- Mimecast ---------------------------------------------------------------
//
// Pattern: https://protect-<region>.mimecast.com/s/<hash>?domain=<target>
//
// The `domain` query param contains the bare host, not the full URL —
// path/query are dropped by the wrapper. We reconstruct https://<host>
// as the best-effort unwrap and surface it; the rest of the pipeline
// then runs against that landing host. (Mimecast also has a `url=`
// variant on its newer click-rewrite service; check both.)
func unwrapMimecast(u *url.URL, host string) string {
	// Anchored host match. Contains(".mimecast.com") would match
	// attacker-controlled hosts like `mimecast.com.attacker.com` or
	// `evil.com/.mimecast.com.spoof.com` — letting an attacker bless
	// their own host as a Mimecast hop and smuggle a benign-looking
	// `domain=` target through the unwrap. Use HasSuffix + exact-match
	// in line with every other wrapper detector in this file.
	if !strings.HasSuffix(host, ".mimecast.com") && host != "mimecast.com" {
		return ""
	}
	if v := pickQueryParam(u, "url"); v != "" {
		return v
	}
	if d := u.Query().Get("domain"); d != "" {
		d = strings.TrimSpace(d)
		// "example.com" → "https://example.com"
		if !strings.HasPrefix(d, "http://") && !strings.HasPrefix(d, "https://") {
			d = "https://" + d
		}
		if isHTTPishURL(d) {
			return d
		}
	}
	return ""
}

// --- Cisco Secure Email (IronPort) ------------------------------------------
//
// Pattern: https://secure-web.cisco.com/<token>/<base64-or-url>
//
// Two formats:
//   1. Token in path, target URL as path-after-token (URL-encoded)
//   2. ?url= query param on newer deployments
//
// Conservative implementation: prefer the query param when present;
// otherwise parse the last path segment as a URL if it looks like one.
func unwrapCisco(u *url.URL, host string) string {
	if host != "secure-web.cisco.com" {
		return ""
	}
	if v := pickQueryParam(u, "url"); v != "" {
		return v
	}
	// Look for an embedded https?:// in the path.
	if idx := strings.Index(u.Path, "/https://"); idx >= 0 {
		return u.Path[idx+1:]
	}
	if idx := strings.Index(u.Path, "/http://"); idx >= 0 {
		return u.Path[idx+1:]
	}
	return ""
}

// --- Barracuda --------------------------------------------------------------
//
// Pattern: https://linkprotect.cudasvc.com/url?a=<target>&...
//   or:   https://barracudacentral.org/...?url=<target>
func unwrapBarracuda(u *url.URL, host string) string {
	if host != "linkprotect.cudasvc.com" && !strings.HasSuffix(host, ".cudasvc.com") {
		return ""
	}
	if v := pickQueryParam(u, "a"); v != "" {
		return v
	}
	return pickQueryParam(u, "url")
}

// --- Symantec / Broadcom Click-Time URL Protection --------------------------
//
// Pattern: https://clicktime.symantec.com/<token>?u=<target>
//   or:   https://click.symantec.com/...?url=<target>
//   or:   https://clicktime.cloud.proofpoint.com/... (some tenants ride
//          Proofpoint infra after the Broadcom acquisition)
func unwrapSymantec(u *url.URL, host string) string {
	if !strings.HasSuffix(host, ".symantec.com") && host != "clicktime.symantec.com" {
		return ""
	}
	if v := pickQueryParam(u, "u"); v != "" {
		return v
	}
	return pickQueryParam(u, "url")
}

// --- Gmail link-redirect ----------------------------------------------------
//
// Pattern: https://www.google.com/url?q=<target>&...
//   or:   https://mail.google.com/mail/u/0/...
//
// Gmail wraps outbound clicks on links inside threads with /url?q=...
// The body of the email is what the user sees, but Chrome navigates the
// wrapper first. Only the /url path on www.google.com counts as a
// link-wrapper; the rest of google.com is legitimate.
func unwrapGmail(u *url.URL, host string) string {
	if host != "www.google.com" || u.Path != "/url" {
		return ""
	}
	return pickQueryParam(u, "q")
}

// pickQueryParam returns the value of `name` only when it parses as an
// http(s) URL. Any other value is rejected (an attacker can't smuggle
// `javascript:` or `data:` through here).
func pickQueryParam(u *url.URL, name string) string {
	v := u.Query().Get(name)
	if v == "" {
		return ""
	}
	if isHTTPishURL(v) {
		return v
	}
	if dec, err := url.QueryUnescape(v); err == nil && isHTTPishURL(dec) {
		return dec
	}
	return ""
}

// isHTTPishURL is a strict http(s):// check. Crucially excludes
// javascript:, data:, file:, vbscript:, chrome-extension:, etc.
func isHTTPishURL(s string) bool {
	if len(s) < 8 {
		return false
	}
	low := strings.ToLower(s)
	return strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")
}
