// cmdcheck.go — POST /v1/command-check
//
// Fast endpoint for browser-extension copy-button mediation. The extension
// hooks every copy event from a <pre>/<code> block and asks us "is this
// safe to paste in a terminal?" before the clipboard fills.
//
// Latency budget: <100ms p99. No sandbox, no DB writes, no remote calls.
// Pure in-memory: shellcmd patterns + installreg lookup + trustreg check.
// Heavier per-URL analysis stays on /v1/check.
//
// Threat model:
//   - User browses to a docs-style page (real or fake).
//   - User clicks the "Copy" button next to an install command.
//   - Browser fires a copy event → content script captures the selection
//     text + page URL + page title.
//   - Extension POSTs here BEFORE the clipboard fills.
//   - We return ALLOW / WARN / REQUIRE_APPROVAL / BLOCK + reason.
//   - Extension shows a confirm dialog on non-ALLOW or blocks the copy
//     outright on BLOCK.
//
// Per the rule families we agreed on:
//   - official_match (host + command + target URLs all align with a
//     registered vendor template)               -> ALLOW
//   - dangerous_command_structure (hard-fail
//     shellcmd pattern: rundll32 over UNC, mshta
//     remote HTA, certutil urlcache)            -> BLOCK
//   - 2+ soft signals on untrusted host         -> REQUIRE_APPROVAL
//   - 2+ soft signals on trusted host           -> WARN
//   - 0-1 soft signals                          -> ALLOW
//
// Visible-vs-clipboard mismatch detection happens client-side in the
// extension (it sees both the selection text and what document.execCommand
// would have written); not handled by this endpoint.
package httpgw

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/xgenguardian/services/verdict-api/internal/installreg"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
	"github.com/xgenguardian/services/verdict-api/internal/trustreg"
)

// Local mirror of sandbox-render/app/shellcmd.py patterns. Kept here so
// /v1/command-check doesn't have to fetch sandbox for trivial analysis.
// CRITICAL: keep in sync with shellcmd.py's HARD_FAIL_PATTERNS / SOFT_SIGNAL_PATTERNS.
var (
	hardFailPatterns = []struct {
		Code string
		Re   *regexp.Regexp
	}{
		{"RUNDLL32_UNC_PATH", regexp.MustCompile(`(?i)\brundll32(?:\.exe)?\s+\\\\[^\s"';|&]+`)},
		{"MSHTA_REMOTE_HTA", regexp.MustCompile(`(?i)\bmshta(?:\.exe)?\s+https?://`)},
		{"POWERSHELL_IEX_REMOTE", regexp.MustCompile(`(?i)\b(?:IEX|Invoke-Expression|iwr|irm)\b[^\n]{0,200}\bhttps?://`)},
		{"CERTUTIL_URLCACHE", regexp.MustCompile(`(?i)\bcertutil\b.*-(?:urlcache|decode)`)},
		{"WMIC_REMOTE_PROCESS", regexp.MustCompile(`(?i)\bwmic\s+/node:`)},
	}
	softSignalPatterns = []struct {
		Code string
		Re   *regexp.Regexp
	}{
		{"SHELL_AMPERSAND_TRICK", regexp.MustCompile(`(?i)\b(?:curl|wget|irm|iwr)\s[^\n;]*\s&\s+(?:bash|sh|zsh|powershell|rundll32|mshta)`)},
		{"BASE64_PIPED_TO_SHELL", regexp.MustCompile(`(?i)\bbase64\b[^\n|]*\s*\|\s*(?:bash|sh|zsh)`)},
		{"ECHO_BASE64_PIPED", regexp.MustCompile(`(?i)\becho\s+['"][A-Za-z0-9+/=]{40,}['"][^|]*\|\s*(?:base64|bash|sh|zsh)`)},
		{"CURL_PIPE_SHELL", regexp.MustCompile(`(?i)\b(?:curl|wget)\s[^\n|;]*\|\s*(?:bash|sh|zsh)`)},
		{"RAW_GITHUB_INSTALLER", regexp.MustCompile(`(?i)raw\.githubusercontent\.com/[^/\s"']+/[^/\s"']*(?:install|setup|loader|bootstrap)`)},
		{"UNC_PATH_IN_COMMAND", regexp.MustCompile(`(?i)\\\\[a-z0-9_.-]+\.(?:com|net|org|io|app|cloud|me|to|in|digital|cfd|click)\\`)},
		{"POWERSHELL_ENCODED_COMMAND", regexp.MustCompile(`(?i)\bpowershell(?:\.exe)?\s+(?:-\w+\s+)*-(?:e|enc|encodedcommand)\b`)},
		{"POWERSHELL_BYPASS_POLICY", regexp.MustCompile(`(?i)-ExecutionPolicy\s+Bypass`)},
	}
)

type commandCheckRequest struct {
	// PageURL — the full URL of the page where the copy happened.
	PageURL string `json:"page_url"`
	// Command — the text the user just selected / a copy button placed
	// on the clipboard. Already-decoded, post-JS-render text. May span
	// multiple lines (we collapse whitespace before matching).
	Command string `json:"command"`
	// PageTitle — for context only, surfaced in the response. Optional.
	PageTitle string `json:"page_title,omitempty"`
}

type commandCheckResponse struct {
	// Verdict — one of ALLOW / WARN / REQUIRE_APPROVAL / BLOCK.
	// The extension UI maps these to no-op / yellow toast / confirm modal / hard block.
	Verdict string `json:"verdict"`
	// Confidence — 0..1 self-assessment. Surfaced for analytics; not used by extension UI.
	Confidence float64 `json:"confidence"`
	// ReasonCodes — stable strings analogous to /v1/check.reason_codes.
	ReasonCodes []string `json:"reason_codes"`
	// Explanation — one-sentence human-readable rationale shown in modal.
	Explanation string `json:"explanation"`
	// OfficialBrand — when verdict is ALLOW via official_match, the brand
	// name. Lets the extension surface "✓ Verified official Anthropic install".
	OfficialBrand string `json:"official_brand,omitempty"`
	// LatencyMs — server-side processing time. Helpful for SLO tracking.
	LatencyMs int `json:"latency_ms"`
}

func (s *Server) commandCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	t0 := time.Now()
	var req commandCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Command == "" {
		// Empty selection → nothing to analyze. Allow the underlying copy
		// (UI shouldn't have triggered a check at all, but be permissive).
		writeJSON(w, commandCheckResponse{
			Verdict: "ALLOW", Confidence: 0.5,
			LatencyMs: int(time.Since(t0).Milliseconds()),
		})
		return
	}

	host := hostOfURL(req.PageURL)
	cmd := collapseWhitespace(req.Command)

	// Step 1: Official match — strongest positive trust.
	if m := installreg.MatchCommand(host, cmd); m != nil {
		writeJSON(w, commandCheckResponse{
			Verdict:       "ALLOW",
			Confidence:    0.95,
			ReasonCodes:   []string{string(reasons.OfficialInstallMatch)},
			Explanation:   "Verified official " + m.Brand + " install command.",
			OfficialBrand: m.Brand,
			LatencyMs:     int(time.Since(t0).Milliseconds()),
		})
		return
	}

	// Step 2: Hard-fail patterns — instant BLOCK regardless of host.
	var hardCodes []string
	for _, p := range hardFailPatterns {
		if p.Re.MatchString(cmd) {
			hardCodes = append(hardCodes, p.Code)
		}
	}
	if len(hardCodes) > 0 {
		codes := append([]string{string(reasons.MaliciousInstallCommand)}, hardCodes...)
		writeJSON(w, commandCheckResponse{
			Verdict:     "BLOCK",
			Confidence:  0.95,
			ReasonCodes: codes,
			Explanation: "This command contains a known-malicious pattern. Do NOT paste it into your terminal.",
			LatencyMs:   int(time.Since(t0).Milliseconds()),
		})
		return
	}

	// Step 3: Soft signals.
	var softCodes []string
	for _, p := range softSignalPatterns {
		if p.Re.MatchString(cmd) {
			softCodes = append(softCodes, p.Code)
		}
	}

	// Page-host trust influences the soft-signal threshold:
	//   - Trusted host: 2+ soft signals -> WARN (vendor publishing slightly
	//     unusual install is suspicious but not blocking).
	//   - Untrusted host: 2+ soft signals -> REQUIRE_APPROVAL.
	//   - Untrusted host + 1 soft signal -> WARN.
	//   - Trusted host + 0-1 signals     -> ALLOW.
	//   - Untrusted host + 0 signals     -> ALLOW (no IOCs found at all).
	trusted := trustreg.IsTrusted(host)
	switch {
	case len(softCodes) >= 2 && !trusted:
		codes := append([]string{string(reasons.SuspiciousInstallCommand)}, softCodes...)
		writeJSON(w, commandCheckResponse{
			Verdict: "REQUIRE_APPROVAL", Confidence: 0.8, ReasonCodes: codes,
			Explanation: "This command on an unverified site has multiple traits common in malware-staging chains. Confirm intent before pasting.",
			LatencyMs:   int(time.Since(t0).Milliseconds()),
		})
		return
	case len(softCodes) >= 2 && trusted:
		codes := append([]string{string(reasons.SuspiciousInstallCommand)}, softCodes...)
		writeJSON(w, commandCheckResponse{
			Verdict: "WARN", Confidence: 0.7, ReasonCodes: codes,
			Explanation: "Vendor publishing an install command with multiple unusual patterns. Inspect before pasting.",
			LatencyMs:   int(time.Since(t0).Milliseconds()),
		})
		return
	case len(softCodes) == 1 && !trusted:
		codes := append([]string{string(reasons.SuspiciousInstallCommand)}, softCodes...)
		writeJSON(w, commandCheckResponse{
			Verdict: "WARN", Confidence: 0.6, ReasonCodes: codes,
			Explanation: "Command on an unverified site uses a pattern common in install scripts but also abused by malware.",
			LatencyMs:   int(time.Since(t0).Milliseconds()),
		})
		return
	}

	writeJSON(w, commandCheckResponse{
		Verdict: "ALLOW", Confidence: 0.6,
		LatencyMs: int(time.Since(t0).Milliseconds()),
	})
}

// hostOfURL — defensive host extraction for the page_url field.
// Returns lowercase host, "" if the URL is malformed.
func hostOfURL(rawurl string) string {
	if rawurl == "" {
		return ""
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// collapseWhitespace — duplicated from installreg.collapseWhitespace
// because that package's helper is unexported. Small enough to inline.
func collapseWhitespace(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
