// Package pageclass — Stage A of the staged policy engine.
//
// Classifies a URL (and, when available, render artefacts) into one of the
// explicit page classes from dev spec §9. Page class drives:
//   - sensitive-class TTL caps (login/payment/oauth = 7 d max)
//   - sink-allowlist lookup (each class has its own expected destinations)
//   - risk-threshold tuning (login pages are stricter than generic pages)
//
// Two-stage classification:
//   1. URL-only heuristic (cheap, runs always in Tier-1)
//   2. DOM-aware refinement after sandbox render (looks at password/email/
//      OTP/payment fields, OAuth markers, download triggers)
package pageclass

import "strings"

// Class is the wire-format page class. Stable strings — never rename.
type Class string

const (
	Login            Class = "login"
	PasswordStep     Class = "password-step"
	MFA              Class = "mfa"
	OAuthConsent     Class = "oauth-consent"
	Payment          Class = "payment"
	Download         Class = "download"
	Invoice          Class = "invoice"
	CryptoWithdrawal Class = "crypto-withdrawal"
	SupportScareware Class = "support-scareware"
	// DeveloperToolInstallLure — docs / install / getting-started pages
	// that publish shell commands intended for the user to copy-paste into
	// a terminal. This is the Straiker "Fake Claude Code" attack class:
	// the page itself is the weapon (text in a <pre> block).
	// Treated as sensitive so fail-closed-on-unverified applies and
	// shouldRunTier2 always sends these to sandbox for shellcmd scanning.
	DeveloperToolInstallLure Class = "developer-tool-install-lure"
	Generic          Class = "generic"
)

// devToolBrandKeywords — substrings that, when present in the URL host or
// path, raise suspicion that a page is impersonating a dev-tool install
// page. Match against the lower-cased URL. Kept in this file so pageclass
// and pipeline share the same canonical list.
var devToolBrandKeywords = []string{
	"claude", "anthropic",
	"openai", "chatgpt", "codex", "copilot",
	"cursor", "cline", "continue", "windsurf",
	"jetbrains", "pycharm", "intellij", "webstorm", "goland", "phpstorm",
	"notebooklm", "perplexity", "comet",
	"snowflake", "databricks",
	"mcp-server",
}

// IsSensitive reports whether the page class requires special handling
// (tight TTL caps, fail-closed when verification unavailable, etc.).
func (c Class) IsSensitive() bool {
	switch c {
	case Login, PasswordStep, MFA, OAuthConsent, Payment, CryptoWithdrawal,
		Invoice, Download, DeveloperToolInstallLure:
		return true
	}
	return false
}

// IsDevToolInstallLure — convenience predicate, exported so the pipeline
// can decide whether to force Tier-2 without re-walking class enums.
func (c Class) IsDevToolInstallLure() bool {
	return c == DeveloperToolInstallLure
}

// LooksLikeDevToolInstallLure — URL-only check used by shouldRunTier2 to
// force a sandbox render even when the URL-class heuristic settled on
// something more specific (e.g. /download). True when the URL contains
// both an install/docs path hint AND a known dev-tool brand keyword.
func LooksLikeDevToolInstallLure(rawurl string) bool {
	l := strings.ToLower(rawurl)
	hasPathHint := false
	for _, h := range []string{
		"/docs", "/install", "/download", "/getting-started",
		"/getting_started", "/quickstart", "/quick-start", "/setup",
		"/guide", "/tutorial", "/cli",
	} {
		if strings.Contains(l, h) {
			hasPathHint = true
			break
		}
	}
	if !hasPathHint {
		return false
	}
	for _, b := range devToolBrandKeywords {
		if strings.Contains(l, b) {
			return true
		}
	}
	return false
}

// FromURL — Stage A.1: cheap URL-only classification. Used in Tier-1 to
// decide whether to force Tier-2 for sensitive pages.
//
// Order matters: more specific patterns first so e.g. "oauth/consent" beats
// the generic "/login" match.
func FromURL(rawurl string) Class {
	l := strings.ToLower(rawurl)
	switch {
	case strings.Contains(l, "/oauth"), strings.Contains(l, "/authorize"),
		strings.Contains(l, "/consent"), strings.Contains(l, "/adminconsent"):
		return OAuthConsent
	case strings.Contains(l, "/mfa"), strings.Contains(l, "/2fa"),
		strings.Contains(l, "/otp"), strings.Contains(l, "/totp"),
		strings.Contains(l, "/passkey"), strings.Contains(l, "/webauthn"):
		return MFA
	case strings.Contains(l, "/password"), strings.Contains(l, "/pwd"):
		return PasswordStep
	case strings.Contains(l, "/login"), strings.Contains(l, "/signin"),
		strings.Contains(l, "/sign-in"), strings.Contains(l, "/log-in"),
		strings.Contains(l, "/verify"), strings.Contains(l, "/recover"),
		strings.Contains(l, "/reset"):
		return Login
	case strings.Contains(l, "/payment"), strings.Contains(l, "/pay"),
		strings.Contains(l, "/checkout"), strings.Contains(l, "/billing"),
		strings.Contains(l, "/wallet"):
		return Payment
	case strings.Contains(l, "/withdraw"), strings.Contains(l, "/crypto"):
		return CryptoWithdrawal
	case strings.Contains(l, "/invoice"):
		return Invoice
	}
	// Dev-tool install lure check goes BEFORE the bare /download fallback
	// so we don't lose the dev-tool signal on URLs like
	// "/download/claude-cli". Once classified as DevToolInstallLure,
	// shouldRunTier2 forces sandbox+shellcmd analysis.
	if LooksLikeDevToolInstallLure(rawurl) {
		return DeveloperToolInstallLure
	}
	if strings.Contains(l, "/download") {
		return Download
	}
	return Generic
}

// DOMHints carries the post-render signals used by Refine().
type DOMHints struct {
	HasPasswordField   bool
	HasEmailField      bool
	HasOTPField        bool   // input[name~="otp"|"code"|"token"] + numeric
	HasPaymentField    bool   // card-number / cvv / expiry
	HasPasskeyAPI      bool   // navigator.credentials.create called
	HasOAuthClientID   bool   // URL had a client_id parameter
	ForcedFullscreen   bool
	PopupStorm         bool
	AlertLoop          bool
	HasDownloadTrigger bool
	// HasInstallShellCommand — sandbox saw a <pre>/<code> block whose text
	// matches a shell-install pattern (curl/wget/irm/brew/npm/pip/cargo
	// followed by install/run/get + a URL or package name). Used to promote
	// a URL-class-Generic page to DeveloperToolInstallLure when the page
	// content reveals it.
	HasInstallShellCommand bool
}

// Refine — Stage A.2: post-render refinement. Promotes Generic → specific
// when the DOM shows clear signals; demotes false positives where URL hints
// don't match the actual page (e.g. an /oauth tutorial page with no OAuth
// form is downgraded to Generic).
func Refine(urlClass Class, h DOMHints) Class {
	// Strongest DOM signals win, even when the URL didn't hint at it.
	switch {
	case h.HasOAuthClientID:
		return OAuthConsent
	case h.HasPaymentField:
		return Payment
	case h.HasPasswordField && h.HasOTPField:
		// MFA step (some flows show password + OTP together).
		return MFA
	case h.HasOTPField || h.HasPasskeyAPI:
		return MFA
	case h.HasPasswordField:
		if urlClass == PasswordStep {
			return PasswordStep
		}
		return Login
	case h.PopupStorm && h.AlertLoop && h.ForcedFullscreen:
		// Three scareware abuse classes at once → fake support scam.
		return SupportScareware
	case h.HasDownloadTrigger:
		return Download
	}

	// Promote to DeveloperToolInstallLure when the URL hinted at it OR
	// the rendered DOM contains a shell-install command. The page-content
	// signal catches phishing pages that don't have install/docs in the
	// URL path (e.g. ravishingtattle.com/docs/en/overview disguises the
	// purpose in the path but the body is full of install commands).
	if urlClass == DeveloperToolInstallLure || h.HasInstallShellCommand {
		return DeveloperToolInstallLure
	}

	// URL hint stands when DOM is ambiguous.
	return urlClass
}
