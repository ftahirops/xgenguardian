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

import (
	"net/url"
	"strings"
)

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
	// AI coding agents / IDEs
	"claude", "anthropic",
	"openai", "chatgpt", "codex", "copilot",
	"cursor", "cline", "continue", "windsurf",
	"jetbrains", "pycharm", "intellij", "webstorm", "goland", "phpstorm",
	"notebooklm", "perplexity", "comet",
	"snowflake", "databricks",
	"mcp-server",
	// Wave 2.5 — language runtimes + package managers (broader install-lure
	// surface; nodejs-install-* was slipping through pre-expansion).
	"nodejs", "node-js", "npm", "yarn", "pnpm",
	"python", "pip", "poetry", "uv-pip",
	"rust", "rustup", "cargo",
	"golang", "go-lang",
	"ruby", "rubygems", "rails",
	"php", "composer",
	"java", "maven", "gradle", "openjdk",
	// Container + infra tooling
	"docker", "podman", "kubernetes", "kubectl", "helm", "minikube",
	"terraform", "ansible", "vagrant", "consul", "vault", "nomad",
	// Editors + developer apps
	"vscode", "visual-studio", "neovim", "emacs", "sublime", "atom-editor",
	// Dev infra
	"github-cli", "gitlab-runner", "hashicorp",
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

// IsCredentialPage reports whether the page class collects credentials
// or payment information from the user — login/password/MFA/OAuth/payment/
// crypto/invoice. Use this (not IsSensitive) for rules that act on
// credential-sink data, because Download and DeveloperToolInstallLure
// pages don't collect credentials (they OFFER files / show commands)
// and the credential-sink heuristics produce false positives there.
//
// Example: signal.org/download has download links to updates.signal.org
// (cross-origin). IsSensitive=true → credential-sink rule fires →
// CREDENTIAL_SINK_CROSS_ORIGIN false-positive. IsCredentialPage=false →
// rule correctly skipped.
func (c Class) IsCredentialPage() bool {
	switch c {
	case Login, PasswordStep, MFA, OAuthConsent, Payment, CryptoWithdrawal,
		Invoice:
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
		"/guide", "/tutorial", "/cli", "/installer",
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
	// Wave 2.5 — structural fallback. An SLD that LITERALLY contains
	// "install", "installer", or "setup" combined with a /docs|/install|
	// /download|/installer|/setup path is the canonical install-lure
	// shape regardless of which brand the attacker is impersonating.
	// Examples in the wild:
	//   nodejs-install-quick.example/installer
	//   secure-install-page.example/setup
	//   one-click-installer.example/download
	// Without this branch the brand list has to enumerate every runtime
	// and language ecosystem on Earth; the structural check covers the
	// rest. SLD-only match (not full URL) to avoid path/scheme drift.
	if sld := extractSLD(rawurl); sld != "" {
		if strings.Contains(sld, "install") || strings.Contains(sld, "setup-") || strings.HasPrefix(sld, "setup-") || strings.HasSuffix(sld, "-setup") {
			return true
		}
	}
	return false
}

// FromURL — Stage A.1: cheap URL-only classification. Used in Tier-1 to
// decide whether to force Tier-2 for sensitive pages.
//
// Path-keyword checks operate on the URL's PATH ONLY, not the full URL
// string. Pre-Wave-2.5 the path switch used strings.Contains on the
// lowercased full URL, which produced two real false-positive classes:
//
//   1. Host-substring drift: https://paypal-account-security.example/
//      matched "/pay" because the host substring "/paypal-..." (with
//      the slash from "//paypal-...") contains "/pay" as a substring.
//      Smoke corpus caught this; it misclassified one phishing host
//      as Payment instead of letting the SLD-keyword branch fire.
//
//   2. //host-prefix drift: https://login.example/ matched "/login"
//      because the URL substring "//login.example/" contains "/login".
//      Any SLD that happens to be one of these keywords got promoted.
//
// Both vanish once we parse the URL and check u.Path only. Ordering is
// preserved (oauth > mfa > password > login > payment > crypto >
// invoice) so e.g. "/oauth/consent" still beats "/login" alone.
func FromURL(rawurl string) Class {
	u, err := url.Parse(rawurl)
	// pathOnly is what the keyword switch reads. On parse failure we
	// fall back to scanning the full URL, which preserves prior
	// behaviour on garbage input (better something than nothing).
	pathOnly := ""
	if err == nil && u != nil {
		pathOnly = strings.ToLower(u.Path)
	}
	if pathOnly == "" {
		pathOnly = strings.ToLower(rawurl)
	}
	// containsPath helper — strings.Contains over pathOnly. Kept inline
	// to keep the change diff focused.
	cp := func(needle string) bool { return strings.Contains(pathOnly, needle) }
	switch {
	case cp("/oauth"), cp("/authorize"), cp("/consent"), cp("/adminconsent"):
		return OAuthConsent
	case cp("/mfa"), cp("/2fa"), cp("/otp"), cp("/totp"),
		cp("/passkey"), cp("/webauthn"):
		return MFA
	case cp("/password"), cp("/pwd"):
		return PasswordStep
	case cp("/login"), cp("/signin"), cp("/sign-in"), cp("/log-in"),
		cp("/verify"), cp("/recover"), cp("/reset"):
		return Login
	case cp("/payment"), cp("/pay"), cp("/checkout"),
		cp("/billing"), cp("/wallet"):
		return Payment
	case cp("/withdraw"), cp("/crypto"):
		return CryptoWithdrawal
	case cp("/invoice"):
		return Invoice
	}
	// Dev-tool install lure check goes BEFORE the bare /download fallback
	// so we don't lose the dev-tool signal on URLs like
	// "/download/claude-cli". Once classified as DevToolInstallLure,
	// shouldRunTier2 forces sandbox+shellcmd analysis.
	if LooksLikeDevToolInstallLure(rawurl) {
		return DeveloperToolInstallLure
	}
	if strings.Contains(pathOnly, "/download") {
		return Download
	}
	// Wave 2.5 — SLD-keyword fallback. URLs like
	//   https://bank-login-secure-2026.example/
	//   https://paypal-account-security.example/
	//   https://wellsfargo-online-update.example/
	// have the sensitive intent baked into the HOST not the PATH.
	// Without this branch the path-based switch above gives them
	// Generic, the verdict falls back to the soft-rule accumulator,
	// and a fresh-domain phishing host without "login" in the path
	// slips through. The branch reads only the SLD (registrable
	// domain's leftmost label) so false-positives on legitimate
	// sites that happen to mention "login" in their path don't fire.
	if sld := extractSLD(rawurl); sld != "" {
		switch {
		case strings.Contains(sld, "login"),
			strings.Contains(sld, "signin"),
			strings.Contains(sld, "sign-in"),
			strings.Contains(sld, "secure"),
			strings.Contains(sld, "verify"),
			strings.Contains(sld, "account"),
			strings.Contains(sld, "auth"),
			strings.Contains(sld, "bank-"),
			strings.Contains(sld, "-bank"),
			strings.Contains(sld, "logon"),
			strings.Contains(sld, "-update"),
			strings.Contains(sld, "update-"),
			// well-known bank brand names embedded in attacker SLDs
			// (wellsfargo-online-update.example, chase-account-verify.example).
			// Conservative: only kick in when paired with attacker-pattern
			// tokens via the other branches above; standalone "chase" in
			// chase.com etc. is the legit brand and won't reach this branch
			// because it would match brandgraph/trustreg.
			strings.HasPrefix(sld, "wellsfargo-"),
			strings.HasPrefix(sld, "chase-"),
			strings.HasPrefix(sld, "citibank-"),
			strings.HasPrefix(sld, "bankofamerica-"),
			strings.HasPrefix(sld, "hsbc-"),
			strings.HasPrefix(sld, "barclays-"),
			strings.HasPrefix(sld, "santander-"):
			return Login
		case strings.Contains(sld, "checkout"),
			strings.Contains(sld, "payment"),
			strings.Contains(sld, "billing"),
			strings.Contains(sld, "-pay-"),
			strings.HasSuffix(sld, "-pay"),
			strings.HasPrefix(sld, "pay-"):
			return Payment
		case strings.Contains(sld, "wallet"),
			strings.Contains(sld, "metamask"),
			strings.Contains(sld, "claim-airdrop"),
			strings.Contains(sld, "revoke-permissions"):
			return CryptoWithdrawal
		}
	}
	return Generic
}

// ExtractSLD exposes the package-local extractSLD helper. Used by
// internal/httpgw to feed support-scam scoring with a consistent SLD
// definition.
func ExtractSLD(rawurl string) string { return extractSLD(rawurl) }

// extractSLD returns the leftmost label of the registrable domain in
// lowercase. Cheap host-only parser — does NOT do public-suffix lookup
// (too much policy weight for this branch). Returns "" on unparseable
// input so callers can safely chain.
func extractSLD(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil || u == nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	// For "www.bank-login.example" we want "bank-login", not "www".
	// Drop a leading "www." then return the leftmost remaining label.
	if parts[0] == "www" && len(parts) >= 3 {
		return parts[1]
	}
	// For "bank-login-secure-2026.example" parts is
	// ["bank-login-secure-2026","example"]; we want "bank-login-secure-2026".
	return parts[0]
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
