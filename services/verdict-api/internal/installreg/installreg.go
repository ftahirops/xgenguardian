// Package installreg — Official Install Registry.
//
// Positive-match counterpart to the shellcmd negative-match scanner. Where
// shellcmd.go flags structurally suspicious commands (rundll32 over UNC,
// mshta + remote HTA, etc.), installreg recognizes the *correct* install
// commands published by official vendors and lets them through with high
// confidence.
//
// The match is a triple: (page host belongs to a registered brand) AND
// (the command structure matches a known template for that brand) AND
// (any URL inside the command targets one of the brand's canonical hosts).
// All three must agree before we award OfficialMatch — partial overlap is
// the exact attack pattern (real-looking command on a fake page, or fake
// command on a real page).
//
// Adding entries here is intentionally a code change. Data-driven
// expansion would let an attacker who compromised the registry data
// pre-approve malicious commands. Keep the list small and curated.
package installreg

import (
	"regexp"
	"strings"
)

// Template — one official install method for one brand. A brand may have
// many (macOS curl, Windows PowerShell, Linux package manager, etc.).
type Template struct {
	// Brand — canonical brand name, matches trustreg.Entry.Brand.
	Brand string

	// AllowedPageHosts — page hostnames where this template legitimately
	// appears (typically the vendor's docs/download subdomains). Exact match
	// or suffix; suffixes are written with leading dot ".vendor.com".
	AllowedPageHosts []string

	// CommandRegex — full-string regex over the (whitespace-collapsed)
	// command text. Must use anchors only if the entire command is required.
	// Most templates anchor on the most distinctive call (e.g. the actual
	// download URL).
	CommandRegex *regexp.Regexp

	// TargetURLPattern — every URL the command fetches MUST match this
	// pattern. Defended against the "real command shell with fake URL" form.
	// Use nil only when the template has no URL (e.g. a bare `brew install`
	// against the official Homebrew registry).
	TargetURLPattern *regexp.Regexp

	// Label — short human-readable name surfaced in the verdict response
	// ("Claude Code official macOS install", "Homebrew bottle").
	Label string
}

// MatchResult — what MatchCommand returns when a (host, command) pair is
// recognized.
type MatchResult struct {
	Brand    string
	Label    string
	Template *Template
}

// registry — hand-curated entries. Initial scope = top dev tools targeted
// by the Straiker "Fake Claude Code" 2026-05-27 campaign + the most
// commonly impersonated runtime / package-manager install pages.
//
// Templates are deliberately written to match the EXACT commands the
// official vendors publish. If a vendor changes their template, this
// stops matching and the (now legitimate but unrecognized) command will
// route through the general dev-install-lure path — surfaced via the
// telemetry-only "official_match miss on trusted host" signal so we can
// see and update the template without users hitting FPs.
var registry = []Template{
	// === Anthropic / Claude Code ===
	{
		Brand: "anthropic",
		AllowedPageHosts: []string{
			"docs.anthropic.com", "anthropic.com", "www.anthropic.com",
			"claude.ai", "www.claude.ai", "console.anthropic.com",
		},
		// macOS/Linux: curl -fsSL https://claude.ai/install.sh | bash
		// (Anthropic publishes "| bash"; the alternate "| sh" form is
		// also accepted for safety.)
		CommandRegex: regexp.MustCompile(
			`(?i)curl\s+(?:-[a-z]+\s+)*-?\w*\s*https?://claude\.ai/install\.sh\s*\|\s*(?:bash|sh)`),
		TargetURLPattern: regexp.MustCompile(`^https?://claude\.ai/install\.sh$`),
		Label:            "Claude Code official install (macOS/Linux)",
	},
	{
		Brand: "anthropic",
		AllowedPageHosts: []string{
			"docs.anthropic.com", "anthropic.com", "www.anthropic.com",
			"claude.ai", "www.claude.ai", "console.anthropic.com",
		},
		// Windows: irm https://claude.ai/install.ps1 | iex
		CommandRegex: regexp.MustCompile(
			`(?i)irm\s+https?://claude\.ai/install\.ps1\s*\|\s*iex`),
		TargetURLPattern: regexp.MustCompile(`^https?://claude\.ai/install\.ps1$`),
		Label:            "Claude Code official install (Windows)",
	},
	{
		Brand: "anthropic",
		AllowedPageHosts: []string{
			"docs.anthropic.com", "anthropic.com", "www.anthropic.com",
			"claude.ai", "www.claude.ai",
		},
		// npm: npm install -g @anthropic-ai/claude-code
		CommandRegex: regexp.MustCompile(
			`(?i)npm\s+(?:install|i)\s+(?:-g\s+)?@anthropic-ai/claude-code`),
		TargetURLPattern: nil,
		Label:            "Claude Code official install (npm)",
	},

	// === OpenAI ===
	{
		Brand: "openai",
		AllowedPageHosts: []string{
			"platform.openai.com", "openai.com", "www.openai.com",
		},
		CommandRegex: regexp.MustCompile(
			`(?i)pip\s+install\s+(?:--upgrade\s+)?openai\b`),
		TargetURLPattern: nil,
		Label:            "OpenAI Python SDK (pip)",
	},
	{
		Brand: "openai",
		AllowedPageHosts: []string{
			"platform.openai.com", "openai.com", "www.openai.com",
		},
		CommandRegex: regexp.MustCompile(
			`(?i)npm\s+(?:install|i)\s+(?:--save\s+)?openai\b`),
		TargetURLPattern: nil,
		Label:            "OpenAI Node SDK (npm)",
	},

	// === Cursor ===
	{
		Brand: "cursor",
		AllowedPageHosts: []string{
			"cursor.com", "www.cursor.com", "docs.cursor.com", "cursor.sh",
		},
		// Cursor publishes a `cursor` CLI install on macOS.
		CommandRegex: regexp.MustCompile(
			`(?i)curl\s+(?:-[a-z]+\s+)*-?\w*\s*https?://(?:downloads\.)?cursor\.(?:com|sh)/[^\s|]+\s*\|\s*sh`),
		TargetURLPattern: regexp.MustCompile(`^https?://(?:downloads\.)?cursor\.(?:com|sh)/`),
		Label:            "Cursor official install",
	},

	// === Cline (VS Code extension) ===
	{
		Brand: "cline",
		AllowedPageHosts: []string{
			"cline.bot", "www.cline.bot", "docs.cline.bot",
			"marketplace.visualstudio.com",
		},
		// Installed via marketplace; CLI is `code --install-extension saoudrizwan.claude-dev`
		CommandRegex: regexp.MustCompile(
			`(?i)code\s+--install-extension\s+saoudrizwan\.claude-dev\b`),
		TargetURLPattern: nil,
		Label:            "Cline VS Code extension",
	},

	// === Continue.dev (VS Code / JetBrains extension) ===
	{
		Brand: "continue-dev",
		AllowedPageHosts: []string{
			"continue.dev", "www.continue.dev", "docs.continue.dev",
			"hub.continue.dev", "marketplace.visualstudio.com",
		},
		CommandRegex: regexp.MustCompile(
			`(?i)code\s+--install-extension\s+continue\.continue\b`),
		TargetURLPattern: nil,
		Label:            "Continue.dev VS Code extension",
	},

	// === JetBrains Toolbox ===
	{
		Brand: "jetbrains",
		AllowedPageHosts: []string{
			"jetbrains.com", "www.jetbrains.com",
			"download.jetbrains.com",
		},
		// JetBrains primary distribution is binary downloads; we recognize
		// download URLs going to download.jetbrains.com.
		CommandRegex: regexp.MustCompile(
			`(?i)(?:curl|wget)\s+(?:-[a-z]+\s+)*https?://download\.jetbrains\.com/[^\s|]+`),
		TargetURLPattern: regexp.MustCompile(`^https?://download\.jetbrains\.com/`),
		Label:            "JetBrains binary download",
	},

	// === Homebrew ===
	{
		Brand: "homebrew",
		AllowedPageHosts: []string{
			"brew.sh", "www.brew.sh", "docs.brew.sh",
		},
		// The single Homebrew install command — pinned exactly.
		CommandRegex: regexp.MustCompile(
			`(?i)/bin/bash\s+-c\s+"\$\(curl\s+-fsSL\s+https://raw\.githubusercontent\.com/Homebrew/install/HEAD/install\.sh\)"`),
		TargetURLPattern: regexp.MustCompile(
			`^https://raw\.githubusercontent\.com/Homebrew/install/HEAD/install\.sh$`),
		Label: "Homebrew official install",
	},

	// === Rust / rustup ===
	{
		Brand: "rust-lang",
		AllowedPageHosts: []string{
			"rust-lang.org", "www.rust-lang.org", "doc.rust-lang.org",
			"rustup.rs", "sh.rustup.rs",
		},
		// curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
		CommandRegex: regexp.MustCompile(
			`(?i)curl\s+(?:--proto\s+'?=https'?\s+)?(?:--tlsv1\.2\s+)?(?:-[a-z]+\s+)*https?://sh\.rustup\.rs\s*\|\s*sh`),
		TargetURLPattern: regexp.MustCompile(`^https?://sh\.rustup\.rs/?$`),
		Label:            "Rust rustup official install",
	},

	// === Node.js (download page only — no curl|sh equivalent) ===
	{
		Brand: "nodejs",
		AllowedPageHosts: []string{
			"nodejs.org", "www.nodejs.org",
		},
		// nvm: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
		CommandRegex: regexp.MustCompile(
			`(?i)curl\s+(?:-[a-z]+\s+)*-o-?\s+https?://raw\.githubusercontent\.com/nvm-sh/nvm/[^\s|]+/install\.sh\s*\|\s*bash`),
		TargetURLPattern: regexp.MustCompile(
			`^https?://raw\.githubusercontent\.com/nvm-sh/nvm/`),
		Label: "nvm (Node Version Manager) install",
	},

	// === Python pip self-update ===
	{
		Brand: "python",
		AllowedPageHosts: []string{
			"python.org", "www.python.org", "pip.pypa.io",
			"docs.python.org",
		},
		CommandRegex: regexp.MustCompile(
			`(?i)(?:python3?|py)\s+-m\s+pip\s+install\s+(?:--upgrade\s+)?pip\b`),
		TargetURLPattern: nil,
		Label:            "pip self-update",
	},

	// === Docker (Linux convenience script) ===
	{
		Brand: "docker",
		AllowedPageHosts: []string{
			"docs.docker.com", "docker.com", "www.docker.com",
		},
		// curl -fsSL https://get.docker.com | sh
		CommandRegex: regexp.MustCompile(
			`(?i)curl\s+(?:-[a-z]+\s+)*-?\w*\s*https?://get\.docker\.com/?\s*\|\s*sh`),
		TargetURLPattern: regexp.MustCompile(`^https?://get\.docker\.com/?$`),
		Label:            "Docker convenience install (Linux)",
	},

	// === kubectl (Linux/macOS) ===
	{
		Brand: "kubernetes",
		AllowedPageHosts: []string{
			"kubernetes.io", "www.kubernetes.io", "k8s.io",
		},
		CommandRegex: regexp.MustCompile(
			`(?i)curl\s+(?:-[a-z]+\s+)*https?://dl\.k8s\.io/release/[^\s|]+/bin/`),
		TargetURLPattern: regexp.MustCompile(`^https?://dl\.k8s\.io/`),
		Label:            "kubectl official binary",
	},

	// === Go / golang ===
	{
		Brand: "golang",
		AllowedPageHosts: []string{
			"go.dev", "www.go.dev", "golang.org", "www.golang.org",
		},
		CommandRegex: regexp.MustCompile(
			`(?i)(?:curl|wget)\s+(?:-[a-z]+\s+)*https?://go\.dev/dl/[^\s|]+`),
		TargetURLPattern: regexp.MustCompile(`^https?://go\.dev/dl/`),
		Label:            "Go official binary",
	},
}

// urlExtractor pulls all http(s) URLs from a free-text command for
// TargetURLPattern checking.
var urlExtractor = regexp.MustCompile(`https?://[^\s"';)|&]+`)

// MatchCommand reports whether a (page host, command text) pair matches
// any registry entry whose AllowedPageHosts contains the host and whose
// CommandRegex matches the command and (when set) whose TargetURLPattern
// matches every URL in the command.
//
// Returns nil when no template matches. The caller uses a nil return as
// "command does not have a positive trust match" and falls back to the
// general dev-install-lure handling.
func MatchCommand(pageHost, command string) *MatchResult {
	if pageHost == "" || command == "" {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(pageHost, "."))
	// Collapse runs of whitespace so the regexes can be written cleanly.
	cmd := collapseWhitespace(command)
	for i := range registry {
		t := &registry[i]
		if !hostInList(host, t.AllowedPageHosts) {
			continue
		}
		if !t.CommandRegex.MatchString(cmd) {
			continue
		}
		if t.TargetURLPattern != nil {
			urls := urlExtractor.FindAllString(cmd, -1)
			// Allow when at least one URL matches AND no URL fails. Lets
			// templates with "optional" companion URLs (e.g. a docs link
			// alongside the install URL) still match cleanly. Pure-no-URL
			// templates skip this block entirely.
			anyOK := false
			for _, u := range urls {
				if !t.TargetURLPattern.MatchString(u) {
					return nil // strict — any off-pattern URL kills the match
				}
				anyOK = true
			}
			if !anyOK {
				continue
			}
		}
		return &MatchResult{Brand: t.Brand, Label: t.Label, Template: t}
	}
	return nil
}

// HasTemplatesForHost reports whether the registry has at least one
// template registered for the given host. Used for the telemetry-only
// "official_match miss on trusted host" signal: if we know a host has
// templates but none matched, that's worth logging (vendor may have
// updated their install instructions and we need to refresh the template).
func HasTemplatesForHost(pageHost string) bool {
	host := strings.ToLower(strings.TrimSuffix(pageHost, "."))
	for i := range registry {
		if hostInList(host, registry[i].AllowedPageHosts) {
			return true
		}
	}
	return false
}

// Size returns the number of templates. For diagnostics.
func Size() int { return len(registry) }

func hostInList(host string, list []string) bool {
	for _, h := range list {
		h = strings.ToLower(h)
		if strings.HasPrefix(h, ".") {
			if strings.HasSuffix(host, h) {
				return true
			}
			continue
		}
		if host == h {
			return true
		}
	}
	return false
}

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
