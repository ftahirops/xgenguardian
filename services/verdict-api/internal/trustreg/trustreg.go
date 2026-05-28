// Package trustreg — Trusted Identity Registry.
//
// Why this exists: a single bad row in an external feed (e.g. PhishDB listing
// "https://www.Amazon.com" as a phishing URL) used to flip our entire engine
// into BLOCKing amazon.com. Worse, every legitimate login page (login.live.com,
// accounts.google.com, github.com/login) was returning ISOLATE because the
// staged policy fails-closed for sensitive pages without active verification.
//
// The Trusted Identity Registry is the single curated source of "we know this
// host belongs to a major brand". It is consulted at three points:
//
//   1. persist.queryFeedHit — for trusted hosts, only exact-URL feed matches
//      count, not bare-domain matches. One bad feed row can never block a
//      whole brand.
//
//   2. policy.Apply Stage G — sensitive-page-verification-unavailable does
//      NOT escalate to ISOLATE for trusted hosts. We already know who they
//      are, sandbox failure doesn't change that.
//
//   3. policy.Apply Stage D — CREDENTIAL_SINK_HIDDEN_MIRROR and friends are
//      downgraded for trusted hosts (GitHub's login posts to multiple legit
//      endpoints — analytics, captcha, auth — that match our hidden-mirror
//      detector).
//
// This is a CURATED list. Adding to it requires a code change. That's
// intentional — we never want this to be data-driven where a typo could
// silently trust a phisher's domain.
package trustreg

import (
	"os"
	"strings"
)

// Entry — one brand + its set of host suffixes.
type Entry struct {
	Brand    string   // canonical brand name, e.g. "google", "microsoft"
	Hosts    []string // exact hosts that always trust
	Suffixes []string // host suffixes (e.g. ".google.com") that trust (with caveats)
}

// registry — hand-curated trusted-identity entries. Order doesn't matter;
// IsTrusted does a full scan.
//
// Rules for adding here:
//   - Only add hosts you would personally trust on day one of a new install.
//   - Prefer exact `Hosts` over `Suffixes` — suffix matches can be spoofed
//     by attackers via legitimate subdomains (e.g. user.googlepages.com).
//   - Never add domains that are heavily user-content (sites.google.com,
//     storage.googleapis.com) — those are shared-hosting, handled separately.
var registry = []Entry{
	{
		Brand: "google",
		Hosts: []string{
			"google.com", "www.google.com",
			"accounts.google.com", "myaccount.google.com",
			"mail.google.com", "drive.google.com", "docs.google.com",
			"calendar.google.com", "meet.google.com", "photos.google.com",
			"workspace.google.com", "admin.google.com",
			"console.cloud.google.com", "console.developers.google.com",
			"play.google.com", "pay.google.com", "wallet.google.com",
			"chrome.google.com", "myactivity.google.com",
			"youtube.com", "www.youtube.com", "studio.youtube.com",
			"gmail.com", "www.gmail.com",
			// Google-owned secondary domains (CDN, API, ads, analytics).
			// fp-bench flagged these as Google impersonators because they
			// visually match Google's design system; they're legitimately
			// Google-owned and must never be blocked.
			"googleapis.com", "googleusercontent.com", "googletagmanager.com",
			"googlevideo.com", "googlesyndication.com", "googledomains.com",
			"google-analytics.com", "googleadservices.com", "googleoptimize.com",
			"gstatic.com", "ggpht.com", "doubleclick.net",
			"goo.gl", "g.co", "youtu.be",
			"firebase.com",
			"android.com", "chromium.org",
			// Google update / static CDN domains.
			"gvt1.com", "gvt2.com", "gvt3.com",
			"recaptcha.net", "withgoogle.com", "googleblog.com",
			// firebaseapp.com / firebasestorage.googleapis.com stay in
			// shared-hosting (sharedHostingDomains) — they let any user
			// host content — not in trustreg.
		},
		// Suffixes deliberately exclude .google.com — that's shared-hosting
		// territory (sites.google.com lets anyone host content). Only the
		// specific brand-owned CDN/API suffixes here.
		Suffixes: []string{
			".googleusercontent.com", ".googletagmanager.com",
			".googlevideo.com", ".gstatic.com", ".doubleclick.net",
		},
	},
	{
		Brand: "microsoft",
		Hosts: []string{
			"microsoft.com", "www.microsoft.com",
			"login.live.com", "login.microsoftonline.com", "login.microsoft.com",
			"account.microsoft.com", "account.live.com",
			"outlook.office.com", "outlook.live.com", "outlook.office365.com",
			"portal.office.com", "portal.azure.com",
			"admin.microsoft.com", "admin.exchange.microsoft.com",
			"office.com", "www.office.com", "office365.com",
			"teams.microsoft.com", "onedrive.live.com",
			"github.com", "www.github.com", "gist.github.com",
			"bing.com", "www.bing.com",
			"sharepoint.com", "live.com",
			"msn.com", "skype.com", "xbox.com",
		},
		Suffixes: []string{
			".microsoft.com", ".microsoftonline.com", ".office.com",
			".office365.com", ".sharepoint.com", ".live.com",
			".xbox.com", ".azure.com", ".azureedge.net",
		},
	},
	{
		Brand: "apple",
		Hosts: []string{
			"apple.com", "www.apple.com",
			"appleid.apple.com", "idmsa.apple.com",
			"icloud.com", "www.icloud.com",
			"developer.apple.com", "itunes.apple.com",
			"buy.itunes.apple.com",
		},
	},
	{
		Brand: "amazon",
		Hosts: []string{
			"amazon.com", "www.amazon.com",
			"amazon.co.uk", "www.amazon.co.uk",
			"amazon.de", "amazon.fr", "amazon.it", "amazon.es",
			"amazon.ca", "amazon.com.au", "amazon.co.jp",
			"amazon.in", "amazon.com.br", "amazon.com.mx",
			"smile.amazon.com",
			"aws.amazon.com", "console.aws.amazon.com",
			"signin.aws.amazon.com",
			"sellercentral.amazon.com", "sellercentral-europe.amazon.com",
			"kdp.amazon.com", "advertising.amazon.com",
			"music.amazon.com", "primevideo.com", "www.primevideo.com",
		},
	},
	{
		Brand: "paypal",
		Hosts: []string{
			"paypal.com", "www.paypal.com",
			"paypal.me", "www.paypal.me",
		},
		Suffixes: []string{".paypal.com"},
	},
	{
		Brand: "stripe",
		Hosts: []string{
			"stripe.com", "www.stripe.com",
			"checkout.stripe.com", "dashboard.stripe.com",
			"connect.stripe.com", "billing.stripe.com",
		},
	},
	{
		Brand: "facebook-meta",
		Hosts: []string{
			"facebook.com", "www.facebook.com", "m.facebook.com",
			"messenger.com", "www.messenger.com",
			"instagram.com", "www.instagram.com",
			"whatsapp.com", "web.whatsapp.com",
			"meta.com", "about.meta.com",
			"fbcdn.net", "scontent.fbcdn.net", "static.xx.fbcdn.net",
			"graph.facebook.com",
		},
		Suffixes: []string{".fbcdn.net"},
	},
	{
		Brand: "dropbox",
		Hosts: []string{
			"dropbox.com", "www.dropbox.com",
			"paper.dropbox.com",
		},
	},
	{
		Brand: "slack",
		Hosts: []string{
			"slack.com", "www.slack.com", "api.slack.com",
		},
		Suffixes: []string{".slack.com"},
	},
	{
		Brand: "notion",
		Hosts: []string{
			"notion.so", "www.notion.so", "app.notion.so",
			"notion.com", "www.notion.com",
		},
	},
	{
		Brand: "atlassian",
		Hosts: []string{
			"atlassian.com", "www.atlassian.com", "id.atlassian.com",
			"bitbucket.org", "www.bitbucket.org",
		},
		Suffixes: []string{".atlassian.net", ".atlassian.com"},
	},
	{
		Brand: "linkedin",
		Hosts: []string{
			"linkedin.com", "www.linkedin.com",
		},
	},
	{
		Brand: "twitter-x",
		Hosts: []string{
			"twitter.com", "www.twitter.com",
			"x.com", "www.x.com",
		},
	},
	{
		Brand: "tiktok",
		Hosts: []string{
			"tiktok.com", "www.tiktok.com", "m.tiktok.com",
			"tiktokcdn.com", "p16-sign.tiktokcdn-us.com",
			"tiktokv.com", "byteoversea.com",
		},
		Suffixes: []string{".tiktokcdn.com", ".tiktokcdn-us.com", ".tiktokv.com", ".byteoversea.com"},
	},
	// Mail.ru — major Russian email provider, FP'd via visual CLIP similarity
	// to mail brands. Add as its own trusted entry.
	{
		Brand: "mail-ru",
		Hosts: []string{"mail.ru", "www.mail.ru", "e.mail.ru", "id.mail.ru"},
		Suffixes: []string{".mail.ru"},
	},
	// Huawei (parent of hicloudcam.com). Adding to suppress its FP.
	{
		Brand: "huawei",
		Hosts: []string{
			"huawei.com", "www.huawei.com", "consumer.huawei.com",
			"hicloud.com", "hicloudcam.com", "vmall.com",
		},
		Suffixes: []string{".huawei.com", ".hicloud.com", ".hicloudcam.com"},
	},
	{
		Brand: "chase",
		Hosts: []string{
			"chase.com", "www.chase.com",
			"secure.chase.com", "online.chase.com",
		},
	},
	{
		Brand: "bank-of-america",
		Hosts: []string{
			"bankofamerica.com", "www.bankofamerica.com",
			"secure.bankofamerica.com",
		},
	},
	{
		Brand: "wells-fargo",
		Hosts: []string{
			"wellsfargo.com", "www.wellsfargo.com",
			"connect.secure.wellsfargo.com",
		},
	},
	{
		Brand: "citi",
		Hosts: []string{
			"citi.com", "www.citi.com",
			"online.citi.com", "citibank.com", "www.citibank.com",
		},
	},
	{
		Brand: "wikipedia",
		Hosts: []string{
			"wikipedia.org", "www.wikipedia.org",
			"en.wikipedia.org", "commons.wikimedia.org",
			"wikimedia.org", "www.wikimedia.org",
		},
	},
	{
		Brand: "cloudflare",
		Hosts: []string{
			"cloudflare.com", "www.cloudflare.com",
			"dash.cloudflare.com", "developers.cloudflare.com",
			"one.one.one.one",
		},
	},
	{
		Brand: "mozilla",
		Hosts: []string{
			"mozilla.org", "www.mozilla.org",
			"firefox.com", "www.firefox.com",
			"addons.mozilla.org", "accounts.firefox.com",
		},
	},
	{
		Brand: "reddit",
		Hosts: []string{
			"reddit.com", "www.reddit.com", "old.reddit.com",
			"new.reddit.com",
		},
	},
	// Spotify wasn't in trustreg — added after FP. Same pattern for
	// Netflix and the streaming services we seeded into brand_screenshots.
	{
		Brand: "spotify",
		Hosts: []string{
			"spotify.com", "www.spotify.com", "open.spotify.com",
			"accounts.spotify.com",
		},
		Suffixes: []string{".spotify.com"},
	},
	{
		Brand: "netflix",
		Hosts: []string{"netflix.com", "www.netflix.com"},
		Suffixes: []string{".netflix.com", ".nflxso.net", ".nflxext.com"},
	},
	{
		Brand: "discord",
		Hosts: []string{"discord.com", "www.discord.com", "discordapp.com"},
		Suffixes: []string{".discord.com", ".discordapp.com", ".discordapp.net"},
	},
	// AI developer tools — heavily impersonated per Straiker's 2026-05-27
	// report on the ACRStealer/Amatera "Fake Claude Code" campaign (88
	// tracked impersonator domains across 10 hosting platforms). Anthropic,
	// JetBrains, Cline, Continue.dev, Snowflake, Cursor, Perplexity Comet
	// all named as either lures or post-payload theft targets.
	{
		Brand: "anthropic",
		Hosts: []string{
			"anthropic.com", "www.anthropic.com",
			"claude.ai", "www.claude.ai",
			"console.anthropic.com", "docs.anthropic.com",
			"api.anthropic.com", "support.anthropic.com",
			// Anthropic also publishes docs/dashboard under claude.com — the
			// docs.anthropic.com redirect chain lands on docs.claude.com /
			// platform.claude.com. Add the whole claude.com suffix.
			"claude.com", "www.claude.com",
			"docs.claude.com", "platform.claude.com",
			"console.claude.com", "code.claude.com",
		},
		Suffixes: []string{".anthropic.com", ".claude.ai", ".claude.com"},
	},
	{
		Brand: "openai",
		Hosts: []string{
			"openai.com", "www.openai.com",
			"chatgpt.com", "www.chatgpt.com",
			"chat.openai.com", "platform.openai.com",
			"api.openai.com", "auth.openai.com",
			"help.openai.com", "labs.openai.com",
		},
		Suffixes: []string{".openai.com", ".chatgpt.com"},
	},
	{
		Brand: "jetbrains",
		Hosts: []string{
			"jetbrains.com", "www.jetbrains.com",
			"account.jetbrains.com", "plugins.jetbrains.com",
			"download.jetbrains.com",
		},
		Suffixes: []string{".jetbrains.com"},
	},
	{
		Brand: "cursor",
		Hosts: []string{"cursor.com", "www.cursor.com", "cursor.sh"},
		Suffixes: []string{".cursor.com", ".cursor.sh"},
	},
	{
		Brand: "cline",
		Hosts: []string{"cline.bot", "www.cline.bot"},
		Suffixes: []string{".cline.bot"},
	},
	{
		Brand: "continue-dev",
		Hosts: []string{"continue.dev", "www.continue.dev", "hub.continue.dev"},
		Suffixes: []string{".continue.dev"},
	},
	{
		Brand: "snowflake",
		Hosts: []string{
			"snowflake.com", "www.snowflake.com",
			"app.snowflake.com", "signup.snowflake.com",
		},
		Suffixes: []string{".snowflakecomputing.com", ".snowflake.com"},
	},
	{
		Brand: "perplexity",
		Hosts: []string{
			"perplexity.ai", "www.perplexity.ai",
			"comet.perplexity.ai",
		},
		Suffixes: []string{".perplexity.ai"},
	},
	{
		Brand: "huggingface",
		Hosts: []string{"huggingface.co", "www.huggingface.co"},
		Suffixes: []string{".huggingface.co", ".hf.co"},
	},
	{
		Brand: "replicate",
		Hosts: []string{"replicate.com", "www.replicate.com"},
		Suffixes: []string{".replicate.com", ".replicate.delivery"},
	},
	// Major developer infrastructure — language runtimes, package
	// managers, container platforms. Surfaced as FPs once the
	// developer-tool-install-lure page class was added, because their
	// docs/download pages show install commands and CLIP misclassified
	// them at high visual similarity. Add as own trusted brands.
	{
		Brand: "nodejs",
		Hosts: []string{"nodejs.org", "www.nodejs.org"},
		Suffixes: []string{".nodejs.org"},
	},
	{
		Brand: "python",
		Hosts: []string{"python.org", "www.python.org", "pypi.org", "www.pypi.org", "docs.python.org"},
		Suffixes: []string{".python.org", ".pypi.org"},
	},
	{
		Brand: "homebrew",
		Hosts: []string{"brew.sh", "www.brew.sh", "docs.brew.sh"},
		Suffixes: []string{".brew.sh"},
	},
	{
		Brand: "docker",
		Hosts: []string{
			"docker.com", "www.docker.com", "docs.docker.com",
			"hub.docker.com", "download.docker.com",
		},
		Suffixes: []string{".docker.com", ".docker.io"},
	},
	{
		Brand: "kubernetes",
		Hosts: []string{
			"kubernetes.io", "www.kubernetes.io",
			"k8s.io", "www.k8s.io",
		},
		Suffixes: []string{".kubernetes.io", ".k8s.io"},
	},
	{
		Brand: "rust-lang",
		Hosts: []string{
			"rust-lang.org", "www.rust-lang.org",
			"doc.rust-lang.org", "crates.io", "www.crates.io",
		},
		Suffixes: []string{".rust-lang.org", ".crates.io"},
	},
	{
		Brand: "golang",
		Hosts: []string{"go.dev", "www.go.dev", "golang.org", "www.golang.org", "pkg.go.dev"},
		Suffixes: []string{".go.dev", ".golang.org"},
	},
	{
		Brand: "npm",
		Hosts: []string{"npmjs.com", "www.npmjs.com", "registry.npmjs.org"},
		Suffixes: []string{".npmjs.com", ".npmjs.org"},
	},
	// Personal-infra block was moved out of source control to keep this
	// curated registry brand-only. Operator-specific entries (your own
	// mail server, internal SaaS, family domains) live in a gitignored
	// config loaded at startup from XGG_LOCAL_TRUSTREG_PATH (default
	// /etc/xgg/local-trustreg.yaml). See loadLocalEntries() below.
}

// hostMatchSet — precomputed exact-host lookup, built once at init.
var hostMatchSet map[string]string // host -> brand

// suffixMatchList — list of (suffix, brand) tuples, scanned linearly.
var suffixMatchList []struct {
	suffix string
	brand  string
}

func init() {
	hostMatchSet = make(map[string]string, 256)
	for _, e := range registry {
		for _, h := range e.Hosts {
			hostMatchSet[strings.ToLower(h)] = e.Brand
		}
		for _, s := range e.Suffixes {
			suffixMatchList = append(suffixMatchList, struct {
				suffix string
				brand  string
			}{strings.ToLower(s), e.Brand})
		}
	}
	loadLocalEntries()
}

// loadLocalEntries — reads operator-specific trusted hosts from the
// XGG_LOCAL_TRUSTED_HOSTS env var (comma-separated). Entries starting
// with "." are treated as suffix matches; otherwise exact hostname.
//
// Example:
//   XGG_LOCAL_TRUSTED_HOSTS="mail.example.com,intranet.example.com,.example.com"
//
// Kept out of the curated `registry` so the public source code does
// not leak per-operator infrastructure. A future Personal Profile
// feature will replace this with a per-user YAML.
func loadLocalEntries() {
	csv := os.Getenv("XGG_LOCAL_TRUSTED_HOSTS")
	if csv == "" {
		return
	}
	for _, raw := range strings.Split(csv, ",") {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, ".") {
			suffixMatchList = append(suffixMatchList, struct {
				suffix string
				brand  string
			}{s, "local"})
			continue
		}
		hostMatchSet[s] = "local"
	}
}

// normalize — lowercase + strip trailing dot. Idempotent.
func normalize(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// IsTrusted reports whether host belongs to a registered trusted brand.
// This is the load-bearing function — used to skip fail-closed ISOLATE
// and limit feed lookups to exact URLs.
func IsTrusted(host string) bool {
	if host == "" {
		return false
	}
	h := normalize(host)
	if _, ok := hostMatchSet[h]; ok {
		return true
	}
	for _, s := range suffixMatchList {
		if strings.HasSuffix(h, s.suffix) {
			return true
		}
	}
	return false
}

// BrandFor returns the canonical brand name for a host, or "" if not trusted.
// Used to populate display strings and brand-aware policy.
func BrandFor(host string) string {
	if host == "" {
		return ""
	}
	h := normalize(host)
	if b, ok := hostMatchSet[h]; ok {
		return b
	}
	for _, s := range suffixMatchList {
		if strings.HasSuffix(h, s.suffix) {
			return s.brand
		}
	}
	return ""
}

// Size returns the number of registered exact hosts. For diagnostics.
func Size() int { return len(hostMatchSet) }
