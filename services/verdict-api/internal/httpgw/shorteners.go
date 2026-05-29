// shorteners.go — known URL-shortener allowlist.
//
// URL shorteners (bit.ly, t.co, etc.) issue HTTP 301/302 to the real
// destination. Browsers follow the redirect; our pipeline checks the
// landing URL anyway. Treating the shortener hop itself as a separate
// "suspicious redirect" signal produces false positives on every share
// link a user follows from Twitter, Slack, news sites, etc.
//
// When the inbound URL host is in this set, the pipeline:
//   - Skips the suspicious-redirect-chain reason code on the shortener hop
//   - Forces a deep render so the FINAL URL (after redirect) gets full
//     Tier-2 evaluation
//
// Note: this is an ALLOWLIST OF HOPS, not of destinations. The page the
// shortener points at still goes through every rule.
package httpgw

import "strings"

// isURLShortener reports whether the host is a well-known shortener.
// Match is exact OR suffix (so geo subdomains like in.bit.ly match).
func isURLShortener(host string) bool {
	h := strings.ToLower(host)
	if _, ok := urlShortenerHosts[h]; ok {
		return true
	}
	for s := range urlShortenerHosts {
		if strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// urlShortenerHosts — curated list of well-known shorteners. Limited to
// services with a clear reputation: long-running, name-recognized, and
// not used by malware kits as their primary infrastructure (which would
// be more like discord.gg or random-looking *.cc TLDs).
var urlShortenerHosts = map[string]struct{}{
	// Major services
	"bit.ly":         {},
	"t.co":           {},  // Twitter
	"goo.gl":         {},  // Google (deprecated but live)
	"tinyurl.com":    {},
	"ow.ly":          {},  // Hootsuite
	"buff.ly":        {},  // Buffer
	"is.gd":          {},
	"v.gd":           {},
	"rebrand.ly":     {},
	"rb.gy":          {},
	"cutt.ly":        {},

	// Platform-specific
	"youtu.be":       {},  // YouTube
	"fb.me":          {},  // Facebook
	"lnkd.in":        {},  // LinkedIn
	"trib.al":        {},  // SocialFlow (publisher tooling)
	"flip.it":        {},  // Flipboard
	"medium.com":     {},  // Medium short links (medium.com/@user/long)
	"link.medium.com": {},
	"reut.rs":        {},  // Reuters
	"nyti.ms":        {},  // NY Times
	"bbc.in":         {},  // BBC
	"on.wsj.com":     {},  // WSJ
	"econ.st":        {},  // Economist
	"theatln.tc":     {},  // The Atlantic
	"theguardian.com": {}, // not strictly a shortener but their share URLs redirect
	"gu.com":         {},  // Guardian short
	"npr.org":        {},

	// Open-source
	"pulse.ly":       {},

	// GitHub-adjacent
	"git.io":         {},  // GitHub (deprecated 2022 but cached links live)

	// Microsoft/Apple platform
	"aka.ms":         {},  // Microsoft
	"apple.co":       {},  // Apple

	// Amazon
	"amzn.to":        {},  // Amazon

	// Slack / Discord (not shorteners but used like one)
	"slack.com":      {},
	"discord.gg":     {},
}
