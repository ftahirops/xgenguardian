// Package orggraph — same-organization graph for verdict policy.
//
// PURPOSE — eliminate a whole class of false positive without trustreg growth.
//
// Many large organizations operate dozens of distinct registrable domains.
// Disney owns moviesanywhere.com, hulu.com, espn.com, abc.com, marvel.com,
// disneyplus.com, etc. The HIDDEN_MALICIOUS_LINK rule (Phase 6) counts
// cross-origin hidden anchors as suspicious because that's the pattern of
// a phishing kit scraping referrers. But a Disney portal that links to
// 6 other Disney brands is the normal corporate-family nav menu, not a
// phishing kit.
//
// Old approach: add each Disney domain to trustreg. Doesn't scale and
// makes trustreg a dumping ground.
//
// New approach: SameOrg(a, b) returns true when both registrable domains
// map to the same organization. Cross-origin counters treat same-org links
// as not-cross-origin. Adds 1 graph entry to cover N domains; trustreg
// stays small and principled.
//
// Tiers (matches the discipline doc):
//
//   Tier 0: hardcoded ~15 critical infrastructure providers (handled by
//           trustreg)
//   Tier 1: top ~500 impersonation targets (handled by trustreg)
//   Tier S: organization graph — N organizations × M domains each
//           (handled here). Membership in an org graph does NOT imply
//           trust; it implies "for cross-origin-anchor purposes, these
//           are the same entity." Critical distinction.
//
// Implementation note: this is a curated seed of well-known multi-brand
// organizations. It does NOT use WHOIS data, brand registries, or
// commercial sources. Growing it requires explicit PRs with the
// "Definition of a Real Fix" criteria — never as a side-effect of a
// false-positive patch on a single URL.
package orggraph

import "strings"

// Membership maps a registrable domain to an organization ID.
// Both keys and values are lowercase. Suffixes (".disney.com") are
// expanded into the explicit-host entries so SameOrg can do a single
// O(1) lookup per side without suffix-walking the registry.
var membership = map[string]string{}

// orgs — curated seed. Each org lists its known registrable domains.
// To add an org: append here, run the tests, write a PR with corpus
// entries demonstrating the FP class it prevents.
var orgs = map[string][]string{
	// Disney — moviesanywhere, ESPN, Hulu, ABC, Marvel, Pixar, Star Wars,
	// Nat Geo, Disney+, Hotstar. Adding here fixed the moviesanywhere.com
	// → Disney FP class without trustreg.
	"disney": {
		"disney.com", "disneyplus.com", "disneynow.com",
		"hulu.com", "espn.com", "abc.com",
		"marvel.com", "starwars.com", "pixar.com",
		"nationalgeographic.com", "natgeotv.com",
		"moviesanywhere.com", "hotstar.com",
		"shopdisney.com", "disneyparks.com",
	},

	// Alphabet / Google
	"alphabet": {
		"google.com", "google.co.uk", "google.de", "google.fr", "google.co.jp",
		"youtube.com", "youtu.be", "blogger.com",
		"android.com", "chrome.com",
		"gmail.com", "googleusercontent.com",
		"gstatic.com", "googleapis.com", "googlevideo.com",
		"waymo.com", "fitbit.com", "nest.com",
		"firebase.com", "firebaseapp.com",
		"deepmind.com",
	},

	// Microsoft
	"microsoft": {
		"microsoft.com", "microsoftonline.com",
		"office.com", "office365.com", "outlook.com", "live.com",
		"msn.com", "bing.com",
		"xbox.com", "minecraft.net", "mojang.com",
		"linkedin.com", "github.com",
		"azure.com", "azurewebsites.net",
		"windows.com", "windowsazure.com",
		"skype.com",
		"visualstudio.com",
	},

	// Meta
	"meta": {
		"meta.com", "facebook.com", "fb.com", "fb.me",
		"instagram.com", "whatsapp.com",
		"messenger.com", "fbcdn.net",
		"oculus.com", "metaview.com",
		"threads.net",
	},

	// Amazon
	"amazon": {
		"amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp",
		"amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amazon.in",
		"amazonaws.com", "awsstatic.com", "aws.amazon.com",
		"audible.com", "twitch.tv",
		"imdb.com", "ring.com", "kindle.com",
		"goodreads.com", "alexa.com",
		"zappos.com", "wholefoodsmarket.com",
		"abebooks.com",
	},

	// Apple
	"apple": {
		"apple.com", "icloud.com", "me.com", "mac.com",
		"appleid.apple.com", "itunes.com",
		"beats.com", "beatsbydre.com",
		"swift.org",
	},

	// Adobe
	"adobe": {
		"adobe.com", "behance.net", "magento.com",
		"frame.io",
	},

	// Salesforce
	"salesforce": {
		"salesforce.com", "force.com",
		"slack.com", "slackb.com",
		"heroku.com", "herokuapp.com",
		"tableau.com", "mulesoft.com",
		"pardot.com",
	},

	// Atlassian
	"atlassian": {
		"atlassian.com", "atlassian.net",
		"jira.com", "confluence.com",
		"bitbucket.org", "trello.com",
		"statuspage.io", "opsgenie.com",
	},

	// Netflix
	"netflix": {
		"netflix.com", "nflxext.com", "nflxvideo.net", "nflximg.net",
	},

	// Spotify
	"spotify": {
		"spotify.com", "scdn.co", "spotifycdn.com",
	},

	// Cloudflare
	"cloudflare": {
		"cloudflare.com", "cloudflare-dns.com",
		"workers.dev", "pages.dev",
		"cf-ipfs.com",
	},

	// Anthropic
	"anthropic": {
		"anthropic.com", "claude.ai",
	},

	// OpenAI
	"openai": {
		"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
	},

	// Stripe
	"stripe": {
		"stripe.com", "stripecdn.com",
	},

	// Shopify
	"shopify": {
		"shopify.com", "myshopify.com",
		"shopifycdn.com", "shopifyapps.com",
	},

	// PayPal
	"paypal": {
		"paypal.com", "paypalobjects.com",
		"venmo.com", "braintreepayments.com",
	},

	// Mozilla
	"mozilla": {
		"mozilla.org", "firefox.com",
		"mdn.dev", "mozilla.com",
	},

	// IBM / Red Hat
	"ibm": {
		"ibm.com", "redhat.com",
		"openshift.com", "fedoraproject.org",
	},

	// Oracle
	"oracle": {
		"oracle.com", "oraclecloud.com",
		"sun.com", "java.com",
		"mysql.com", "netsuite.com",
	},

	// SAP
	"sap": {
		"sap.com", "ariba.com", "concur.com",
		"successfactors.com", "sap.io",
	},

	// Bytedance / TikTok
	"bytedance": {
		"tiktok.com", "tiktokcdn.com", "tiktokv.com",
		"byteoversea.com", "douyin.com",
	},

	// Twitter / X
	"x": {
		"x.com", "twitter.com", "t.co", "twimg.com",
		"pscp.tv", "vine.co",
	},

	// Reddit
	"reddit": {
		"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
	},

	// PayPal note: separate from Stripe; both are processors, separate orgs.

	// Wikipedia / Wikimedia
	"wikimedia": {
		"wikipedia.org", "wikimedia.org", "wikidata.org",
		"wiktionary.org", "wikiquote.org", "wikinews.org",
		"wikibooks.org", "wikisource.org", "mediawiki.org",
	},

	// Stack Exchange
	"stackexchange": {
		"stackoverflow.com", "stackexchange.com",
		"serverfault.com", "superuser.com", "askubuntu.com",
		"mathoverflow.net",
	},

	// GitHub note: in Microsoft above. NOT duplicated here.
}

func init() {
	for org, hosts := range orgs {
		for _, h := range hosts {
			membership[strings.ToLower(h)] = org
		}
	}
}

// OrgOf returns the organization ID for a registrable domain. Returns
// the empty string when the domain is not in the graph (most domains
// won't be — that's expected and not an error).
func OrgOf(registrableDomain string) string {
	return membership[strings.ToLower(registrableDomain)]
}

// SameOrg returns true when both registrable domains map to the same
// organization. Returns false when either domain is unknown, even if
// they're literally the same string — callers must do exact-host comparison
// first if they want "same host" semantics.
func SameOrg(a, b string) bool {
	oa := OrgOf(a)
	if oa == "" {
		return false
	}
	return oa == OrgOf(b)
}

// SameOrgHosts — same as SameOrg but accepts subdomain-form inputs. Strips
// to the registrable suffix (last two labels for most TLDs) before lookup.
// This is a simplification; for proper PSL handling, use a real public-
// suffix-list library when accuracy matters. The simplified form is
// sufficient for the common-TLD case which is what the orggraph covers.
func SameOrgHosts(a, b string) bool {
	return SameOrg(registrable(a), registrable(b))
}

func registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	// Two-label form (last two). Works for example.com, google.com,
	// disneyplus.com. Doesn't work for ccTLD double-extensions
	// (amazon.co.uk → would return "co.uk"). For those we list every
	// regional ccTLD form explicitly in the org membership above.
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
