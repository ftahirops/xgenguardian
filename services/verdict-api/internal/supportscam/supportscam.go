// Package supportscam — fake-helpdesk / tech-support-scam scorer.
//
// Detects the page class FTC, FBI, Microsoft, and AnyDesk independently
// flag as a top-volume real-world threat: a page that impersonates a
// brand's support / security team and pressures the user to call a
// phone number, install a remote-access tool, or pay in gift cards /
// wire / crypto.
//
// Wave 3 / Phase 1: URL + SLD + page title scoring. Phase 2 adds
// visible-DOM text from sandbox-render (needs a new VisibleText field
// on renderResponse). Phase 3 adds OCR of the screenshot for phone
// numbers / payment-method demands rendered as images. The scoring
// function's signature is stable across phases — caller adds richer
// inputs without touching policy.
//
// Source basis (per docs/detection-category-improvement-plan.md §2):
//
//   Microsoft tech-support scams:
//     https://support.microsoft.com/en-us/security/avoid-and-report-microsoft-technical-support-scams
//   FTC tech-support scams + gift-card scam guidance:
//     https://consumer.ftc.gov/features/pass-it-on/impersonator-scams/tech-support-scams
//   FBI Phantom Hacker / tech-support scams:
//     https://www.fbi.gov/contact-us/field-offices/phoenix/news/press-releases/the-phantom-hacker-fbi-phoenix-warns-public-of-new-financial-scam
//   AnyDesk + TeamViewer abuse-prevention guidance:
//     https://anydesk.com/en/abuse-prevention
package supportscam

import (
	"sort"
	"strings"
)

// Inputs is the cross-phase input bag. Today only URL/SLD/Title are
// populated; VisibleText and OCRText are zero values until Phase 2/3.
// Score consumes whichever are present.
type Inputs struct {
	URL         string
	SLD         string
	Title       string
	VisibleText string // Phase 2
	OCRText     string // Phase 3
	// Host is the lowercase registrable domain. Used by the brand-
	// impersonation check to compare against brandgraph membership.
	Host string
	// HostInBrandgraph — true when Host is a curated brand. If a page
	// CLAIMS to be Microsoft support AND the host is in brandgraph
	// under the Microsoft brand, that's legitimate support, not a
	// scam. False here is the dangerous case.
	HostInBrandgraph bool
}

// Category is a stable label for a single scoring category. Surfaced
// to the response trace + telemetry so the doc's rule-health report
// can compute per-category contribution to FP/FN.
type Category string

const (
	CatScareware            Category = "scareware"
	CatPaymentDemand        Category = "payment_demand"
	CatRemoteTool           Category = "remote_tool"
	CatBrandImpersonation   Category = "brand_impersonation"
	CatGovImpersonation     Category = "gov_impersonation"
	CatSupportPhoneLure     Category = "support_phone_lure"
)

// Hit is one fired indicator. Surfaced so the warn/block page can
// render "this page used the phrase 'Your computer is infected' and
// also offered AnyDesk."
type Hit struct {
	Category Category
	Phrase   string  // the matched phrase (lower-case)
	Weight   float64 // contribution to score
	Source   string  // "url" | "sld" | "title" | "visible" | "ocr"
}

// Result is the scorer output. Caller wires Score into ContextOutput
// + adds a policy rule that consumes it.
type Result struct {
	Score float64 // 0..1+ (caps applied by Apply, not the scorer)
	Hits  []Hit
}

// thresholds — policy callers should use these so the scorer + the
// rule stay in sync. Mature engine will move to per-mode thresholds
// during the §23.3 risk-score migration.
const (
	// ThresholdWarn — minimum score to recommend WARN.
	ThresholdWarn = 0.30
	// ThresholdBlock — minimum score to recommend BLOCK on sensitive
	// pages (login/payment/install) or on hosts not in brandgraph
	// when impersonating a brand.
	ThresholdBlock = 0.50
	// ThresholdHardBlock — composite scams cross this with multiple
	// categories firing (e.g. brand_impersonation + payment_demand +
	// remote_tool). At this level the rule fires BLOCK regardless of
	// page class — composite tech-support-scams target everyone.
	ThresholdHardBlock = 0.80
)

// Score evaluates the inputs. Pure function. Order of evaluation
// inside a category doesn't matter — only the total per-category
// contribution. Each category caps so that one super-noisy category
// (e.g. lots of urgency words) can't single-handedly cross the WARN
// threshold without corroboration from another category.
func Score(in Inputs) Result {
	r := Result{}
	r.addCategory(in, scareware,          CatScareware,          0.30)
	r.addCategory(in, paymentDemand,      CatPaymentDemand,      0.30)
	r.addCategory(in, remoteTool,         CatRemoteTool,         0.30)
	r.addBrandImpersonation(in)
	r.addCategory(in, govImpersonation,   CatGovImpersonation,   0.25)
	r.addCategory(in, supportPhoneLure,   CatSupportPhoneLure,   0.20)
	// Structural composite: if the SLD contains BOTH a brand token AND a
	// scareware/help token (and the host is not in brandgraph), the
	// SLD itself is acting as a tech-support lure. This is the
	// canonical apple-virus-alert-help / windows-defender-warning /
	// microsoft-virus-alert URL shape that surfaced in smoke corpus.
	// One additive bonus per match — caps at 0.30 so it can't dominate.
	r.addSLDCompositeBonus(in)
	// Total cap at 1.5 — even a perfect-storm page can't shoot to
	// infinity. The policy rule consumes raw score (no clipping); we
	// just refuse to let runaway hits dominate the trace.
	if r.Score > 1.5 {
		r.Score = 1.5
	}
	// Sort hits so the trace and tests are deterministic.
	sort.SliceStable(r.Hits, func(i, j int) bool {
		if r.Hits[i].Weight != r.Hits[j].Weight {
			return r.Hits[i].Weight > r.Hits[j].Weight
		}
		return r.Hits[i].Phrase < r.Hits[j].Phrase
	})
	return r
}

// addCategory walks a phrase list, scores hits against every populated
// input source, caps the per-category total at `capWeight`, and adds
// hits to the result.
func (r *Result) addCategory(in Inputs, phrases []phrase, cat Category, capWeight float64) {
	var local []Hit
	var total float64
	for _, p := range phrases {
		for _, src := range sourcesFromInputs(in) {
			if strings.Contains(src.text, p.term) {
				total += p.weight
				local = append(local, Hit{
					Category: cat, Phrase: p.term, Weight: p.weight, Source: src.name,
				})
				break // each phrase contributes once across sources
			}
		}
	}
	if total > capWeight {
		// Scale all hits proportionally so the per-category contribution
		// is exactly capWeight, preserving the relative ordering.
		factor := capWeight / total
		for i := range local {
			local[i].Weight *= factor
		}
		total = capWeight
	}
	r.Hits = append(r.Hits, local...)
	r.Score += total
}

// addBrandImpersonation is the one category where the "host is the
// brand" escape applies. A page that mentions "Microsoft Support" on
// microsoft.com is legitimate; the same phrase on
// fake-microsoft-support.example is a scam. We only score this
// category when HostInBrandgraph is false.
func (r *Result) addBrandImpersonation(in Inputs) {
	if in.HostInBrandgraph {
		return
	}
	r.addCategory(in, brandImpersonation, CatBrandImpersonation, 0.35)
}

// addSLDCompositeBonus credits the structural pattern of a brand
// token co-occurring with a scareware / helpline token in the SLD.
// Examples (all real attacker URL shapes; none are legit):
//
//	apple-virus-alert-help
//	apple-virus-alert
//	windows-defender-warning
//	microsoft-virus-alert
//	norton-virus-help
//
// Each matching pair adds 0.10 to a per-category total capped at 0.30.
// Skips when host is in brandgraph (real brand-controlled support
// pages do legitimately combine these tokens). Categorised as
// CatBrandImpersonation so downstream rule-health reports can
// attribute the contribution.
func (r *Result) addSLDCompositeBonus(in Inputs) {
	if in.HostInBrandgraph || in.SLD == "" {
		return
	}
	sld := strings.ToLower(in.SLD)
	brandTokens := []string{
		"microsoft", "windows", "office365",
		"apple", "icloud", "macos",
		"google", "gmail", "android",
		"amazon", "aws",
		"norton", "mcafee", "avast", "avg",
		"facebook", "meta", "instagram", "whatsapp",
		"chase", "wellsfargo", "paypal", "citibank",
	}
	scareTokens := []string{
		"virus", "alert", "warning", "infected", "defender",
		"security-alert", "helpline", "tech-support", "support-help",
		"virus-alert", "alert-help", "virus-help", "warning-help",
		"refund-claim", "billing-alert", "account-locked",
	}
	hits := 0
	var matchedBrand, matchedScare string
	for _, b := range brandTokens {
		if strings.Contains(sld, b) {
			for _, s := range scareTokens {
				if strings.Contains(sld, s) {
					if matchedBrand == "" {
						matchedBrand, matchedScare = b, s
					}
					hits++
				}
			}
		}
	}
	if hits == 0 {
		return
	}
	weight := 0.10 * float64(hits)
	if weight > 0.30 {
		weight = 0.30
	}
	r.Score += weight
	r.Hits = append(r.Hits, Hit{
		Category: CatBrandImpersonation,
		Phrase:   matchedBrand + " + " + matchedScare,
		Weight:   weight,
		Source:   "sld_composite",
	})
}

// sourcesFromInputs returns the populated text sources to scan, each
// pre-lowercased. The scorer's per-source unique behavior means a
// phrase appearing in both URL and Title still counts once — which is
// what we want; phrase intent doesn't double.
func sourcesFromInputs(in Inputs) []source {
	out := make([]source, 0, 5)
	if in.URL != "" {
		out = append(out, source{name: "url", text: strings.ToLower(in.URL)})
	}
	if in.SLD != "" {
		out = append(out, source{name: "sld", text: strings.ToLower(in.SLD)})
	}
	if in.Title != "" {
		out = append(out, source{name: "title", text: strings.ToLower(in.Title)})
	}
	if in.VisibleText != "" {
		out = append(out, source{name: "visible", text: strings.ToLower(in.VisibleText)})
	}
	if in.OCRText != "" {
		out = append(out, source{name: "ocr", text: strings.ToLower(in.OCRText)})
	}
	return out
}

type source struct {
	name string
	text string
}

// phrase pairs a substring with its weight. Substrings are lowercase.
type phrase struct {
	term   string
	weight float64
}

// --- phrase dictionaries (research-sourced; see file header) -----------

var scareware = []phrase{
	// Real Microsoft / Norton / McAfee scareware text observed on
	// active scam pages and the FTC sample collection.
	{"your computer is infected", 0.15},
	{"your device is at risk", 0.12},
	{"virus detected", 0.12},
	{"trojan detected", 0.12},
	{"spyware detected", 0.12},
	{"malware detected", 0.10},
	{"security alert", 0.08},
	{"system has been compromised", 0.12},
	{"unauthorized access detected", 0.10},
	{"do not turn off your computer", 0.15},
	{"do not close this window", 0.10},
	{"your data is being stolen", 0.15},
	{"your files are encrypted", 0.10},
	{"your account has been suspended", 0.10},
	// URL-shape variants
	{"virus-alert", 0.10},
	{"virus-warning", 0.10},
	{"defender-warning", 0.10},
	{"defender-alert", 0.10},
	{"security-warning", 0.08},
	{"system-alert", 0.08},
}

var paymentDemand = []phrase{
	// FTC gift-card scam guidance — gift-card payment is the canonical
	// scam-only payment method. Weights skewed to high because real
	// support never demands these.
	{"gift card", 0.20},
	{"google play card", 0.20},
	{"apple gift card", 0.20},
	{"amazon gift card", 0.20},
	{"steam gift card", 0.20},
	{"itunes card", 0.20},
	{"itunes gift card", 0.20},
	{"western union", 0.15},
	{"moneygram", 0.15},
	{"wire transfer", 0.10},
	{"bitcoin payment", 0.15},
	{"crypto payment", 0.12},
	{"cash app", 0.08},
	{"venmo", 0.05},
	{"zelle", 0.05},
}

var remoteTool = []phrase{
	// AnyDesk + TeamViewer's own anti-scam guidance — these are the
	// canonical remote-tool lures. Scammers walk users through
	// installing one of these tools as the first step. Weight high.
	{"anydesk", 0.15},
	{"teamviewer", 0.15},
	{"team viewer", 0.15},
	{"quick assist", 0.10}, // Microsoft Quick Assist — abused
	{"ultraviewer", 0.15},
	{"ammyy", 0.15},
	{"rustdesk", 0.15},
	{"supremo", 0.15},
	{"splashtop", 0.10},
	{"screenconnect", 0.10},
	{"logmein", 0.10},
	{"showmypc", 0.15},
}

var brandImpersonation = []phrase{
	// "Brand + Support" or "Brand + Security" combos. Only scored
	// when host is NOT in brandgraph. Pre-Phase-2 covers SLD/URL/Title
	// only; Phase 2 will catch DOM text + image alt text.
	{"microsoft support", 0.15},
	{"microsoft-support", 0.15},
	{"microsoft helpline", 0.15},
	{"microsoft-helpline", 0.15},
	{"windows defender", 0.10},
	{"windows-defender", 0.10},
	{"apple support", 0.15},
	{"apple-support", 0.15},
	{"apple helpline", 0.12},
	{"apple-helpline", 0.12},
	{"icloud support", 0.12},
	{"google support", 0.12},
	{"google-support", 0.12},
	{"gmail support", 0.10},
	{"amazon support", 0.12},
	{"amazon-support", 0.12},
	{"norton support", 0.15},
	{"norton-support", 0.15},
	{"mcafee support", 0.15},
	{"mcafee-support", 0.15},
	{"avast support", 0.12},
	{"avg support", 0.12},
	{"facebook support", 0.10},
	{"meta support", 0.10},
}

var govImpersonation = []phrase{
	// US-only for Phase 1. Multi-jurisdiction expansion later.
	{"irs.gov", 0.15},
	{"irs tax", 0.10},
	{"irs-tax", 0.10},
	{"social security administration", 0.15},
	{"ssa.gov", 0.15},
	{"medicare.gov", 0.12},
	{"medicare-claim", 0.12},
	{"federal trade commission", 0.10},
	{"hmrc.gov", 0.12},                   // UK
	{"ato.gov.au", 0.10},                 // AU
	{"customs duty", 0.08},
	{"unpaid taxes", 0.10},
	{"unpaid-taxes", 0.10},
	{"arrest warrant", 0.15},
	{"arrest-warrant", 0.15},
	{"deportation notice", 0.15},
}

var supportPhoneLure = []phrase{
	{"call us at", 0.08},
	{"call now", 0.08},
	{"helpline", 0.08},
	{"toll free", 0.05},
	{"toll-free", 0.05},
	{"24/7 support", 0.05},
	{"support number", 0.05},
	{"customer service number", 0.05},
	{"contact our support team", 0.05},
}
