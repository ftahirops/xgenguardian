// Package paymentscam — money-fraud / scam-payment-method scorer.
//
// Complements internal/supportscam by focusing on the PAYMENT side of
// scams: fake IRS refunds, gift-card demands, wire-transfer fraud,
// invoice phishing, lottery / inheritance / sweepstakes scams, romance-
// scam money requests, and charity-impersonation. Same phrase-scoring
// architecture as supportscam — small, fast, no ML.
//
// Wave 3 Phase 2: URL + SLD + title + visible-DOM text scoring.
// Phase 3 will add OCR text from screenshot.
//
// Source basis:
//
//	FTC consumer alerts on tax-refund / IRS impostor scams:
//	  https://consumer.ftc.gov/articles/irs-impostor-scams
//	FTC gift-card scam guidance:
//	  https://consumer.ftc.gov/articles/avoiding-and-reporting-gift-card-scams
//	FBI IC3 wire-fraud / business-email-compromise advisory:
//	  https://www.ic3.gov/Media/Y2022/PSA220504
//	FBI romance-scam advisory:
//	  https://www.fbi.gov/news/stories/romance-scams
//	FTC sweepstakes / lottery scam guidance:
//	  https://consumer.ftc.gov/articles/fake-prize-sweepstakes-lottery-scams
//
// Hard rule philosophy: a page that demands payment via gift card or
// wire transfer for a "tax refund" / "lottery winnings" / "lawsuit
// settlement" is scam-by-construction — no benign reading. Composite
// scores cross HardBlock and BLOCK regardless of page class.
package paymentscam

import (
	"sort"
	"strings"
)

// Inputs is the cross-phase input bag. Identical shape to
// supportscam.Inputs so the same plumbing serves both.
type Inputs struct {
	URL         string
	SLD         string
	Title       string
	VisibleText string
	OCRText     string
	Host        string
	// HostInBrandgraph short-circuits the brand-impersonation category
	// only. A legitimate IRS page on irs.gov can legitimately discuss
	// tax refunds; an attacker hosting "claim your IRS refund" on
	// irs-refund-claim.example cannot.
	HostInBrandgraph bool
}

// Category labels for telemetry and the rule-health report.
type Category string

const (
	CatGiftCardScam    Category = "gift_card_scam"
	CatWireFraud       Category = "wire_fraud"
	CatTaxRefundScam   Category = "tax_refund_scam"
	CatFakeInvoice     Category = "fake_invoice"
	CatLotteryScam     Category = "lottery_scam"
	CatRomanceScam     Category = "romance_scam"
	CatCharityScam     Category = "charity_scam"
	CatGovImpersonation Category = "gov_impersonation"
)

// Hit is one fired indicator.
type Hit struct {
	Category Category
	Phrase   string
	Weight   float64
	Source   string // "url" | "sld" | "title" | "visible" | "ocr"
}

// Result mirrors supportscam.Result so consumers can iterate.
type Result struct {
	Score float64
	Hits  []Hit
}

const (
	ThresholdWarn      = 0.30
	ThresholdBlock     = 0.50
	ThresholdHardBlock = 0.80
)

// Score evaluates the inputs. Pure function.
//
// Hosts in brandgraph get an early-return: a Wikipedia article on
// "gift card" or a news article about wire-fraud doesn't score against
// the site for being a scam. Scams don't happen on trustreg hosts.
// The SLD-composite path skips the early-return anyway since it's
// inspecting URL shape, not page content.
func Score(in Inputs) Result {
	if in.HostInBrandgraph {
		return Result{}
	}
	r := Result{}
	r.addCategory(in, giftCardScam,     CatGiftCardScam,    0.35)
	r.addCategory(in, wireFraud,        CatWireFraud,       0.30)
	r.addCategory(in, taxRefundScam,    CatTaxRefundScam,   0.30)
	r.addCategory(in, fakeInvoice,      CatFakeInvoice,     0.25)
	r.addCategory(in, lotteryScam,      CatLotteryScam,     0.30)
	r.addCategory(in, romanceScam,      CatRomanceScam,     0.20)
	r.addCategory(in, charityScam,      CatCharityScam,     0.20)
	r.addGovImpersonation(in)
	// SLD-composite bonus — payment-method token + scam-pretext token
	// in the same SLD (e.g. irs-refund, gift-card-redeem,
	// wire-transfer-urgent). Catches URL-only signal cases that the
	// per-category phrase lists miss in isolation.
	r.addSLDCompositeBonus(in)
	if r.Score > 1.5 {
		r.Score = 1.5
	}
	sort.SliceStable(r.Hits, func(i, j int) bool {
		if r.Hits[i].Weight != r.Hits[j].Weight {
			return r.Hits[i].Weight > r.Hits[j].Weight
		}
		return r.Hits[i].Phrase < r.Hits[j].Phrase
	})
	return r
}

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
				break
			}
		}
	}
	if total > capWeight {
		factor := capWeight / total
		for i := range local {
			local[i].Weight *= factor
		}
		total = capWeight
	}
	r.Hits = append(r.Hits, local...)
	r.Score += total
}

// addGovImpersonation skips when host is in brandgraph — legitimate
// .gov / .gov.uk / .gov.au pages discuss tax, customs, social security
// programs and so on. Only non-brandgraph hosts get scored.
func (r *Result) addGovImpersonation(in Inputs) {
	if in.HostInBrandgraph {
		return
	}
	r.addCategory(in, govImpersonation, CatGovImpersonation, 0.30)
}

// addSLDCompositeBonus credits SLD-only co-occurrence of a payment-
// method token + a scam-pretext token. Real attacker URL shapes that
// surfaced in the smoke corpus and FTC samples:
//
//	irs-refund-claim
//	tax-refund-direct-deposit
//	gift-card-redeem-instant
//	western-union-urgent-payment
//	wire-transfer-secure-claim
func (r *Result) addSLDCompositeBonus(in Inputs) {
	if in.HostInBrandgraph || in.SLD == "" {
		return
	}
	sld := strings.ToLower(in.SLD)
	paymentTokens := []string{
		"gift-card", "giftcard",
		"western-union", "moneygram", "wire-transfer",
		"bitcoin", "crypto",
	}
	pretextTokens := []string{
		"refund", "claim", "redeem", "urgent",
		"tax-refund", "irs", "ssa", "hmrc",
		"lottery", "sweepstakes", "winner", "prize",
		"invoice", "overdue", "lawsuit", "settlement",
		// Wave 3 corpus-driven additions
		"inheritance", "beneficiary", "deceased", "estate",
		"social-security", "ssn", "suspended",
		"geek-squad", "mcafee-invoice", "norton-invoice",
		"renewal", "renewal-invoice", "subscription",
		"customs", "duty", "unpaid",
		"medicare", "benefits",
	}
	hits := 0
	var matchedPay, matchedPretext string
	for _, p := range paymentTokens {
		if strings.Contains(sld, p) {
			for _, x := range pretextTokens {
				if strings.Contains(sld, x) {
					if matchedPay == "" {
						matchedPay, matchedPretext = p, x
					}
					hits++
				}
			}
		}
	}
	if hits == 0 {
		// Also catch pretext-only SLDs that ARE scams even without an
		// explicit payment method (e.g. irs-tax-refund-direct-deposit).
		// Two pretext tokens together in the SLD is a strong signal.
		var found []string
		for _, x := range pretextTokens {
			if strings.Contains(sld, x) {
				found = append(found, x)
				if len(found) >= 2 {
					break
				}
			}
		}
		if len(found) >= 2 {
			r.Score += 0.30
			r.Hits = append(r.Hits, Hit{
				Category: CatTaxRefundScam,
				Phrase:   strings.Join(found, " + "),
				Weight:   0.30,
				Source:   "sld_composite",
			})
		}
		return
	}
	weight := 0.15 * float64(hits)
	if weight > 0.35 {
		weight = 0.35
	}
	r.Score += weight
	r.Hits = append(r.Hits, Hit{
		Category: CatGiftCardScam,
		Phrase:   matchedPay + " + " + matchedPretext,
		Weight:   weight,
		Source:   "sld_composite",
	})
}

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

type phrase struct {
	term   string
	weight float64
}

// --- phrase dictionaries ----------------------------------------------------

var giftCardScam = []phrase{
	// Direct gift-card payment demands — FTC: gift cards are NEVER
	// requested by legitimate businesses or government agencies.
	{"gift card", 0.20},
	{"gift cards", 0.20},
	{"google play card", 0.20},
	{"apple gift card", 0.20},
	{"amazon gift card", 0.20},
	{"steam gift card", 0.20},
	{"itunes card", 0.20},
	{"itunes gift card", 0.20},
	{"target gift card", 0.18},
	{"walmart gift card", 0.18},
	{"ebay gift card", 0.18},
	{"vanilla card", 0.18},
	{"sephora gift card", 0.15},
	{"scratch off the back", 0.20}, // canonical scam phrase
	{"reveal the code on the back", 0.20},
	{"send the card numbers", 0.20},
	{"text us the gift card numbers", 0.20},
}

var wireFraud = []phrase{
	{"western union", 0.20},
	{"moneygram", 0.20},
	{"wire transfer", 0.10},
	{"wire the money", 0.15},
	{"send via wire", 0.12},
	{"bank wire", 0.10},
	{"swift transfer", 0.08},
	{"international wire", 0.10},
	{"urgent wire transfer", 0.20},
	{"cash app payment", 0.10},
	{"zelle transfer", 0.08},
	{"venmo payment", 0.05},
}

var taxRefundScam = []phrase{
	{"tax refund", 0.10},
	{"refund pending", 0.12},
	{"unclaimed refund", 0.15},
	{"direct deposit refund", 0.12},
	{"claim your refund", 0.15},
	{"refund of $", 0.10},
	{"refund amount", 0.08},
	{"file your taxes", 0.06},
	{"tax compensation", 0.10},
	{"federal refund", 0.08},
	{"state refund", 0.06},
	{"irs refund check", 0.20},
	{"refund waiting", 0.15},
}

var fakeInvoice = []phrase{
	{"unpaid invoice", 0.10},
	{"overdue invoice", 0.12},
	{"invoice attached", 0.10},
	{"please pay this invoice", 0.10},
	{"final notice", 0.10},
	{"payment reminder", 0.06},
	{"open the attached invoice", 0.08},
	{"renewal invoice", 0.08},
	{"automatic renewal charged", 0.10},
	{"your subscription was renewed", 0.08},
	{"geek squad", 0.10}, // canonical scam invoice brand
	{"mcafee invoice", 0.12},
	{"norton invoice", 0.12},
	{"paypal invoice", 0.10},
	// Wave 3 hyphenated SLD variants for /v1/check URL-only paths
	{"geek-squad", 0.15},
	{"mcafee-invoice", 0.15},
	{"norton-invoice", 0.15},
	{"paypal-invoice-overdue", 0.18},
	{"invoice-overdue", 0.12},
	{"renewal-invoice", 0.10},
}

var lotteryScam = []phrase{
	{"congratulations you have won", 0.20},
	{"lottery winner", 0.15},
	{"sweepstakes winner", 0.15},
	{"jackpot winner", 0.15},
	{"selected as a winner", 0.15},
	{"claim your prize", 0.12},
	{"claim your winnings", 0.15},
	{"you have been selected", 0.10},
	{"lucky draw", 0.10},
	{"random selection", 0.08},
	{"powerball winner", 0.15},
	{"mega millions winner", 0.15},
	{"inheritance from", 0.15}, // 419 / inheritance scams
	{"prince of nigeria", 0.20}, // canonical
	{"deceased relative", 0.15},
	{"beneficiary of the estate", 0.15},
	// Wave 3 — hyphenated SLD variants
	{"inheritance-claim", 0.18},
	{"inheritance-beneficiary", 0.18},
	{"unclaimed-inheritance", 0.18},
	{"deceased-relative", 0.15},
}

var romanceScam = []phrase{
	{"send me money for", 0.15},
	{"i need money for", 0.10},
	{"can you wire me", 0.15},
	{"emergency surgery", 0.10},
	{"stuck in customs", 0.15},
	{"travel emergency", 0.10},
	{"meet in person soon", 0.05},
	{"have not met but love", 0.10},
}

var charityScam = []phrase{
	{"donate now", 0.05},
	{"emergency donation", 0.08},
	{"hurricane relief", 0.06},
	{"earthquake relief", 0.06},
	{"war relief", 0.06},
	{"orphans need your help", 0.08},
	{"100% of donations", 0.05},
}

var govImpersonation = []phrase{
	{"irs.gov", 0.10},
	{"internal revenue service", 0.10},
	{"social security administration", 0.12},
	{"ssa.gov", 0.12},
	{"medicare.gov", 0.10},
	{"medicare-claim", 0.10},
	{"federal trade commission", 0.08},
	{"hmrc.gov", 0.10},
	{"hm revenue customs", 0.10},
	{"ato.gov.au", 0.08},
	{"customs duty", 0.06},
	{"unpaid customs", 0.10},
	{"unpaid taxes", 0.12},
	{"arrest warrant", 0.15},
	{"deportation notice", 0.15},
	{"social security number suspended", 0.20},
	{"benefits suspended", 0.10},
	// Wave 3 hyphenated SLD variants for /v1/check URL-only paths
	{"social-security-number", 0.18},
	{"social-security-suspended", 0.20},
	{"ssn-suspended", 0.18},
	{"benefits-suspended", 0.15},
}
