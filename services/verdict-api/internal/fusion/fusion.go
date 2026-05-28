// Package fusion — combines Tier-1 signals, visual brand-match output,
// and sandbox-extracted form/redirect data into a single verdict.
//
// Phase-1 implementation is **rule-based, not ML**. We can replace this
// with a gradient-boosted model (LightGBM via gobrain or local inference)
// once we have labeled samples — see Phase 4 (#38) for the training pipeline.
//
// Verdict assignment (architecture.md §27 #13 — identity-mismatch fusion rule):
//
//   if  visual_similarity ≥ τ_visual
//   AND domain ∉ matched_brand.canonical_domains
//   AND (domain_age < 90d OR ASN ∉ brand.ASNs OR cert ∉ brand.issuers)
//        → BLOCK (high confidence)
//
//   else compute weighted sum of signals; BLOCK ≥ 0.85, WARN ≥ 0.55,
//        ANALYZING if Tier-2 still pending, else CLEAN.
package fusion

import (
	"math"
	"strings"
	"time"
)

// Inputs is everything we know about the URL after Tier-1 + Tier-2.
// Any field may be zero-valued — fusion is robust to missing signals.
type Inputs struct {
	Domain string
	URL    string

	// --- infrastructure ---
	DomainAge   time.Duration // 0 ⇒ unknown
	CertAge     time.Duration
	CertIssuer  string
	ASN         int

	// --- Tier-1 lexical / homoglyph ---
	Tier1Signals []Signal

	// --- visual brand match ---
	VisualTopBrand    string
	VisualTopScore    float64 // cosine similarity 0..1
	FaviconMatchBrand string  // brand name matched by favicon hash (exact)
	// pHash near-duplicate match — deterministic visual similarity.
	// Distance is Hamming over 64-bit perceptual hashes; <=8 is
	// near-certain near-duplicate. Populated by visual-match's
	// brand_screenshots.phash backfill path.
	PHashMatchBrand    string
	PHashMatchDistance int

	// --- form / behavior ---
	HasPasswordForm   bool
	CrossOriginPost   bool
	CrossOriginTarget string

	// --- file downloads discovered on the page ---
	RiskyDownloads    int
	RiskyDownloadHint string // first risky URL for the evidence panel

	// --- brand registry context (set when VisualTopBrand resolves) ---
	BrandCanonicalDomains []string
	BrandLegitimateASNs   []int
	BrandLegitimateIssuers []string

	// --- external corroborators (optional) ---
	GSBClean       *bool // nil if not consulted
	VTPositives    int   // 0 if not consulted
	BlocklistHit   bool
}

type Signal struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

type Output struct {
	Verdict    string   `json:"verdict"`     // CLEAN | WARN | BLOCK | ANALYZING
	Confidence float64  `json:"confidence"`  // 0..1
	Signals    []Signal `json:"signals"`
	TopBrand   string   `json:"visual_top_brand,omitempty"`
	TopScore   float64  `json:"visual_top_score,omitempty"`
	Reason     string   `json:"block_reason,omitempty"`
}

// Thresholds — tunable. Initial values set from architecture.md §32.3.
const (
	VisualBlockThreshold = 0.92
	VisualWarnThreshold  = 0.80
	ScoreBlockThreshold  = 0.85
	ScoreWarnThreshold   = 0.55
)

// Score runs the fusion logic and returns the verdict.
func Score(in Inputs) Output {
	signals := append([]Signal(nil), in.Tier1Signals...)
	var sum float64

	// Hard short-circuit: blocklist hit.
	if in.BlocklistHit {
		signals = append(signals, Signal{Name: "blocklist_hit", Weight: 1.0, Detail: "domain on aggregated threat feeds"})
		return Output{
			Verdict:    "BLOCK",
			Confidence: 1.0,
			Signals:    signals,
			Reason:     "Domain is on aggregated threat-intelligence feeds.",
		}
	}

	// Universal phishing rule (#13): visual match + identity mismatch.
	if in.VisualTopScore >= VisualBlockThreshold && in.VisualTopBrand != "" {
		if isImpersonation(in) {
			reason := buildImpersonationReason(in)
			signals = append(signals,
				Signal{Name: "visual_brand_match", Weight: 0.7,
					Detail: in.VisualTopBrand + " similarity " + ftoa(in.VisualTopScore)},
				Signal{Name: "identity_mismatch", Weight: 0.4, Detail: reason},
			)
			return Output{
				Verdict:    "BLOCK",
				Confidence: clamp(0.85 + (in.VisualTopScore-VisualBlockThreshold)*1.5),
				Signals:    signals,
				TopBrand:   in.VisualTopBrand,
				TopScore:   in.VisualTopScore,
				Reason:     reason,
			}
		}
	}

	// Favicon exact match to a brand that isn't the page's brand.
	if in.FaviconMatchBrand != "" && !domainOfBrand(in.Domain, in.BrandCanonicalDomains) {
		signals = append(signals, Signal{
			Name: "favicon_brand_match", Weight: 0.5,
			Detail: "favicon matches " + in.FaviconMatchBrand + " on non-canonical domain",
		})
	}

	// Form-action exfil signal.
	if in.HasPasswordForm && in.CrossOriginPost {
		signals = append(signals, Signal{
			Name: "cred_form_cross_origin", Weight: 0.45,
			Detail: "password form posts to " + in.CrossOriginTarget,
		})
	}

	// Risky downloads (executables / archives / Office macros linked from the page).
	if in.RiskyDownloads > 0 {
		w := 0.25 + 0.05*float64(in.RiskyDownloads-1)
		if w > 0.55 {
			w = 0.55
		}
		signals = append(signals, Signal{
			Name:   "risky_downloads",
			Weight: w,
			Detail: itoa(in.RiskyDownloads) + " executable/archive download(s) linked, e.g. " + in.RiskyDownloadHint,
		})
	}

	// Domain age (#5).
	if in.DomainAge > 0 {
		switch {
		case in.DomainAge < 1*time.Hour:
			signals = append(signals, Signal{Name: "domain_age", Weight: 0.5, Detail: "<1h old"})
		case in.DomainAge < 24*time.Hour:
			signals = append(signals, Signal{Name: "domain_age", Weight: 0.4, Detail: "<24h old"})
		case in.DomainAge < 7*24*time.Hour:
			signals = append(signals, Signal{Name: "domain_age", Weight: 0.3, Detail: "<7d old"})
		case in.DomainAge < 30*24*time.Hour:
			signals = append(signals, Signal{Name: "domain_age", Weight: 0.2, Detail: "<30d old"})
		case in.DomainAge < 90*24*time.Hour:
			signals = append(signals, Signal{Name: "domain_age", Weight: 0.1, Detail: "<90d old"})
		case in.DomainAge > 5*365*24*time.Hour:
			signals = append(signals, Signal{Name: "domain_age", Weight: -0.05, Detail: ">5y old (mild trust)"})
		}
	}

	// External corroborators.
	if in.GSBClean != nil && !*in.GSBClean {
		signals = append(signals, Signal{Name: "gsb_unsafe", Weight: 0.6, Detail: "Google Safe Browsing flags"})
	}
	if in.VTPositives >= 3 {
		signals = append(signals, Signal{Name: "vt_positives", Weight: 0.3, Detail: itoa(in.VTPositives) + " AV engines flag"})
	}

	// Weak visual match (between WARN and BLOCK thresholds).
	if in.VisualTopScore >= VisualWarnThreshold && in.VisualTopScore < VisualBlockThreshold {
		signals = append(signals, Signal{
			Name: "visual_brand_match_weak", Weight: 0.2,
			Detail: in.VisualTopBrand + " similarity " + ftoa(in.VisualTopScore),
		})
	}

	for _, s := range signals {
		sum += s.Weight
	}

	conf := clamp(sigmoid(sum, 1.0))
	verdict := "CLEAN"
	reason := ""
	switch {
	case conf >= ScoreBlockThreshold:
		verdict = "BLOCK"
		reason = "Multiple high-risk signals exceeded block threshold."
	case conf >= ScoreWarnThreshold:
		verdict = "WARN"
	}

	return Output{
		Verdict:    verdict,
		Confidence: conf,
		Signals:    signals,
		TopBrand:   in.VisualTopBrand,
		TopScore:   in.VisualTopScore,
		Reason:     reason,
	}
}

// isImpersonation — pure-function predicate the universal rule uses.
func isImpersonation(in Inputs) bool {
	if domainOfBrand(in.Domain, in.BrandCanonicalDomains) {
		return false
	}
	// Any one of these mismatches is sufficient to indict.
	if in.DomainAge > 0 && in.DomainAge < 90*24*time.Hour {
		return true
	}
	if in.ASN != 0 && !intIn(in.ASN, in.BrandLegitimateASNs) && len(in.BrandLegitimateASNs) > 0 {
		return true
	}
	if in.CertIssuer != "" && !strIn(in.CertIssuer, in.BrandLegitimateIssuers) && len(in.BrandLegitimateIssuers) > 0 {
		return true
	}
	return false
}

func buildImpersonationReason(in Inputs) string {
	parts := []string{
		"Visually impersonates " + in.VisualTopBrand + " (" + ftoa(in.VisualTopScore) + " similarity)",
	}
	if !domainOfBrand(in.Domain, in.BrandCanonicalDomains) {
		parts = append(parts, "but " + in.Domain + " is not a canonical " + in.VisualTopBrand + " domain")
	}
	if in.DomainAge > 0 && in.DomainAge < 90*24*time.Hour {
		parts = append(parts, "domain registered "+humanizeAge(in.DomainAge)+" ago")
	}
	if in.ASN != 0 && len(in.BrandLegitimateASNs) > 0 && !intIn(in.ASN, in.BrandLegitimateASNs) {
		parts = append(parts, "hosted on AS"+itoa(in.ASN)+" (not a known "+in.VisualTopBrand+" ASN)")
	}
	if in.HasPasswordForm && in.CrossOriginPost {
		parts = append(parts, "credentials posted to "+in.CrossOriginTarget)
	}
	return strings.Join(parts, "; ") + "."
}

// --- helpers ---

func domainOfBrand(domain string, canonicals []string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, c := range canonicals {
		c = strings.ToLower(c)
		if d == c || strings.HasSuffix(d, "."+c) {
			return true
		}
	}
	return false
}

func intIn(x int, xs []int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func strIn(x string, xs []string) bool {
	xl := strings.ToLower(x)
	for _, v := range xs {
		if strings.Contains(xl, strings.ToLower(v)) {
			return true
		}
	}
	return false
}

func clamp(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func sigmoid(x, k float64) float64 {
	return 1.0 / (1.0 + math.Exp(-k*x))
}

func humanizeAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return itoa(int(d.Minutes())) + " min"
	case d < 24*time.Hour:
		return itoa(int(d.Hours())) + " h"
	case d < 30*24*time.Hour:
		return itoa(int(d.Hours()/24)) + " d"
	case d < 365*24*time.Hour:
		return itoa(int(d.Hours()/(24*30))) + " mo"
	default:
		return itoa(int(d.Hours()/(24*365))) + " y"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func ftoa(f float64) string {
	// fixed-2 formatting without fmt import overhead
	whole := int(f * 100)
	if whole < 0 {
		whole = 0
	}
	if whole > 100 {
		whole = 100
	}
	return "0." + padLeft(itoa(whole), 2)
}

func padLeft(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}
