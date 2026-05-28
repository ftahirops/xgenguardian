// Package drift detects material change between a stored page fingerprint
// and a freshly-scanned one (UNIFIED-PLAN.md §4.3). When any of the eight
// drift triggers fires, the scheduler forces a revalidation tier-up
// (light → medium → deep) and re-grades the URL.
package drift

import "strings"

// Fingerprint groups the per-URL fingerprint columns from `urls` plus the
// per-domain values from `domains`. All fields are nullable (empty string
// or 0 means "unknown").
type Fingerprint struct {
	FinalURL           string
	RedirectFingerprint string
	CertSHA256         string
	PageFingerprint    string // title + favicon hash
	FormFingerprint    string
	ScriptOriginFingerprint string
	ASN                int
	LinksDownloads     bool   // page now offers downloads where it didn't before
	BrandClaim         string // brand the page claims to be (empty if none)
	FeedHit            bool   // a TI feed entry now exists for the domain
}

// Trigger is a single drift cause. Matches the spec's eight-or-so trigger
// conditions plus a couple of extras (script_origin, ASN).
type Trigger string

const (
	TFinalURL        Trigger = "final_url_change"
	TRedirectChain   Trigger = "redirect_chain_change"
	TCert            Trigger = "cert_drift"
	TPage            Trigger = "title_favicon_drift"
	TForm            Trigger = "form_action_drift"
	TScriptOrigin    Trigger = "script_origin_drift"
	THostingASN      Trigger = "hosting_asn_change"
	TNewDownloads    Trigger = "new_downloads_appeared"
	TBrandClaim      Trigger = "new_brand_claim"
	TFeedHit         Trigger = "new_feed_hit"
)

// Compare returns the set of triggers that fired between stored and fresh.
// An empty result means no material drift — light revalidation is enough.
func Compare(stored, fresh Fingerprint) []Trigger {
	var out []Trigger

	if differs(stored.FinalURL, fresh.FinalURL) {
		out = append(out, TFinalURL)
	}
	if differs(stored.RedirectFingerprint, fresh.RedirectFingerprint) {
		out = append(out, TRedirectChain)
	}
	if differs(stored.CertSHA256, fresh.CertSHA256) {
		out = append(out, TCert)
	}
	if differs(stored.PageFingerprint, fresh.PageFingerprint) {
		out = append(out, TPage)
	}
	if differs(stored.FormFingerprint, fresh.FormFingerprint) {
		out = append(out, TForm)
	}
	if differs(stored.ScriptOriginFingerprint, fresh.ScriptOriginFingerprint) {
		out = append(out, TScriptOrigin)
	}
	if stored.ASN != 0 && fresh.ASN != 0 && stored.ASN != fresh.ASN {
		out = append(out, THostingASN)
	}
	if !stored.LinksDownloads && fresh.LinksDownloads {
		out = append(out, TNewDownloads)
	}
	if stored.BrandClaim == "" && fresh.BrandClaim != "" {
		out = append(out, TBrandClaim)
	}
	if !stored.FeedHit && fresh.FeedHit {
		out = append(out, TFeedHit)
	}
	return out
}

// differs reports whether two fingerprint strings have meaningfully changed.
// Empty stored value means "no baseline yet" — not a drift event.
func differs(stored, fresh string) bool {
	s := strings.TrimSpace(stored)
	f := strings.TrimSpace(fresh)
	if s == "" {
		return false
	}
	return s != f
}

// Tier — revalidation tier the scheduler should run on a re-visit.
//
//	light  : fingerprint diff only (URL/DNS/cert/headers). ~10ms.
//	medium : HTML fetch + DOM-lite parse. ~200ms.
//	deep   : full Playwright sandbox + behavioral + downloads. 2-10s.
type Tier int

const (
	TierLight  Tier = 1
	TierMedium Tier = 2
	TierDeep   Tier = 3
)

func (t Tier) String() string {
	switch t {
	case TierLight:
		return "light"
	case TierMedium:
		return "medium"
	case TierDeep:
		return "deep"
	}
	return "unknown"
}

// EscalateTo decides the minimum tier to run given the triggers that fired.
//
//   - Any of cert / script_origin / form drift on a trusted page is severe
//     enough to deserve a deep re-scan: these are the compromise indicators
//     and they need full behavioural + form-action analysis to confirm.
//   - Brand-claim appearance and new-downloads also go deep: the brand or
//     download is the point of the attack.
//   - Title/favicon drift, redirect-chain drift, ASN change → medium.
//   - No triggers → caller can stay on light revalidation.
func EscalateTo(triggers []Trigger) Tier {
	if len(triggers) == 0 {
		return TierLight
	}
	deep := map[Trigger]struct{}{
		TCert: {}, TScriptOrigin: {}, TForm: {}, TBrandClaim: {},
		TNewDownloads: {}, TFeedHit: {},
	}
	for _, t := range triggers {
		if _, ok := deep[t]; ok {
			return TierDeep
		}
	}
	return TierMedium
}
