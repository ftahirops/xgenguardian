package trustscore

import "testing"

func TestScore_NoSignals_NeutralLow(t *testing.T) {
	r := Score(Signals{})
	if r.Score != 0.30 {
		t.Errorf("zero signals should yield neutral 0.30; got %f", r.Score)
	}
	if len(r.Contributors) != 0 {
		t.Errorf("zero signals should produce no contributors; got %+v", r.Contributors)
	}
}

func TestScore_EstablishedCleanBrand_High(t *testing.T) {
	// A canonical brand domain that's old, clean, with valid HTTPS,
	// known org membership. Should land high but never above 1.0.
	r := Score(Signals{
		DomainAgeDays:        365 * 12,
		DomainAgeKnown:       true,
		FeedClean:            true,
		VendorDNSClean:       true,
		BrandgraphFullTrust:  true,
		OrggraphKnown:        true,
		HTTPSValid:           true,
		HistoricalCleanCount: 50,
	})
	if r.Score < 0.85 {
		t.Errorf("established clean brand should score ≥ 0.85; got %f (contribs=%v)", r.Score, r.Contributors)
	}
	if r.Score > 1.0 {
		t.Errorf("score must be clamped to 1.0; got %f", r.Score)
	}
}

func TestScore_FreshUnknown_Subtracts(t *testing.T) {
	r := Score(Signals{
		DomainAgeDays:  5,
		DomainAgeKnown: true,
	})
	if r.Score >= 0.30 {
		t.Errorf("fresh unknown domain should score below neutral; got %f", r.Score)
	}
}

func TestScore_ClampedNonNegative(t *testing.T) {
	// Stack every negative we have; result must clamp at 0.0.
	r := Score(Signals{DomainAgeDays: 1, DomainAgeKnown: true})
	if r.Score < 0.0 {
		t.Errorf("score must never go negative; got %f", r.Score)
	}
}

func TestScore_ScopedTrustWorthLessThanFullTrust(t *testing.T) {
	full := Score(Signals{BrandgraphFullTrust: true})
	scoped := Score(Signals{BrandgraphAnyScope: true})
	if scoped.Score >= full.Score {
		t.Errorf("scoped trust should score lower than full trust; full=%f scoped=%f", full.Score, scoped.Score)
	}
}

func TestScore_FullTrustSuppressesScopedDouble(t *testing.T) {
	// A host that's both full-trust and scoped-trust must not double-count
	// brand membership.
	r := Score(Signals{BrandgraphFullTrust: true, BrandgraphAnyScope: true})
	// Only one "brand" label should appear.
	count := 0
	for _, c := range r.Contributors {
		if c.Label == "curated brand domain" || c.Label == "known scoped brand relationship" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("brand membership should add exactly once; got %d contribs", count)
	}
}

func TestScore_HistoricalCleanCappedAt50(t *testing.T) {
	r50 := Score(Signals{HistoricalCleanCount: 50})
	r500 := Score(Signals{HistoricalCleanCount: 500})
	if r50.Score != r500.Score {
		t.Errorf("historical-clean cap should produce equal scores at 50 and 500; got %f vs %f", r50.Score, r500.Score)
	}
}

func TestScore_ContributorsExplainTheNumber(t *testing.T) {
	// Every nonzero score component must show up in Contributors so the
	// evidence UI can show "trust came from X, Y, Z."
	r := Score(Signals{
		DomainAgeDays:       365 * 4,
		DomainAgeKnown:      true,
		FeedClean:           true,
		BrandgraphFullTrust: true,
	})
	wantLabels := map[string]bool{
		"domain age ≥ 3 years": false,
		"no threat-feed hits":  false,
		"curated brand domain": false,
	}
	for _, c := range r.Contributors {
		if _, ok := wantLabels[c.Label]; ok {
			wantLabels[c.Label] = true
		}
	}
	for label, seen := range wantLabels {
		if !seen {
			t.Errorf("expected contributor %q; got %v", label, r.Contributors)
		}
	}
}
