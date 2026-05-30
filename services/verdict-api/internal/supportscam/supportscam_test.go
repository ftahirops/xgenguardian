package supportscam

import (
	"strings"
	"testing"
)

// --- Smoke-corpus failing cases (the headline reason this package exists) -----

func TestScore_SmokeCorpusFailingCases(t *testing.T) {
	cases := []struct {
		name    string
		in      Inputs
		wantMin float64
	}{
		{
			name: "microsoft-support-helpline",
			in: Inputs{
				URL: "https://microsoft-support-helpline.example/call",
				SLD: "microsoft-support-helpline",
				// Host not in brandgraph
			},
			wantMin: ThresholdWarn, // must at least WARN
		},
		{
			name: "apple-virus-alert-help",
			in: Inputs{
				URL: "https://apple-virus-alert-help.example/",
				SLD: "apple-virus-alert-help",
			},
			wantMin: ThresholdWarn,
		},
		{
			name: "windows-defender-warning",
			in: Inputs{
				URL: "https://windows-defender-warning.example/contact",
				SLD: "windows-defender-warning",
			},
			wantMin: ThresholdWarn,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Score(c.in)
			if r.Score < c.wantMin {
				t.Errorf("score = %.3f; want >= %.3f. Hits: %s", r.Score, c.wantMin, summarise(r.Hits))
			}
		})
	}
}

// --- Per-category baseline -----------------------------------------------------

func TestScore_PaymentDemand_GiftCard(t *testing.T) {
	r := Score(Inputs{
		URL:         "https://example.com/contact",
		VisibleText: "Please pay using Apple gift card or Google Play card",
	})
	if r.Score == 0 {
		t.Fatalf("payment-demand category must fire on 'apple gift card'")
	}
	if !hasCategory(r.Hits, CatPaymentDemand) {
		t.Errorf("expected CatPaymentDemand hit; got %s", summarise(r.Hits))
	}
}

func TestScore_RemoteTool_AnyDesk(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Please install AnyDesk so we can assist you",
	})
	if !hasCategory(r.Hits, CatRemoteTool) {
		t.Errorf("expected CatRemoteTool hit; got %s", summarise(r.Hits))
	}
}

func TestScore_Scareware(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Your computer is infected. Do not turn off your computer.",
	})
	if !hasCategory(r.Hits, CatScareware) {
		t.Errorf("expected CatScareware hit")
	}
	if r.Score < ThresholdWarn {
		t.Errorf("two scareware phrases should cross WARN; got %.3f", r.Score)
	}
}

func TestScore_GovImpersonation_IRS(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "You have unpaid taxes. The IRS will issue an arrest warrant.",
	})
	if !hasCategory(r.Hits, CatGovImpersonation) {
		t.Errorf("expected gov-impersonation hits")
	}
}

// --- Brand-impersonation escape via brandgraph membership ---------------------

func TestScore_BrandImpersonation_HostInBrandgraph_DoesNotFire(t *testing.T) {
	r := Score(Inputs{
		URL:              "https://support.microsoft.com/help",
		Title:            "Microsoft Support",
		Host:             "support.microsoft.com",
		HostInBrandgraph: true,
	})
	if hasCategory(r.Hits, CatBrandImpersonation) {
		t.Errorf("brand-impersonation must NOT fire when host is in brandgraph")
	}
}

func TestScore_BrandImpersonation_HostNotInBrandgraph_Fires(t *testing.T) {
	r := Score(Inputs{
		URL:              "https://fake-microsoft-support.example/help",
		Title:            "Microsoft Support",
		SLD:              "fake-microsoft-support",
		Host:             "fake-microsoft-support.example",
		HostInBrandgraph: false,
	})
	if !hasCategory(r.Hits, CatBrandImpersonation) {
		t.Errorf("brand-impersonation must fire on non-brandgraph host")
	}
}

// --- Composite scam crosses HardBlock --------------------------------------

func TestScore_CompositeScam_CrossesHardBlock(t *testing.T) {
	r := Score(Inputs{
		URL:   "https://microsoft-support-helpline.example/",
		SLD:   "microsoft-support-helpline",
		Title: "Microsoft Support — Virus Detected",
		VisibleText: "Your computer is infected. " +
			"Please call us at 1-800-555-0100. " +
			"Install AnyDesk so our technician can fix this. " +
			"Pay with Apple gift card.",
		Host: "microsoft-support-helpline.example",
	})
	if r.Score < ThresholdHardBlock {
		t.Errorf("composite scam should cross HardBlock %.2f; got %.3f. Hits: %s",
			ThresholdHardBlock, r.Score, summarise(r.Hits))
	}
}

// --- Per-category capping prevents runaway -----------------------------------

func TestScore_RepeatedPhrasesCapped(t *testing.T) {
	// Stuffing the same scareware phrase many times must not let
	// scareware alone exceed its 0.30 cap.
	repeated := strings.Repeat("Your computer is infected. ", 50)
	r := Score(Inputs{VisibleText: repeated})
	// Sum of scareware contributions must not exceed cap 0.30.
	var cat float64
	for _, h := range r.Hits {
		if h.Category == CatScareware {
			cat += h.Weight
		}
	}
	if cat > 0.30+1e-9 {
		t.Errorf("scareware cap violated: got %.3f want <= 0.30", cat)
	}
}

// --- Score below threshold for ordinary content ------------------------------

func TestScore_BenignContent_ReturnsZero(t *testing.T) {
	r := Score(Inputs{
		URL:         "https://en.wikipedia.org/wiki/Phishing",
		Title:       "Phishing - Wikipedia",
		VisibleText: "Phishing is a type of social engineering attack...",
	})
	// Wikipedia article ABOUT phishing legitimately discusses these
	// terms. We do NOT want false positives. Score should stay below
	// WARN — none of the scareware/payment/remote-tool phrases appear.
	if r.Score >= ThresholdWarn {
		t.Errorf("benign Wikipedia content scored %.3f; should be < %.3f. Hits: %s",
			r.Score, ThresholdWarn, summarise(r.Hits))
	}
}

// --- Determinism (sort order stable) -----------------------------------------

func TestScore_HitsSortedByWeightDesc(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Your computer is infected. Please install AnyDesk. Pay with apple gift card.",
	})
	for i := 1; i < len(r.Hits); i++ {
		if r.Hits[i].Weight > r.Hits[i-1].Weight {
			t.Errorf("hits not sorted by weight desc")
		}
	}
}

// --- helpers ---

func hasCategory(hits []Hit, cat Category) bool {
	for _, h := range hits {
		if h.Category == cat {
			return true
		}
	}
	return false
}

func summarise(hits []Hit) string {
	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		parts = append(parts, string(h.Category)+":"+h.Phrase)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
