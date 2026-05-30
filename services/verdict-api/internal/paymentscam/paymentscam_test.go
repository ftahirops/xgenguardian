package paymentscam

import (
	"strings"
	"testing"
)

// --- Smoke-corpus failing case ---

func TestScore_SmokeCorpus_WireFraudIRS(t *testing.T) {
	// Smoke corpus URL: irs-tax-refund-direct-deposit.example/file
	r := Score(Inputs{
		URL: "https://irs-tax-refund-direct-deposit.example/file",
		SLD: "irs-tax-refund-direct-deposit",
	})
	if r.Score < ThresholdWarn {
		t.Errorf("IRS-tax-refund SLD must at least WARN; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
	}
}

// --- Per-category baselines ---

func TestScore_GiftCardScam(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Please pay using Apple gift card. Scratch off the back and send us the code.",
	})
	if !hasCategory(r.Hits, CatGiftCardScam) {
		t.Errorf("expected CatGiftCardScam hits; got %s", summarise(r.Hits))
	}
	// Cap is 0.35 — single category alone reaches WARN but not BLOCK.
	// By design: BLOCK needs corroboration across categories. Two
	// gift-card phrases together with wire-fraud or tax-refund pretext
	// cross BLOCK (covered by Composite test).
	if r.Score < ThresholdWarn {
		t.Errorf("two gift-card phrases should cross WARN; got %.3f", r.Score)
	}
}

func TestScore_WireFraud(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Send via Western Union urgent wire transfer immediately",
	})
	if !hasCategory(r.Hits, CatWireFraud) {
		t.Errorf("expected wire-fraud hits")
	}
}

func TestScore_TaxRefundScam(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Claim your refund. Your IRS refund check of $1,800 is pending direct deposit.",
	})
	if !hasCategory(r.Hits, CatTaxRefundScam) {
		t.Errorf("expected tax-refund hits")
	}
}

func TestScore_LotteryScam(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Congratulations you have won the powerball winner draw. Claim your prize.",
	})
	if !hasCategory(r.Hits, CatLotteryScam) {
		t.Errorf("expected lottery-scam hits")
	}
}

func TestScore_FakeInvoice(t *testing.T) {
	r := Score(Inputs{
		VisibleText: "Geek Squad — your subscription was renewed. Please pay this invoice.",
	})
	if !hasCategory(r.Hits, CatFakeInvoice) {
		t.Errorf("expected fake-invoice hits")
	}
}

// --- Government impersonation respects brandgraph ---

func TestScore_GovImpersonation_HostInBrandgraph_DoesNotFire(t *testing.T) {
	r := Score(Inputs{
		URL:              "https://irs.gov/refunds/where-is-my-refund",
		VisibleText:      "Track your federal refund. The IRS will direct deposit your refund.",
		Host:             "irs.gov",
		HostInBrandgraph: true,
	})
	if hasCategory(r.Hits, CatGovImpersonation) {
		t.Errorf("gov-impersonation must NOT fire when host is in brandgraph")
	}
}

func TestScore_GovImpersonation_HostNotInBrandgraph_Fires(t *testing.T) {
	r := Score(Inputs{
		URL:              "https://irs-refund-claim.example/file",
		SLD:              "irs-refund-claim",
		VisibleText:      "Your social security number suspended. Pay outstanding unpaid taxes immediately.",
		Host:             "irs-refund-claim.example",
		HostInBrandgraph: false,
	})
	if !hasCategory(r.Hits, CatGovImpersonation) {
		t.Errorf("gov-impersonation must fire on non-brandgraph host")
	}
}

// --- SLD-composite bonus catches URL-only scams ---

func TestScore_SLDComposite_PaymentMethodPlusPretext(t *testing.T) {
	r := Score(Inputs{
		URL: "https://gift-card-refund-claim.example/redeem",
		SLD: "gift-card-refund-claim",
	})
	if r.Score < ThresholdWarn {
		t.Errorf("SLD composite (gift-card + refund + claim) must WARN; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
	}
}

func TestScore_SLDComposite_TwoPretextTokens(t *testing.T) {
	// Pretext-only: tax-refund + claim in SLD without explicit payment
	// method — still a strong signal.
	r := Score(Inputs{
		URL: "https://tax-refund-claim-portal.example/",
		SLD: "tax-refund-claim-portal",
	})
	if r.Score < ThresholdWarn {
		t.Errorf("two-pretext SLD must WARN; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
	}
}

// --- Composite scam crosses HardBlock ---

func TestScore_Composite_CrossesHardBlock(t *testing.T) {
	r := Score(Inputs{
		URL: "https://irs-refund-claim.example/",
		SLD: "irs-refund-claim",
		VisibleText: "Congratulations you have won! " +
			"Your IRS refund check of $5,000 is waiting. " +
			"Please pay processing fee via Apple gift card. " +
			"Scratch off the back and send us the code via Western Union.",
		Host: "irs-refund-claim.example",
	})
	if r.Score < ThresholdHardBlock {
		t.Errorf("composite scam should cross HardBlock %.2f; got %.3f. Hits: %s",
			ThresholdHardBlock, r.Score, summarise(r.Hits))
	}
}

// --- Cap prevents single category from dominating ---

func TestScore_GiftCardRepeated_Capped(t *testing.T) {
	r := Score(Inputs{
		VisibleText: strings.Repeat("Apple gift card. ", 50),
	})
	var cat float64
	for _, h := range r.Hits {
		if h.Category == CatGiftCardScam {
			cat += h.Weight
		}
	}
	if cat > 0.35+1e-9 {
		t.Errorf("gift-card cap violated: got %.3f want <= 0.35", cat)
	}
}

// --- Benign content does NOT fire ---

func TestScore_BenignWikipediaArticle_BelowThreshold(t *testing.T) {
	r := Score(Inputs{
		URL:   "https://en.wikipedia.org/wiki/Gift_card",
		Title: "Gift card - Wikipedia",
		VisibleText: "A gift card is a prepaid stored-value money card. " +
			"They are typically issued by a retailer. This article explains " +
			"the history and economics of gift cards.",
		Host:             "wikipedia.org",
		HostInBrandgraph: true,
	})
	if r.Score >= ThresholdWarn {
		t.Errorf("benign Wikipedia content should not cross WARN; got %.3f. Hits: %s",
			r.Score, summarise(r.Hits))
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
