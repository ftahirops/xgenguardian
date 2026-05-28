package fusion

import (
	"testing"
	"time"
)

func TestUniversalRule_BlocksLookalike(t *testing.T) {
	in := Inputs{
		Domain:                "w1thineartht.com",
		VisualTopBrand:        "withinearth",
		VisualTopScore:        0.96,
		BrandCanonicalDomains: []string{"withinearth.com"},
		DomainAge:             4 * 24 * time.Hour,
		HasPasswordForm:       true,
		CrossOriginPost:       true,
		CrossOriginTarget:     "https://collect.evil-c2.tk/api",
	}
	out := Score(in)
	if out.Verdict != "BLOCK" {
		t.Fatalf("expected BLOCK, got %q (conf=%.2f)", out.Verdict, out.Confidence)
	}
	if out.Confidence < 0.85 {
		t.Fatalf("expected high confidence, got %.2f", out.Confidence)
	}
}

func TestUniversalRule_AllowsCanonicalDomain(t *testing.T) {
	in := Inputs{
		Domain:                "withinearth.com",
		VisualTopBrand:        "withinearth",
		VisualTopScore:        0.99,
		BrandCanonicalDomains: []string{"withinearth.com"},
		DomainAge:             5 * 365 * 24 * time.Hour,
	}
	out := Score(in)
	if out.Verdict == "BLOCK" {
		t.Fatalf("canonical domain should not be blocked; got BLOCK %q", out.Reason)
	}
}

func TestBlocklistShortCircuit(t *testing.T) {
	out := Score(Inputs{Domain: "evil.tk", BlocklistHit: true})
	if out.Verdict != "BLOCK" || out.Confidence != 1.0 {
		t.Fatalf("blocklist hit should BLOCK with confidence 1.0; got %q %.2f", out.Verdict, out.Confidence)
	}
}

func TestWeakVisualMatch_RaisesWarn(t *testing.T) {
	in := Inputs{
		Domain:         "newish-site.com",
		VisualTopBrand: "github",
		VisualTopScore: 0.85,
		DomainAge:      20 * 24 * time.Hour,
	}
	out := Score(in)
	if out.Verdict == "BLOCK" {
		t.Fatalf("weak visual match shouldn't auto-block, got BLOCK")
	}
}

func TestCleanForOldDomain(t *testing.T) {
	in := Inputs{
		Domain:    "anthropic.com",
		DomainAge: 10 * 365 * 24 * time.Hour,
	}
	out := Score(in)
	if out.Verdict != "CLEAN" {
		t.Fatalf("expected CLEAN, got %q", out.Verdict)
	}
}
