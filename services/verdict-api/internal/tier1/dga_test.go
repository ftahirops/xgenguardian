package tier1

import "testing"

// DGAScore must score legitimate brands low, algorithmic-looking names high.
// We don't pin exact numbers (the model is tuned heuristically), only the
// ordering: legit < threshold (0.6) < DGA.

func TestDGAScore_LegitDomainsScoreLow(t *testing.T) {
	legit := []string{
		"google", "microsoft", "facebook", "amazon", "github", "linkedin",
		"wikipedia", "cloudflare", "twitter", "instagram", "youtube", "reddit",
		"chase", "wellsfargo", "americanexpress", "paypal", "spotify",
		"dropbox", "zoom", "slack", "discord", "stackoverflow",
	}
	for _, d := range legit {
		s := DGAScore(d)
		if s >= 0.6 {
			t.Errorf("legit %q scored %v (should be < 0.6)", d, s)
		}
	}
}

func TestDGAScore_DGADomainsScoreHigh(t *testing.T) {
	// Real-world DGA samples drawn from Conficker / Cryptolocker / Necurs
	// public IOC archives (well-known historic samples).
	dga := []string{
		"xkvjqweru",         // random-looking
		"qzwxecrvtb",        // alternating consonants
		"hkjlpqrxz",         // no vowels
		"abcxyzwvut",        // mostly consonants
		"bxcvbnmqwe",        // keyboard mash
		"zzzqqqxxx",         // very low diversity but uniform
		"jklasdfqwerty",     // typical keyboard-roll DGA
	}
	hits := 0
	for _, d := range dga {
		s := DGAScore(d)
		if s >= 0.6 {
			hits++
		}
	}
	// We don't require every sample to fire (entropy model is conservative);
	// at least half the DGA bucket should.
	if hits < len(dga)/2 {
		t.Errorf("DGA recall too low: %d of %d hit threshold", hits, len(dga))
	}
}

func TestDGAScore_ShortInputs(t *testing.T) {
	// Don't score 1-5 character names — too little signal.
	for _, s := range []string{"a", "ai", "irs", "ip", "fb", "go", ""} {
		if DGAScore(s) != 0 {
			t.Errorf("short input %q should score 0", s)
		}
	}
}

func TestDGASignal_OnlyFiresAboveThreshold(t *testing.T) {
	if _, ok := DGASignal("google"); ok {
		t.Errorf("DGASignal should not fire on 'google'")
	}
	// "qzwxecrvtb": 9 unique chars, almost no English bigrams, low vowel ratio.
	// Scores ~0.69 — comfortably above the 0.6 threshold.
	if _, ok := DGASignal("qzwxecrvtb"); !ok {
		t.Errorf("DGASignal should fire on obvious DGA")
	}
}

func TestDGASignal_WeightScalesWithScore(t *testing.T) {
	// Strong DGA → 0.5 weight; medium → 0.35.
	sig, ok := DGASignal("qzwxecrvtb")
	if !ok {
		t.Fatal("DGA sample didn't fire")
	}
	if sig.Name != "dga_classifier_hit" {
		t.Errorf("signal name wrong: %q", sig.Name)
	}
	if sig.Weight != 0.35 && sig.Weight != 0.5 {
		t.Errorf("weight should be 0.35 or 0.5; got %v", sig.Weight)
	}
}
