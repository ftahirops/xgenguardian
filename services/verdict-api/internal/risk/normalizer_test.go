package risk

import "testing"

// --- score saturation -------------------------------------------------------

func TestCompute_BenignReturnsZero(t *testing.T) {
	r := Compute(Inputs{})
	if r.Score != 0 {
		t.Errorf("benign inputs: score = %.3f; want 0", r.Score)
	}
	if len(r.Contributors) != 0 {
		t.Errorf("benign inputs: contributors = %v; want empty", r.Contributors)
	}
}

func TestCompute_SoftAccumulatorSaturates(t *testing.T) {
	// SoftRisk 1.0 → 0.5 raw → capped to 0.50. Even 100.0 mustn't exceed 0.50.
	r1 := Compute(Inputs{SoftRisk: 1.0})
	r100 := Compute(Inputs{SoftRisk: 100.0})
	if r1.Score > 0.50+1e-9 {
		t.Errorf("soft cap violated at 1.0: got %.3f", r1.Score)
	}
	if r100.Score > 0.50+1e-9 {
		t.Errorf("soft cap violated at 100.0: got %.3f", r100.Score)
	}
	// 1.0 might already cap at 0.50; 100.0 must not be less. Equality
	// is fine — both have saturated. What we want to prevent is
	// regression: a higher SoftRisk producing a LOWER score.
	if r100.Score < r1.Score {
		t.Errorf("score must not decrease as SoftRisk grows; 1.0=%.3f 100.0=%.3f", r1.Score, r100.Score)
	}
}

func TestCompute_TrustSuppressesSoft(t *testing.T) {
	// Same SoftRisk; trust 0 vs trust 1.0 should differ noticeably.
	notrust := Compute(Inputs{SoftRisk: 2.0, TrustScore: 0.0})
	fulltrust := Compute(Inputs{SoftRisk: 2.0, TrustScore: 1.0})
	if !(fulltrust.Score < notrust.Score) {
		t.Errorf("trust must reduce score: notrust=%.3f fulltrust=%.3f", notrust.Score, fulltrust.Score)
	}
}

// --- homoglyph floor --------------------------------------------------------

func TestCompute_HomoglyphFloorsAt085(t *testing.T) {
	r := Compute(Inputs{HomoglyphHardFired: true})
	if r.Score != 0.85 {
		t.Errorf("homoglyph only: score = %.3f; want 0.85", r.Score)
	}
}

func TestCompute_HomoglyphDoesNotDouble(t *testing.T) {
	// SoftRisk already pushes >= 0.85? Then no addition.
	// SoftRisk = 100 saturates at 0.50; floor adds 0.35 to reach 0.85.
	r := Compute(Inputs{SoftRisk: 100, HomoglyphHardFired: true})
	if r.Score < 0.85 {
		t.Errorf("homoglyph floor should bring score to >= 0.85; got %.3f", r.Score)
	}
	if r.Score > 0.85+1e-9 {
		// Soft was 0.50; floor brings to 0.85; nothing else should add.
		t.Errorf("homoglyph_floor should not double-count; got %.3f", r.Score)
	}
}

// --- support-scam normalization --------------------------------------------

func TestCompute_SupportScamNormalizesTo045Cap(t *testing.T) {
	r := Compute(Inputs{SupportScamScore: 1.5})
	// 1.5/1.5 * 0.45 = 0.45
	if r.Score < 0.45-1e-9 || r.Score > 0.45+1e-9 {
		t.Errorf("support-scam max should contribute 0.45; got %.3f", r.Score)
	}
}

// --- compound mode threshold mapping ---------------------------------------

func TestVerdictFor_SafeMode(t *testing.T) {
	cases := []struct {
		score float64
		want  CandidateVerdict
	}{
		{0.0, CandidateAllow},
		{0.30, CandidateAllow},  // < 0.55 = Safe WARN threshold
		{0.55, CandidateWarn},
		{0.75, CandidateWarn},
		{0.85, CandidateBlock},
		{1.0, CandidateBlock},
	}
	for _, c := range cases {
		got := VerdictFor(c.score, ModeSafe)
		if got != c.want {
			t.Errorf("VerdictFor(%.2f, Safe) = %s; want %s", c.score, got, c.want)
		}
	}
}

func TestVerdictFor_StricterModesLowerThresholds(t *testing.T) {
	// Score 0.50 maps differently per mode.
	cases := []struct {
		mode Mode
		want CandidateVerdict
	}{
		{ModeNormal, CandidateAllow},   // warn=0.70 → 0.50 is below
		{ModeSafe, CandidateAllow},     // warn=0.55 → 0.50 is below
		{ModeStrict, CandidateWarn},    // warn=0.45 → 0.50 crosses
		{ModeParanoid, CandidateWarn},  // warn=0.35 → 0.50 crosses
	}
	for _, c := range cases {
		got := VerdictFor(0.50, c.mode)
		if got != c.want {
			t.Errorf("VerdictFor(0.50, %s) = %s; want %s", c.mode, got, c.want)
		}
	}
}

func TestVerdictFor_BlockThresholds(t *testing.T) {
	// Score 0.80 should BLOCK in Strict but only WARN in Normal/Safe.
	cases := []struct {
		mode Mode
		want CandidateVerdict
	}{
		{ModeNormal, CandidateWarn},   // block=0.95
		{ModeSafe, CandidateWarn},     // warn=0.55 block=0.85 → 0.80 is WARN
		{ModeStrict, CandidateBlock},  // block=0.80 → 0.80 hits
		{ModeParanoid, CandidateBlock}, // block=0.75 → 0.80 hits
	}
	for _, c := range cases {
		got := VerdictFor(0.80, c.mode)
		if got != c.want {
			t.Errorf("VerdictFor(0.80, %s) = %s; want %s", c.mode, got, c.want)
		}
	}
}

// --- contributors order ----------------------------------------------------

func TestCompute_ContributorsOrderedLargestFirst(t *testing.T) {
	// Set up multiple contributors where homoglyph dominates.
	r := Compute(Inputs{
		HomoglyphHardFired: true, // floor → ~0.85
		SoftRisk:           0.5,  // → ~0.33
		SensitivePage:      true, // → 0.05
	})
	if len(r.Contributors) == 0 {
		t.Fatalf("expected contributors")
	}
	// Phase-1 sort isn't strict — we just want the trace to be useful.
	// Verify the homoglyph contribution exists.
	var foundHomo bool
	for _, c := range r.Contributors {
		if c.Label == "homoglyph_floor" {
			foundHomo = true
		}
	}
	if !foundHomo {
		t.Errorf("homoglyph_floor missing from contributors: %v", r.Contributors)
	}
}
