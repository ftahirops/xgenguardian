package httpgw

import (
	"reflect"
	"testing"

	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

func TestCodesFromFusion_MapsKnownSignals(t *testing.T) {
	out := fusion.Output{Signals: []fusion.Signal{
		{Name: "visual_brand_match", Weight: 0.7},
		{Name: "domain_age",         Weight: 0.4},
		{Name: "homoglyph",          Weight: 0.3},
		{Name: "unknown_signal",     Weight: 0.1}, // dropped silently
	}}
	got := codesFromFusion(out)
	want := []string{
		string(reasons.BrandClaimDomainMismatch),
		string(reasons.DomainAgeUnderThreshold),
		string(reasons.HomoglyphOfProtectedBrand),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestCodesFromFusion_YaraPrefixFallsBackToGeneric(t *testing.T) {
	out := fusion.Output{Signals: []fusion.Signal{
		{Name: "yara_xgg_clickfix_instructions", Weight: 0.5},
	}}
	got := codesFromFusion(out)
	if len(got) != 1 || got[0] != string(reasons.YaraSignatureMatch) {
		t.Errorf("yara_ prefix should fall back to YaraSignatureMatch; got %v", got)
	}
}

func TestCodesFromFusion_Dedups(t *testing.T) {
	out := fusion.Output{Signals: []fusion.Signal{
		{Name: "visual_brand_match"},
		{Name: "identity_mismatch"}, // also maps to BrandClaimDomainMismatch
	}}
	got := codesFromFusion(out)
	if len(got) != 1 || got[0] != string(reasons.BrandClaimDomainMismatch) {
		t.Errorf("duplicate codes should be dedup'd; got %v", got)
	}
}

func TestCodesFromYaraMatches_UsesRuleDeclaredCode(t *testing.T) {
	matches := []yaraMatch{
		{Rule: "xgg_clickfix_instructions", ReasonCode: string(reasons.ClipboardHijackAttempt)},
		{Rule: "xgg_magecart_card_field_listener", ReasonCode: string(reasons.FormPostsToUnrelatedDomain)},
		{Rule: "xgg_cryptojacker_known_libs", ReasonCode: string(reasons.MinerPoolContact)},
	}
	got := codesFromYaraMatches(matches)
	want := []string{
		string(reasons.ClipboardHijackAttempt),
		string(reasons.FormPostsToUnrelatedDomain),
		string(reasons.MinerPoolContact),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestCodesFromYaraMatches_UnknownCodeFallsBack(t *testing.T) {
	matches := []yaraMatch{
		{Rule: "xgg_made_up_rule", ReasonCode: "MADE_UP_CODE_NOT_REGISTERED"},
		{Rule: "xgg_no_code_at_all", ReasonCode: ""},
	}
	got := codesFromYaraMatches(matches)
	if len(got) != 1 || got[0] != string(reasons.YaraSignatureMatch) {
		t.Errorf("expected single fallback YaraSignatureMatch (dedup'd); got %v", got)
	}
}

func TestYaraWeight_BySeverity(t *testing.T) {
	cases := map[string]float64{
		"critical":  0.7,
		"high":      0.5,
		"medium":    0.3,
		"low":       0.15,
		"CRITICAL":  0.7, // case-insensitive
		"":          0.25,
		"bogus":     0.25,
	}
	for sev, want := range cases {
		if got := yaraWeight(sev); got != want {
			t.Errorf("yaraWeight(%q) = %v, want %v", sev, got, want)
		}
	}
}
