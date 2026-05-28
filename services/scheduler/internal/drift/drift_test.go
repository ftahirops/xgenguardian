package drift

import "testing"

func TestCompare_NoBaseline_NoDrift(t *testing.T) {
	// First scan: stored is empty, fresh has values → not drift, just initial.
	stored := Fingerprint{}
	fresh := Fingerprint{
		CertSHA256:      "abc",
		PageFingerprint: "def",
		ASN:             13335,
	}
	triggers := Compare(stored, fresh)
	if len(triggers) != 0 {
		t.Errorf("empty stored should not produce drift, got %v", triggers)
	}
}

func TestCompare_CertChange(t *testing.T) {
	stored := Fingerprint{CertSHA256: "abc123"}
	fresh := Fingerprint{CertSHA256: "def456"}
	triggers := Compare(stored, fresh)
	if len(triggers) != 1 || triggers[0] != TCert {
		t.Errorf("expected cert drift, got %v", triggers)
	}
}

func TestCompare_MultipleDrifts(t *testing.T) {
	stored := Fingerprint{
		FinalURL: "https://a.example/x", CertSHA256: "old",
		ScriptOriginFingerprint: "s1", FormFingerprint: "f1",
	}
	fresh := Fingerprint{
		FinalURL: "https://a.example/y", CertSHA256: "new",
		ScriptOriginFingerprint: "s2", FormFingerprint: "f2",
	}
	got := Compare(stored, fresh)
	if len(got) != 4 {
		t.Errorf("expected 4 triggers, got %d: %v", len(got), got)
	}
}

func TestCompare_DownloadsAppeared(t *testing.T) {
	got := Compare(Fingerprint{LinksDownloads: false}, Fingerprint{LinksDownloads: true})
	if len(got) != 1 || got[0] != TNewDownloads {
		t.Errorf("got %v", got)
	}
	// Inverse: downloads disappearing is not a drift event for us.
	got = Compare(Fingerprint{LinksDownloads: true}, Fingerprint{LinksDownloads: false})
	if len(got) != 0 {
		t.Errorf("download removal should NOT trigger drift, got %v", got)
	}
}

func TestCompare_BrandClaimAppears(t *testing.T) {
	got := Compare(Fingerprint{}, Fingerprint{BrandClaim: "paypal"})
	if len(got) != 1 || got[0] != TBrandClaim {
		t.Errorf("got %v", got)
	}
}

func TestCompare_ASNZeroIgnored(t *testing.T) {
	// We don't have ASN data → don't false-trigger.
	got := Compare(Fingerprint{ASN: 0}, Fingerprint{ASN: 1234})
	for _, tt := range got {
		if tt == THostingASN {
			t.Errorf("ASN drift should not fire when stored ASN unknown")
		}
	}
}

func TestEscalateTo(t *testing.T) {
	cases := []struct {
		in   []Trigger
		want Tier
	}{
		{nil, TierLight},
		{[]Trigger{TPage}, TierMedium},
		{[]Trigger{TRedirectChain, THostingASN}, TierMedium},
		{[]Trigger{TCert}, TierDeep},
		{[]Trigger{TPage, TForm}, TierDeep},      // form drift → deep
		{[]Trigger{TScriptOrigin}, TierDeep},
		{[]Trigger{TBrandClaim}, TierDeep},
		{[]Trigger{TNewDownloads}, TierDeep},
	}
	for _, c := range cases {
		if got := EscalateTo(c.in); got != c.want {
			t.Errorf("EscalateTo(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}
