package httpgw

import "testing"

// Wave 2 — Tier-2 dispatch tuning. shouldRunTier2 now considers
// piracy-favored ccTLDs (.to/.ws/.cc/.pw) as suspicious so the
// uflix.to-class URLs actually reach the sandbox instead of fast-
// pathing to ALLOW on a low Tier-1 score.

func TestShouldRunTier2_PiracyTLDs_Fire(t *testing.T) {
	cases := []struct {
		url  string
		want bool
		why  string
	}{
		{"https://uflix.to/", true, "Tongan ccTLD heavily abused for piracy streaming"},
		{"https://soap2day.to/movies", true, ".to streaming-piracy class"},
		{"https://example.ws/", true, "Samoan ccTLD spam-favored"},
		{"https://something.cc/path", true, ".cc ccTLD widely abused"},
		{"https://anything.pw/", true, ".pw spam/scam-favored"},
		// Negative: legitimate gTLD ordinary site MUST NOT force Tier-2
		// from this branch alone (other rules might still escalate; this
		// test only asserts that .com/.org/.net don't auto-Tier-2 from
		// the TLD branch).
		{"https://example.com/", false, ".com ordinary site → use other signals"},
		{"https://example.org/", false, ".org ordinary site → use other signals"},
		{"https://example.net/", false, ".net ordinary site → use other signals"},
	}
	for _, c := range cases {
		got := shouldRunTier2(0.0, c.url)
		if got != c.want {
			t.Errorf("shouldRunTier2(%q) = %v; want %v (%s)", c.url, got, c.want, c.why)
		}
	}
}

// .gov/.edu legitimate sites — even with .cc-style multi-part endings,
// the test should isolate the ccTLD branch and not the keyword branch.
// keep this as a positive-control just to confirm the previous rules
// still fire as they did before.
func TestShouldRunTier2_LegacyPaths_StillFire(t *testing.T) {
	for _, u := range []string{
		"https://anything.tk/",  // Freenom-class still fires
		"https://thing.click/x", // .click still fires
		"https://example.com/login", // keyword branch
		"https://1.2.3.4/x86",   // raw IP
	} {
		if !shouldRunTier2(0.0, u) {
			t.Errorf("legacy path should still force Tier-2: %s", u)
		}
	}
}
