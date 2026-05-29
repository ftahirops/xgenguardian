package trustreg

import (
	"os"
	"testing"
)

func TestIsTrusted(t *testing.T) {
	cases := []struct {
		host    string
		trusted bool
	}{
		// Exact hosts from the registry — must trust.
		{"login.microsoftonline.com", true},
		{"accounts.google.com", true},
		{"github.com", true},
		{"www.amazon.com", true},
		{"amazon.com", true},
		{"login.live.com", true},
		{"appleid.apple.com", true},
		{"checkout.stripe.com", true},
		{"www.chase.com", true},
		{"x.com", true},
		{"twitter.com", true},

		// Suffix-trusted (paypal, slack, atlassian).
		{"some-tenant.atlassian.net", true},
		{"my-org.slack.com", true},
		{"www.paypal.com", true},

		// Case + trailing dot normalization.
		{"WWW.AMAZON.COM", true},
		{"amazon.com.", true},

		// Phishing-style spoofs — must NOT trust.
		{"amazon.com.attacker.tld", false},
		{"login.microsoftonline.com.evil.tld", false},
		{"chase.com.signin.example", false},
		{"amazon-secure.com", false},
		{"paypal-account.com", false},

		// Shared-hosting (handled separately, NOT in trustreg).
		{"sites.google.com", false},
		{"storage.googleapis.com", false},
		{"firebaseapp.com", false},

		// Empty / garbage.
		{"", false},
		{"...", false},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got := IsTrusted(tc.host)
			if got != tc.trusted {
				t.Errorf("IsTrusted(%q) = %v, want %v", tc.host, got, tc.trusted)
			}
		})
	}
}

func TestBrandFor(t *testing.T) {
	cases := map[string]string{
		"accounts.google.com":       "google",
		"login.microsoftonline.com": "microsoft",
		"github.com":                "microsoft", // github is Microsoft-owned in our map
		"www.amazon.com":            "amazon",
		"checkout.stripe.com":       "stripe",
		"my-org.slack.com":          "slack",
		"random.unknown.tld":        "",
	}
	for host, want := range cases {
		if got := BrandFor(host); got != want {
			t.Errorf("BrandFor(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestSizeReasonable(t *testing.T) {
	if Size() < 50 {
		t.Errorf("trust registry suspiciously small: %d entries", Size())
	}
}

// --- XGG_LOCAL_TRUSTED_HOSTS validation (Fix 5) ---

func TestIsValidLocalEntry(t *testing.T) {
	cases := []struct {
		entry string
		valid bool
	}{
		// Valid suffix entries
		{".example.com", true},
		{".mail.example.com", true},
		{".internal.corp.example", true},

		// Invalid suffix entries — too broad or too short
		{".com", false},        // single segment
		{".co.uk", false},      // SLD only 2 chars "co" — rejected as TLD pair
		{".uk", false},         // single segment
		{".a", false},          // length < 5
		{".x.y", false},        // SLD "x" is only 1 char

		// Wildcard in suffix or exact
		{"*.example.com", false},
		{".*.example.com", false},

		// Valid exact entries
		{"mail.example.com", true},
		{"intranet.corp.example", true},

		// Invalid exact entries
		{"intranet", false},    // no dot
		{"in tra.net", false},  // space
		{"bad_chars!.com", false},
	}

	for _, tc := range cases {
		got := isValidLocalEntry(tc.entry)
		if got != tc.valid {
			t.Errorf("isValidLocalEntry(%q) = %v, want %v", tc.entry, got, tc.valid)
		}
	}
}

// TestLoadLocalEntries_InvalidsSkipped verifies that an overly-broad suffix
// like ".com" in XGG_LOCAL_TRUSTED_HOSTS is silently skipped and does NOT
// end up in the suffix match list (which would trust all .com domains).
func TestLoadLocalEntries_InvalidsSkipped(t *testing.T) {
	// Backup and restore state around the test.
	origHostSet := hostMatchSet
	origSuffixList := suffixMatchList
	t.Cleanup(func() {
		hostMatchSet = origHostSet
		suffixMatchList = origSuffixList
	})

	// Re-init with a fresh map so we can inspect additions cleanly.
	hostMatchSet = make(map[string]string)
	suffixMatchList = nil

	t.Setenv("XGG_LOCAL_TRUSTED_HOSTS", ".com,.example.com,no-dot,mail.valid.example")
	loadLocalEntries()

	// ".com" should NOT be in the suffix list.
	for _, s := range suffixMatchList {
		if s.suffix == ".com" {
			t.Errorf(".com must not be added to suffixMatchList (overly-broad)")
		}
	}

	// ".example.com" should be present.
	found := false
	for _, s := range suffixMatchList {
		if s.suffix == ".example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf(".example.com should be in suffixMatchList")
	}

	// "no-dot" should NOT be in the exact set.
	if _, ok := hostMatchSet["no-dot"]; ok {
		t.Errorf("bare label 'no-dot' must not be added to hostMatchSet")
	}

	// "mail.valid.example" should be in the exact set.
	if _, ok := hostMatchSet["mail.valid.example"]; !ok {
		t.Errorf("mail.valid.example should be in hostMatchSet")
	}

	// Smoke: .com does NOT make every .com trusted.
	_ = os.Unsetenv // already cleared via t.Setenv cleanup
	if IsTrusted("attacker.com") {
		t.Errorf("attacker.com must not be trusted after .com was rejected")
	}
}
