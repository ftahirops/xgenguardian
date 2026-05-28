package trustreg

import "testing"

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
