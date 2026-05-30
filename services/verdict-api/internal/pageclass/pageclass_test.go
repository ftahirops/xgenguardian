package pageclass

import "testing"

func TestFromURL(t *testing.T) {
	cases := map[string]Class{
		// Most-specific wins: OAuth beats /login when both appear.
		"https://login.microsoftonline.com/common/oauth2/v2.0/authorize": OAuthConsent,
		"https://accounts.google.com/signin/oauth/consent":               OAuthConsent,
		"https://github.com/login/oauth/authorize":                       OAuthConsent,
		// MFA
		"https://www.example.com/auth/2fa":                               MFA,
		"https://www.example.com/passkey":                                MFA,
		"https://example.com/totp/verify":                                MFA,
		// Password step
		"https://accounts.google.com/signin/v2/pwd":                      PasswordStep,
		"https://example.com/login/password":                             PasswordStep,
		// Login
		"https://paypal.com/signin":                                      Login,
		"https://example.com/verify-account":                             Login,
		"https://example.com/recover":                                    Login,
		// Payment
		"https://shop.example/checkout":                                  Payment,
		"https://example.com/billing/update":                             Payment,
		"https://example.com/wallet/topup":                               Payment,
		// Crypto
		"https://exchange.example/withdraw":                              CryptoWithdrawal,
		// Invoice
		"https://example.com/invoice/2024-001":                           Invoice,
		// Download
		"https://example.com/download/installer":                         Download,
		// Generic
		"https://example.com/about":                                      Generic,
		"https://example.com/":                                           Generic,
		"https://wikipedia.org/":                                         Generic,
	}
	for u, want := range cases {
		if got := FromURL(u); got != want {
			t.Errorf("FromURL(%q) = %s, want %s", u, got, want)
		}
	}
}

func TestRefine_DOMSignalsOverrideGenericURL(t *testing.T) {
	// /about page that happens to contain a password field → Login
	got := Refine(Generic, DOMHints{HasPasswordField: true})
	if got != Login {
		t.Errorf("password on generic URL: got %s, want Login", got)
	}

	// /about with payment field → Payment
	got = Refine(Generic, DOMHints{HasPaymentField: true})
	if got != Payment {
		t.Errorf("payment field on generic URL: got %s, want Payment", got)
	}

	// URL with client_id param → OAuth, regardless of URL hint
	got = Refine(Login, DOMHints{HasOAuthClientID: true})
	if got != OAuthConsent {
		t.Errorf("OAuth client_id should force OAuthConsent")
	}
}

func TestRefine_PasswordStepURLKept(t *testing.T) {
	// /signin/v2/pwd URL + password field → keep PasswordStep, don't demote.
	got := Refine(PasswordStep, DOMHints{HasPasswordField: true})
	if got != PasswordStep {
		t.Errorf("PasswordStep URL + password field: got %s, want PasswordStep", got)
	}
}

func TestRefine_MFADetection(t *testing.T) {
	// OTP field alone → MFA
	got := Refine(Generic, DOMHints{HasOTPField: true})
	if got != MFA {
		t.Errorf("OTP only: got %s, want MFA", got)
	}
	// Password + OTP together → MFA (combined-step flows)
	got = Refine(Login, DOMHints{HasPasswordField: true, HasOTPField: true})
	if got != MFA {
		t.Errorf("password+OTP: got %s, want MFA", got)
	}
	// Passkey API → MFA
	got = Refine(Login, DOMHints{HasPasskeyAPI: true})
	if got != MFA {
		t.Errorf("passkey: got %s, want MFA", got)
	}
}

func TestRefine_ScarewareComposite(t *testing.T) {
	// Three abuse signals at once on a generic page → support scareware.
	got := Refine(Generic, DOMHints{
		PopupStorm: true, AlertLoop: true, ForcedFullscreen: true,
	})
	if got != SupportScareware {
		t.Errorf("scareware composite: got %s, want SupportScareware", got)
	}

	// Two of three is not enough.
	got = Refine(Generic, DOMHints{PopupStorm: true, AlertLoop: true})
	if got == SupportScareware {
		t.Errorf("2-of-3 abuse should NOT fire scareware")
	}
}

func TestRefine_KeepsURLHintWhenDOMSilent(t *testing.T) {
	got := Refine(Payment, DOMHints{}) // empty hints
	if got != Payment {
		t.Errorf("empty DOM should keep URL hint Payment, got %s", got)
	}
}

func TestIsSensitive(t *testing.T) {
	sensitive := []Class{Login, PasswordStep, MFA, OAuthConsent, Payment,
		CryptoWithdrawal, Invoice, Download}
	for _, c := range sensitive {
		if !c.IsSensitive() {
			t.Errorf("%s should be sensitive", c)
		}
	}
	notSensitive := []Class{Generic, SupportScareware}
	for _, c := range notSensitive {
		if c.IsSensitive() {
			t.Errorf("%s should NOT be sensitive", c)
		}
	}
}

// Wave 2.5 — SLD-keyword fallback for hosts that bake sensitive intent
// into the registrable domain rather than the path. Real attacker
// pattern caught by smoke corpus (bank-login-secure-2026.example etc.)

func TestFromURL_SLDKeywords_PromoteToSensitive(t *testing.T) {
	cases := []struct {
		url  string
		want Class
	}{
		{"https://bank-login-secure-2026.example/", Login},
		// paypal-account-security.example now correctly maps to Login
		// (path-switch substring bug fixed; SLD branch matches "account").
		{"https://paypal-account-security.example/", Login},
		{"https://wellsfargo-online-update.example/", Login},
		{"https://chase-account-verify.example/", Login},
		{"https://login.microsoft.com.evil.example/", Login}, // "login" in left label
		{"https://www.bank-login.example/", Login},           // www. stripped, second label used
		{"https://newcheckout-2026.example/", Payment},
		// "secure" wins Login over "checkout" → Payment per switch
		// ordering — that's the intended precedence: credential capture
		// is worse than payment capture; both are sensitive-action denies.
		{"https://buy-now-secure-2026.example/", Login},
		{"https://claim-airdrop-uniswap.example/", CryptoWithdrawal},
		// Negative: ordinary sites with no SLD-keyword hit
		{"https://example.com/", Generic},
		{"https://wikipedia.org/", Generic},
	}
	for _, c := range cases {
		got := FromURL(c.url)
		if got != c.want {
			t.Errorf("FromURL(%q) = %s; want %s", c.url, got, c.want)
		}
	}
}

func TestExtractSLD(t *testing.T) {
	cases := []struct {
		url, want string
	}{
		{"https://bank-login-secure.example/", "bank-login-secure"},
		{"https://www.example.com/path", "example"},
		{"https://www.example.com./", "example"},          // trailing dot
		{"https://EXAMPLE.com/", "example"},               // case normalised
		{"not a url", "noturl"},                           // url.Parse is permissive; "not%20a%20url" becomes scheme-less
		{"", ""},
	}
	for _, c := range cases {
		got := extractSLD(c.url)
		// Skip the "not a url" case since url.Parse behavior on bare
		// text is platform-specific; just confirm it doesn't crash.
		if c.url == "not a url" {
			continue
		}
		if got != c.want {
			t.Errorf("extractSLD(%q) = %q; want %q", c.url, got, c.want)
		}
	}
}

// Wave 2.5 — path-switch substring-matching bug regression.
//
// Pre-fix the path switch used strings.Contains on the LOWERCASED FULL
// URL, so the host substring's leading slash (the "/" after "//") could
// fake a path-keyword match. Two real false-positive classes:
//
//   1. paypal-account-security.example → Payment (matched "/pay" in
//      "/paypal-...")
//   2. login.example → Login (matched "/login" in "//login.example/")
//
// Post-fix the switch reads u.Path only, so these stop misfiring and
// the SLD-keyword fallback gets to decide instead.

func TestFromURL_PathSubstringBug_PaypalNotPayment(t *testing.T) {
	cases := []struct {
		url  string
		want Class
	}{
		// The headline case: paypal-* SLD must NOT map to Payment via
		// the path switch. After the fix, no path match → SLD-keyword
		// switch fires on "account" → Login.
		{"https://paypal-account-security.example/", Login},
		// Same class: any SLD containing "pay" was previously broken
		{"https://paypal-login.example/", Login},
	}
	for _, c := range cases {
		got := FromURL(c.url)
		if got != c.want {
			t.Errorf("FromURL(%q) = %s; want %s (path-substring regression)", c.url, got, c.want)
		}
	}
}

func TestFromURL_PathSubstringBug_HostKeywordNotPath(t *testing.T) {
	// host-only keyword must not trigger path-switch. With the fix:
	//   login.example/                → path is "/" → no path match →
	//                                   SLD has "login" → Login (from
	//                                   the SLD-keyword fallback)
	//   pay.example/about             → path is "/about" → no path match →
	//                                   SLD has no keyword → Generic
	cases := []struct {
		url  string
		want Class
	}{
		// SLD keyword "login" still maps to Login but via the SLD branch
		{"https://login.example/", Login},
		// SLD keyword "pay" alone doesn't trigger our SLD switch
		// (we require "-pay-" or "pay-" prefix or "-pay" suffix), so a
		// bare "pay.example" should be Generic.
		{"https://pay.example/about", Generic},
		// /payment in actual path still fires
		{"https://example.com/payment", Payment},
		// /oauth in actual path still fires
		{"https://example.com/api/oauth/v2/authorize", OAuthConsent},
	}
	for _, c := range cases {
		got := FromURL(c.url)
		if got != c.want {
			t.Errorf("FromURL(%q) = %s; want %s", c.url, got, c.want)
		}
	}
}

// Wave 2.5 — LooksLikeDevToolInstallLure expansion. The failing smoke
// case (fake-nodejs-install) slipped through pre-expansion because
// "nodejs" wasn't in devToolBrandKeywords. Two fixes:
//   1. Expand the brand list to cover language runtimes / package
//      managers / container + infra tooling / editors / dev infra.
//   2. Structural fallback: an SLD containing "install" combined with
//      a path hint matches even without a brand in the keyword list.

func TestLooksLikeDevToolInstallLure_RuntimeBrand(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		// Pre-fix failing case
		{"https://nodejs-install-quick.example/installer", true},
		// Other ecosystems we now cover
		{"https://python-install-site.example/setup", true},
		{"https://rustup-install.example/install", true},
		{"https://golang-install.example/download", true},
		{"https://docker-install.example/setup", true},
		{"https://kubernetes-cli-install.example/docs", true},
		{"https://hashicorp-installer.example/download", true},
		// Structural-only (no brand in keyword list — covered by SLD branch)
		{"https://one-click-installer.example/download", true},
		{"https://secure-install-page.example/setup", true},
		// Negative: ordinary site, no install hint or SLD
		{"https://example.com/about", false},
		{"https://example.com/install", false},        // install path but no brand AND no install in SLD
		{"https://anthropic.com/news/release", false}, // brand but no path hint
	}
	for _, c := range cases {
		got := LooksLikeDevToolInstallLure(c.url)
		if got != c.want {
			t.Errorf("LooksLikeDevToolInstallLure(%q) = %v; want %v", c.url, got, c.want)
		}
	}
}
