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
