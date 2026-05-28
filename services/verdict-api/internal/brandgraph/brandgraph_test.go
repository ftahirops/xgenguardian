package brandgraph

import "testing"

func TestTrust_FullTrustMatchesAnyScope(t *testing.T) {
	for _, scope := range []Scope{ScopeLogin, ScopePayment, ScopeOAuthRedirect, ScopeDocs, ScopeApp} {
		m := Trust("claude.ai", scope)
		if m.Brand != "anthropic" {
			t.Errorf("claude.ai should full-trust for scope %s; got %+v", scope, m)
		}
	}
}

func TestTrust_ScopeSpecific_OnlyMatchesItsScope(t *testing.T) {
	// gstatic.com is script-source only — must NOT match login scope.
	if m := Trust("ajax.gstatic.com", ScopeLogin); m.Brand != "" {
		t.Errorf("gstatic.com must NOT trust as login destination; got %+v", m)
	}
	if m := Trust("ajax.gstatic.com", ScopeScriptSource); m.Brand != "google" {
		t.Errorf("gstatic.com should trust as script-source; got %+v", m)
	}
}

func TestTrust_LoginScope_DoesNotImplyFullTrust(t *testing.T) {
	// accounts.google.com is login-scope only, not full-trust.
	if m := Trust("accounts.google.com", ScopeLogin); m.Brand != "google" {
		t.Errorf("accounts.google.com must trust as login; got %+v", m)
	}
	// Should not pass as a docs-scope query (we don't list it as docs).
	if m := Trust("accounts.google.com", ScopeDocs); m.Brand != "" {
		t.Errorf("accounts.google.com isn't scoped for docs; got %+v", m)
	}
}

func TestTrust_CaseAndDotInsensitive(t *testing.T) {
	for _, h := range []string{"Anthropic.COM", "anthropic.com.", "anthropic.com"} {
		if m := Trust(h, ScopeLogin); m.Brand != "anthropic" {
			t.Errorf("normalize(%q) failed; got %+v", h, m)
		}
	}
}

func TestIsAnyTrust(t *testing.T) {
	if !IsAnyTrust("claude.ai") || !IsAnyTrust("accounts.google.com") {
		t.Errorf("expected any-trust match")
	}
	if IsAnyTrust("evil.example.com") {
		t.Errorf("evil.example.com should NOT match")
	}
}

func TestBrandFor(t *testing.T) {
	if BrandFor("login.microsoftonline.com") != "microsoft" {
		t.Errorf("login.microsoftonline.com should be microsoft")
	}
	if BrandFor("randomdomain.example") != "" {
		t.Errorf("unknown host should be empty")
	}
}
