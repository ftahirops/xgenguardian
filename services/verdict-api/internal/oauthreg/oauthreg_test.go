package oauthreg

import "testing"

func TestInspect_MicrosoftConsentURL(t *testing.T) {
	c := New(nil)
	// Seed an entry directly via the internal map for testability.
	c.byKey["microsoft:abcdef-1234"] = entry{AppName: "Acme Verified", TrustLevel: TrustVerified}

	d := c.Inspect("https://login.microsoftonline.com/common/oauth2/v2.0/authorize" +
		"?client_id=abcdef-1234&scope=Mail.ReadWrite+Files.ReadWrite.All&response_type=code")
	if d == nil {
		t.Fatal("expected Decision; got nil")
	}
	if d.Provider != "microsoft" || d.ClientID != "abcdef-1234" {
		t.Errorf("provider/client wrong: %+v", d)
	}
	if !d.Known || d.TrustLevel != TrustVerified {
		t.Errorf("known/trust wrong: %+v", d)
	}
	if !d.SuspiciousScopes {
		t.Errorf("Mail.ReadWrite + Files.ReadWrite.All should mark suspicious scopes")
	}
}

func TestInspect_UnknownClientID(t *testing.T) {
	c := New(nil)
	d := c.Inspect("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=evil-app-xyz&scope=Mail.Send")
	if d == nil || d.Provider != "microsoft" {
		t.Fatalf("expected microsoft Decision; got %+v", d)
	}
	if d.Known {
		t.Errorf("unseeded client_id should be Known=false")
	}
	if !d.SuspiciousScopes {
		t.Errorf("Mail.Send is sensitive; should mark SuspiciousScopes")
	}
}

func TestInspect_Google(t *testing.T) {
	c := New(nil)
	d := c.Inspect("https://accounts.google.com/o/oauth2/v2/auth?client_id=12345.apps.googleusercontent.com&scope=https://www.googleapis.com/auth/gmail.modify")
	if d == nil || d.Provider != "google" {
		t.Fatalf("expected google Decision; got %+v", d)
	}
	if !d.SuspiciousScopes {
		t.Errorf("gmail.modify is sensitive")
	}
}

func TestInspect_GitHub(t *testing.T) {
	c := New(nil)
	d := c.Inspect("https://github.com/login/oauth/authorize?client_id=Iv1.abcdef&scope=repo,user")
	if d == nil || d.Provider != "github" {
		t.Fatalf("expected github Decision; got %+v", d)
	}
}

func TestInspect_NotAnOAuthURL(t *testing.T) {
	c := New(nil)
	for _, u := range []string{
		"https://google.com/search?q=oauth",
		"https://example.com/login",
		"https://accounts.google.com/Login",
		"not a url",
		"",
	} {
		if d := c.Inspect(u); d != nil {
			t.Errorf("non-OAuth URL %q should return nil; got %+v", u, d)
		}
	}
}

func TestInspect_NoClientID(t *testing.T) {
	c := New(nil)
	// Real consent path but no client_id param.
	d := c.Inspect("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=Mail.Read")
	if d != nil {
		t.Errorf("missing client_id should return nil; got %+v", d)
	}
}

func TestScopeList_HandlesBothSeparators(t *testing.T) {
	got := scopeList("openid Mail.ReadWrite Files.Read")
	if len(got) != 3 {
		t.Errorf("space-separated: got %v", got)
	}
	got = scopeList("repo,user,read:org")
	if len(got) != 3 {
		t.Errorf("comma-separated: got %v", got)
	}
}

func TestAnySensitiveScope(t *testing.T) {
	sensitive := [][]string{
		{"openid", "Mail.ReadWrite"},
		{"https://www.googleapis.com/auth/gmail.send"},
		{"Files.ReadWrite.All"},
		{"read:org", "user"},  // benign GitHub scopes — not sensitive
	}
	wants := []bool{true, true, true, false}
	for i, s := range sensitive {
		if got := anySensitiveScope(s); got != wants[i] {
			t.Errorf("case %d (%v): got %v, want %v", i, s, got, wants[i])
		}
	}
}
