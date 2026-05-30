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

// Wave 3 expansion — extended scope coverage for GitHub / Slack /
// Atlassian / Azure. Smoke corpus surfaced the OAUTH_UNKNOWN_CLIENT_ID
// rule not firing on github.com/login/oauth/authorize with scope=repo,
// because `repo` wasn't in the original sensitive-scope list (only
// Microsoft Graph + Google were).

func TestAnySensitiveScope_GitHub(t *testing.T) {
	cases := []struct {
		scopes []string
		want   bool
	}{
		{[]string{"repo"}, true},
		{[]string{"repo:status"}, true},
		{[]string{"admin:org"}, true},
		{[]string{"admin:repo_hook"}, true},
		{[]string{"admin:enterprise"}, true},
		{[]string{"gist"}, true},
		{[]string{"delete_repo"}, true},
		{[]string{"workflow"}, true},
		{[]string{"write:packages"}, true},
		{[]string{"notifications"}, true},
		// Negative: read-only scopes that don't grant write
		{[]string{"read:org"}, false},
		{[]string{"read:user"}, false},
		{[]string{"read:public_key"}, false},
		{[]string{"user"}, false}, // matches existing TestAnySensitiveScope contract
	}
	for _, c := range cases {
		if got := anySensitiveScope(c.scopes); got != c.want {
			t.Errorf("anySensitiveScope(%v) = %v; want %v", c.scopes, got, c.want)
		}
	}
}

func TestAnySensitiveScope_Slack(t *testing.T) {
	cases := []struct {
		scopes []string
		want   bool
	}{
		{[]string{"chat:write"}, true},
		{[]string{"channels:history"}, true},
		{[]string{"groups:history"}, true},
		{[]string{"files:read"}, true},
		{[]string{"users.profile:write"}, true},
		// Negative
		{[]string{"identify"}, false},
		{[]string{"users:read"}, false},
	}
	for _, c := range cases {
		if got := anySensitiveScope(c.scopes); got != c.want {
			t.Errorf("anySensitiveScope(%v) = %v; want %v", c.scopes, got, c.want)
		}
	}
}

func TestAnySensitiveScope_GoogleExtended(t *testing.T) {
	cases := []struct {
		scopes []string
		want   bool
	}{
		{[]string{"https://www.googleapis.com/auth/gmail.compose"}, true},
		{[]string{"https://www.googleapis.com/auth/gmail.readonly"}, true},
		{[]string{"https://www.googleapis.com/auth/spreadsheets"}, true},
		{[]string{"https://www.googleapis.com/auth/cloud-platform"}, true},
		// Negative
		{[]string{"https://www.googleapis.com/auth/userinfo.email"}, false},
	}
	for _, c := range cases {
		if got := anySensitiveScope(c.scopes); got != c.want {
			t.Errorf("anySensitiveScope(%v) = %v; want %v", c.scopes, got, c.want)
		}
	}
}

func TestAnySensitiveScope_Azure(t *testing.T) {
	if !anySensitiveScope([]string{"https://management.azure.com/.default"}) {
		t.Error("Azure management.azure.com should be sensitive")
	}
}
