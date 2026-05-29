package httpgw

import "testing"

// Each subtest covers one wrapper's canonical real-world URL shape.
// Targets are example.com / login.microsoftonline.com so we can assert
// the unwrap returns the wrapped target verbatim without depending on
// query-param ordering.

func TestUnwrap_SafeLinks_AllRegions(t *testing.T) {
	cases := []string{
		"https://ind01.safelinks.protection.outlook.com/?url=https%3A%2F%2Flogin.microsoftonline.com%2Foauth2&data=foo",
		"https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Flogin.microsoftonline.com%2Foauth2",
		"https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Flogin.microsoftonline.com%2Foauth2",
	}
	for _, in := range cases {
		got := unwrapEmailGateway(in)
		if !got.Found {
			t.Errorf("SafeLinks should match %s", in)
			continue
		}
		if got.Wrapper != "safelinks" {
			t.Errorf("wrapper = %q; want safelinks", got.Wrapper)
		}
		if got.URL != "https://login.microsoftonline.com/oauth2" {
			t.Errorf("unwrapped = %q; want login.microsoftonline.com", got.URL)
		}
	}
}

func TestUnwrap_Proofpoint_V1V2(t *testing.T) {
	in := "https://urldefense.proofpoint.com/v2/url?u=https%3A%2F%2Fexample.com%2Fpath&d=abc&c=xyz"
	got := unwrapEmailGateway(in)
	if !got.Found || got.Wrapper != "proofpoint" {
		t.Fatalf("expected proofpoint match; got %+v", got)
	}
	if got.URL != "https://example.com/path" {
		t.Errorf("unwrapped = %q", got.URL)
	}
}

func TestUnwrap_Proofpoint_V3PathFormat(t *testing.T) {
	// v3 puts the wrapped URL between __ markers in the path.
	in := "https://urldefense.com/v3/__https://example.com/path__;!!Token!"
	got := unwrapEmailGateway(in)
	if !got.Found || got.Wrapper != "proofpoint" {
		t.Fatalf("v3 path format must match; got %+v", got)
	}
	if got.URL != "https://example.com/path" {
		t.Errorf("v3 unwrapped = %q", got.URL)
	}
}

func TestUnwrap_Mimecast_DomainParam(t *testing.T) {
	in := "https://protect-eu.mimecast.com/s/abc1?domain=phishing.example.com"
	got := unwrapEmailGateway(in)
	if !got.Found || got.Wrapper != "mimecast" {
		t.Fatalf("mimecast should match; got %+v", got)
	}
	if got.URL != "https://phishing.example.com" {
		t.Errorf("mimecast unwrapped = %q", got.URL)
	}
}

func TestUnwrap_Cisco_EmbeddedURLInPath(t *testing.T) {
	in := "https://secure-web.cisco.com/abc123/https://example.com/path"
	got := unwrapEmailGateway(in)
	if !got.Found || got.Wrapper != "cisco" {
		t.Fatalf("cisco should match; got %+v", got)
	}
	if got.URL != "https://example.com/path" {
		t.Errorf("cisco unwrapped = %q", got.URL)
	}
}

func TestUnwrap_Barracuda_AParam(t *testing.T) {
	in := "https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Fexample.com%2Fpath&c=abc"
	got := unwrapEmailGateway(in)
	if !got.Found || got.Wrapper != "barracuda" {
		t.Fatalf("barracuda should match; got %+v", got)
	}
	if got.URL != "https://example.com/path" {
		t.Errorf("barracuda unwrapped = %q", got.URL)
	}
}

func TestUnwrap_Symantec_UParam(t *testing.T) {
	in := "https://clicktime.symantec.com/abc?u=https%3A%2F%2Fexample.com%2Fpath"
	got := unwrapEmailGateway(in)
	if !got.Found || got.Wrapper != "symantec" {
		t.Fatalf("symantec should match; got %+v", got)
	}
	if got.URL != "https://example.com/path" {
		t.Errorf("symantec unwrapped = %q", got.URL)
	}
}

func TestUnwrap_Gmail_LinkRedirect(t *testing.T) {
	in := "https://www.google.com/url?q=https%3A%2F%2Fexample.com%2Fpath&source=gmail"
	got := unwrapEmailGateway(in)
	if !got.Found || got.Wrapper != "gmail" {
		t.Fatalf("gmail link-redirect should match; got %+v", got)
	}
	if got.URL != "https://example.com/path" {
		t.Errorf("gmail unwrapped = %q", got.URL)
	}
}

// --- Security: only http(s) targets are accepted -----------------------------

func TestUnwrap_RejectsNonHTTPSchemes(t *testing.T) {
	// An attacker could craft a wrapper URL whose `u=` param is
	// javascript:alert(1) hoping we'd plumb it through unchanged. Reject
	// anything that isn't http(s).
	dangerousTargets := []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"chrome-extension://abc/page.html",
		"vbscript:msgbox",
	}
	for _, target := range dangerousTargets {
		in := "https://urldefense.proofpoint.com/v2/url?u=" + target
		got := unwrapEmailGateway(in)
		if got.Found {
			t.Errorf("must NOT unwrap to non-http target %q; got %+v", target, got)
		}
	}
}

// --- Negative: ordinary URLs are not falsely identified as wrappers ----------

func TestUnwrap_OrdinaryURLs_NotWrapped(t *testing.T) {
	cases := []string{
		"https://example.com/",
		"https://www.google.com/search?q=foo",         // google.com but not /url
		"https://outlook.office.com/mail/inbox",       // outlook.com but not safelinks
		"https://microsoft.com/protection/safelinks",  // contains "safelinks" string but not the actual host
		"https://www.proofpoint.com/about",            // proofpoint corporate, not urldefense
	}
	for _, in := range cases {
		got := unwrapEmailGateway(in)
		if got.Found {
			t.Errorf("ordinary URL must not match: %s -> %+v", in, got)
		}
	}
}

// --- Defensive: malformed input returns zero result, doesn't panic ----------

func TestUnwrap_MalformedInputs(t *testing.T) {
	for _, in := range []string{"", "not a url", "ftp://", "://no-scheme"} {
		got := unwrapEmailGateway(in)
		if got.Found {
			t.Errorf("malformed %q should not match", in)
		}
	}
}

// --- Security: anchored host matching ---------------------------------------
//
// Regression for the substring-allowlist bypass: every detector must require
// an EXACT or SUFFIX match on the wrapper host, never a substring match.
// Otherwise an attacker registers e.g. "mimecast.com.attacker.com" and
// smuggles a benign-looking `domain=` value through the unwrap while the
// user's browser actually navigates to the attacker host.

func TestUnwrap_SpoofedHostsRejected(t *testing.T) {
	// Each row: an attacker-controlled host that LOOKS like a wrapper
	// because the wrapper name appears as a substring. None should match.
	spoofs := []string{
		// Mimecast — the specific finding
		"https://mimecast.com.attacker.com/s/abc?domain=phishing-target.com",
		"https://protect-eu.mimecast.com.attacker.com/s/abc?url=https://x.com",
		"https://x.mimecast.com.evil.example/?domain=target.com",
		// SafeLinks
		"https://safelinks.protection.outlook.com.attacker.com/?url=https://x.com",
		// Proofpoint
		"https://urldefense.proofpoint.com.attacker.com/v2/url?u=https://x.com",
		"https://urldefense.com.attacker.com/v2/url?u=https://x.com",
		// Cisco
		"https://secure-web.cisco.com.attacker.com/abc/https://x.com",
		// Barracuda
		"https://linkprotect.cudasvc.com.attacker.com/url?a=https://x.com",
		// Symantec
		"https://clicktime.symantec.com.attacker.com/abc?u=https://x.com",
		// Gmail
		"https://www.google.com.attacker.com/url?q=https://x.com",
	}
	for _, in := range spoofs {
		got := unwrapEmailGateway(in)
		if got.Found {
			t.Errorf("SPOOFED host must NOT be treated as a wrapper: %s → %+v", in, got)
		}
	}
}

// Trailing-dot FQDNs (`example.com.`) resolve identically and must be
// normalized so a real wrapper request isn't accidentally bypassed by an
// attacker-supplied trailing dot — and so a spoofed host can't slip
// through by carrying one.
func TestUnwrap_FQDNTrailingDot_Normalized(t *testing.T) {
	// Real wrapper with trailing dot — should still match.
	in := "https://eur01.safelinks.protection.outlook.com./?url=https%3A%2F%2Fexample.com%2F"
	got := unwrapEmailGateway(in)
	if !got.Found || got.Wrapper != "safelinks" {
		t.Errorf("trailing-dot FQDN should still match wrapper: %s → %+v", in, got)
	}
}
