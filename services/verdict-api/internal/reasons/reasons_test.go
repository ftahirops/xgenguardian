package reasons

import "testing"

func TestRender_KnownCode(t *testing.T) {
	tpl := Render(BrandClaimDomainMismatch)
	if tpl.Title == "" || tpl.Body == "" {
		t.Errorf("expected non-empty template for BrandClaimDomainMismatch")
	}
	if tpl.Severity != SeverityCritical {
		t.Errorf("BrandClaimDomainMismatch should be Critical")
	}
}

func TestRender_UnknownCode(t *testing.T) {
	tpl := Render(Code("BOGUS_REASON_NOT_REGISTERED"))
	if tpl.Title != "BOGUS_REASON_NOT_REGISTERED" {
		t.Errorf("unknown code should echo the code as title")
	}
	if tpl.Body == "" {
		t.Errorf("unknown code should have a fallback body")
	}
}

func TestIsPolicy(t *testing.T) {
	for _, c := range []Code{
		BlockedByStrictnessPolicy,
		BlockedByTenantOverride,
		AllowedByTenantOverride,
		IsolatedSensitivePageClass,
	} {
		if !IsPolicy(c) {
			t.Errorf("%s should be policy-driven", c)
		}
	}
	for _, c := range []Code{
		KnownPhishURLMatch,
		BrandClaimDomainMismatch,
		MaliciousDownloadTrigger,
		PopupStormDetected,
	} {
		if IsPolicy(c) {
			t.Errorf("%s should NOT be policy-driven (it's detection)", c)
		}
	}
}

func TestAllCodes_HaveTemplates(t *testing.T) {
	// Every code returned by All() must have IsKnown == true.
	// Guards against silently dropping templates during refactors.
	for _, c := range All() {
		if !IsKnown(c) {
			t.Errorf("All() returned unregistered code %q", c)
		}
	}
}
