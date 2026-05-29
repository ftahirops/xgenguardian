package orggraph

import "testing"

// TestSameOrg_Disney — moviesanywhere.com and disney.com are in the same
// org. Before orggraph this required adding Disney to trustreg as a
// suffix entry, which mixed FP-fixing with Tier-0 trust. orggraph
// separates the concerns: SameOrg is about cross-origin counting, not
// trust.
func TestSameOrg_Disney(t *testing.T) {
	cases := [][2]string{
		{"moviesanywhere.com", "disney.com"},
		{"moviesanywhere.com", "hulu.com"},
		{"hulu.com", "espn.com"},
		{"espn.com", "abc.com"},
		{"marvel.com", "starwars.com"},
		{"pixar.com", "disneyplus.com"},
		{"nationalgeographic.com", "disney.com"},
		{"hotstar.com", "disneyplus.com"},
	}
	for _, c := range cases {
		if !SameOrg(c[0], c[1]) {
			t.Errorf("SameOrg(%q, %q) = false, expected true (both Disney)", c[0], c[1])
		}
	}
}

// TestSameOrg_NotSameOrg — a Disney domain and a non-Disney domain are
// not same-org. Prevents the graph from silently expanding membership.
func TestSameOrg_NotSameOrg(t *testing.T) {
	cases := [][2]string{
		{"moviesanywhere.com", "netflix.com"},
		{"hulu.com", "spotify.com"},
		{"google.com", "microsoft.com"}, // different orgs
		{"meta.com", "alphabet"},        // alphabet is org-id, not a domain
		{"random-host.example", "disney.com"},
	}
	for _, c := range cases {
		if SameOrg(c[0], c[1]) {
			t.Errorf("SameOrg(%q, %q) = true, expected false (different orgs)", c[0], c[1])
		}
	}
}

// TestSameOrg_Unknown — both domains unknown returns false (not "true
// because both empty"). This is the safety invariant: unknown domains
// are never same-org-with-anything by default.
func TestSameOrg_Unknown(t *testing.T) {
	if SameOrg("random-host-1.example", "random-host-2.example") {
		t.Errorf("two unknown hosts should not be SameOrg")
	}
	if SameOrg("", "") {
		t.Errorf("two empty strings should not be SameOrg")
	}
}

// TestSameOrgHosts — subdomain form should normalize to registrable
// before lookup.
func TestSameOrgHosts(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"www.moviesanywhere.com", "www.disney.com", true},
		{"login.microsoftonline.com", "github.com", true}, // both Microsoft
		{"cdn.shopify.com", "myshopify.com", true},
		{"random.example.com", "another.example.com", false},
	}
	for _, c := range cases {
		got := SameOrgHosts(c.a, c.b)
		if got != c.want {
			t.Errorf("SameOrgHosts(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestOrgOf_Coverage — every host registered in `orgs` must round-trip
// to its org via OrgOf. Catches typos in the source map.
func TestOrgOf_Coverage(t *testing.T) {
	for org, hosts := range orgs {
		for _, h := range hosts {
			if got := OrgOf(h); got != org {
				t.Errorf("OrgOf(%q) = %q, want %q", h, got, org)
			}
		}
	}
}

// TestRegistrable — the simplified two-label registrable extractor.
func TestRegistrable(t *testing.T) {
	cases := []struct{ in, want string }{
		{"www.google.com", "google.com"},
		{"login.microsoftonline.com", "microsoftonline.com"},
		{"a.b.c.example.org", "example.org"},
		{"example.org", "example.org"},
		{"localhost", "localhost"},
		{"", ""},
	}
	for _, c := range cases {
		if got := registrable(c.in); got != c.want {
			t.Errorf("registrable(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
