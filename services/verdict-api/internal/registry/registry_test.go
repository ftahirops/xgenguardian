package registry

import "testing"

func TestSLD(t *testing.T) {
	cases := map[string]string{
		"paypal.com":         "paypal",
		"www.paypal.com":     "paypal",
		"login.paypal.co.uk": "co", // limitation: heuristic ignores PSL
		"github":             "github",
		"":                   "",
	}
	for in, want := range cases {
		if got := sld(in); got != want {
			t.Errorf("sld(%q) = %q, want %q", in, got, want)
		}
	}
}
