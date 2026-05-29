package connid

import "testing"

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
		name string
	}{
		{"127.0.0.1", true, "loopback v4"},
		{"::1", true, "loopback v6"},
		{"10.0.0.5", true, "RFC1918 /8"},
		{"172.16.5.5", true, "RFC1918 /12"},
		{"172.31.255.255", true, "RFC1918 /12 edge"},
		{"172.32.0.1", false, "just outside /12"},
		{"192.168.1.1", true, "RFC1918 /16"},
		{"169.254.1.1", true, "link-local v4"},
		{"fe80::1", true, "link-local v6"},
		{"fc00::1", true, "IPv6 ULA"},
		{"fd12::1", true, "IPv6 ULA"},
		{"100.64.0.1", true, "CGNAT lower edge"},
		{"100.127.255.255", true, "CGNAT upper edge"},
		{"100.128.0.0", false, "outside CGNAT"},
		{"100.63.255.255", false, "just below CGNAT"},
		{"8.8.8.8", false, "public v4"},
		{"1.1.1.1", false, "public v4"},
		{"2606:4700:4700::1111", false, "public v6"},
		{"", false, "empty"},
		{"not-an-ip", false, "garbage"},
		{"  192.168.0.1  ", true, "trimmed"},
	}
	for _, c := range cases {
		if got := IsPrivateIP(c.ip); got != c.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v (%s)", c.ip, got, c.want, c.name)
		}
	}
}

func TestIdentity_ZeroValueIsAbsent(t *testing.T) {
	// A zero Identity must be the "no connection identity available"
	// signal — verdict-api code paths check this before emitting any of
	// the Phase B reason codes.
	var id Identity
	if id.BrowserRemoteIP != "" {
		t.Errorf("zero Identity should have empty BrowserRemoteIP")
	}
	if id.DNSPathConsistent || id.CDNConsistent || id.TLSValidForHost {
		t.Errorf("zero Identity should have all booleans false")
	}
	if id.Confidence != 0 {
		t.Errorf("zero Identity should have zero confidence")
	}
}
