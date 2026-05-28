package rebind

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestIsPrivateOrReserved_IPv4(t *testing.T) {
	rejected := []string{
		"10.0.0.1", "172.16.5.5", "192.168.1.1", // RFC1918
		"127.0.0.1", "127.255.255.254", // loopback
		"169.254.1.1",                  // link-local
		"0.0.0.0",                      // unspecified
		"100.64.0.1", "100.127.255.1",  // CGNAT
		"192.0.0.5",                    // protocol assignments
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // documentation
		"198.18.0.1", "198.19.255.1", // benchmark
		"224.0.0.1",                    // multicast
		"240.0.0.1", "255.255.255.255", // reserved
	}
	for _, s := range rejected {
		ip := net.ParseIP(s)
		if !isPrivateOrReserved(ip) {
			t.Errorf("%s should be private/reserved", s)
		}
	}
}

func TestIsPrivateOrReserved_IPv4Public(t *testing.T) {
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "151.101.1.1", "23.45.67.89", "100.63.255.255",
		"100.128.0.1", // outside CGNAT
		"199.0.0.1",
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if isPrivateOrReserved(ip) {
			t.Errorf("%s should be public", s)
		}
	}
}

func TestIsPrivateOrReserved_IPv6(t *testing.T) {
	rejected := []string{
		"::1",            // loopback
		"::",             // unspecified
		"fc00::1",        // ULA
		"fe80::1",        // link-local
		"ff00::1",        // multicast
		"2001:db8::1",    // documentation
	}
	for _, s := range rejected {
		ip := net.ParseIP(s)
		if !isPrivateOrReserved(ip) {
			t.Errorf("%s should be private/reserved", s)
		}
	}
}

func TestIsPrivateOrReserved_IPv6Public(t *testing.T) {
	allowed := []string{"2606:4700:4700::1111", "2001:4860:4860::8888"}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if isPrivateOrReserved(ip) {
			t.Errorf("%s should be public", s)
		}
	}
}

func TestFilter_DropsPrivateA(t *testing.T) {
	m := new(dns.Msg)
	for _, s := range []string{"1.1.1.1", "192.168.1.1", "10.0.0.1", "8.8.8.8"} {
		rr, _ := dns.NewRR("example.com. 60 IN A " + s)
		m.Answer = append(m.Answer, rr)
	}
	dropped, anyA, wasA := Filter(m)
	if dropped != 2 {
		t.Errorf("dropped: got %d, want 2", dropped)
	}
	if !wasA || !anyA {
		t.Errorf("expected wasA && anyA both true")
	}
	if len(m.Answer) != 2 {
		t.Errorf("answer left: got %d, want 2", len(m.Answer))
	}
}

func TestFilter_AllPrivate_TriggersNXDOMAINHint(t *testing.T) {
	m := new(dns.Msg)
	for _, s := range []string{"192.168.1.1", "10.0.0.1"} {
		rr, _ := dns.NewRR("rebind.example. 60 IN A " + s)
		m.Answer = append(m.Answer, rr)
	}
	_, anyA, wasA := Filter(m)
	if !wasA {
		t.Errorf("expected wasA true")
	}
	if anyA {
		t.Errorf("expected anyA false — caller should rewrite to NXDOMAIN")
	}
	if len(m.Answer) != 0 {
		t.Errorf("expected empty Answer, got %d", len(m.Answer))
	}
}

func TestFilter_PreservesCNAMEAndTXT(t *testing.T) {
	m := new(dns.Msg)
	rr1, _ := dns.NewRR("a.example. 60 IN CNAME b.example.")
	rr2, _ := dns.NewRR("a.example. 60 IN TXT \"hello\"")
	rr3, _ := dns.NewRR("a.example. 60 IN A 192.168.1.1")
	m.Answer = []dns.RR{rr1, rr2, rr3}
	dropped, _, _ := Filter(m)
	if dropped != 1 {
		t.Errorf("expected 1 A dropped, got %d", dropped)
	}
	if len(m.Answer) != 2 {
		t.Errorf("expected CNAME+TXT to remain, got %d records", len(m.Answer))
	}
}

func TestFilter_NilMessage(t *testing.T) {
	d, a, w := Filter(nil)
	if d != 0 || a || w {
		t.Errorf("nil msg should yield zero values")
	}
}
