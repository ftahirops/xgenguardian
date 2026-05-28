// Package rebind filters upstream DNS answers to drop private / reserved
// addresses returned for public names — the DNS-rebinding mitigation
// (docs/UNIFIED-PLAN.md §16, smaller wave).
//
// dnsmasq's --stop-dns-rebind is the reference behaviour. We apply the same
// rule on the recursive answer path: any A/AAAA record pointing at RFC1918,
// loopback, link-local, multicast, or otherwise reserved space is stripped.
// If every A/AAAA answer is filtered, the response is rewritten to NXDOMAIN
// so the browser fails cleanly instead of trying the next stripped record.
package rebind

import (
	"net"

	"github.com/miekg/dns"
)

// Filter walks msg.Answer in place and removes A/AAAA records that point at
// non-publicly-routable address space. Returns the number of records dropped
// and whether at least one valid A/AAAA remains. Callers should treat
// (anyA == false && wasA == true) as "rewrite to NXDOMAIN".
//
// CNAME / MX / TXT etc. are untouched — rebinding only matters for A/AAAA.
func Filter(msg *dns.Msg) (dropped int, anyA, wasA bool) {
	if msg == nil {
		return 0, false, false
	}
	kept := msg.Answer[:0]
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			wasA = true
			if isPrivateOrReserved(v.A) {
				dropped++
				continue
			}
			anyA = true
		case *dns.AAAA:
			wasA = true
			if isPrivateOrReserved(v.AAAA) {
				dropped++
				continue
			}
			anyA = true
		}
		kept = append(kept, rr)
	}
	msg.Answer = kept
	return dropped, anyA, wasA
}

// isPrivateOrReserved reports whether ip is in a non-routable / private
// range. Covers IPv4 + IPv6. Conservative: anything not clearly publicly
// routable is rejected.
func isPrivateOrReserved(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// net.IP.IsPrivate covers RFC1918 (10/8, 172.16/12, 192.168/16) and
	// IPv6 ULA (fc00::/7).
	if ip.IsPrivate() {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 — CGNAT (RFC 6598). Routable inside ISPs but not
		// something a public-internet site should ever resolve to.
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return true
		}
		// 169.254.0.0/16 — link-local (covered above, belt-and-suspenders).
		if v4[0] == 169 && v4[1] == 254 {
			return true
		}
		// 192.0.0.0/24 — IETF protocol assignments.
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 0 {
			return true
		}
		// 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — TEST-NET docs.
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 2 {
			return true
		}
		if v4[0] == 198 && v4[1] == 51 && v4[2] == 100 {
			return true
		}
		if v4[0] == 203 && v4[1] == 0 && v4[2] == 113 {
			return true
		}
		// 198.18.0.0/15 — benchmark.
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return true
		}
		// 240.0.0.0/4 — reserved (240–255).
		if v4[0] >= 240 {
			return true
		}
	} else {
		// IPv6-specific extras.
		// 2001:db8::/32 — documentation.
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
			return true
		}
		// ::ffff:0:0/96 — IPv4-mapped (rewrap and retest).
		if v4 := ip.To4(); v4 != nil {
			return isPrivateOrReserved(v4)
		}
	}
	return false
}
