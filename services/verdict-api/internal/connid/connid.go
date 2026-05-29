// Package connid models "connection identity": the question
//
//	"Did the user's browser actually connect to a legitimate endpoint
//	 for the domain it thinks it visited?"
//
// Backend DNS alone cannot answer this. A backend resolver may see
//
//	bank.example -> 203.0.113.10  (real)
//
// while the user's browser actually reaches
//
//	bank.example -> 198.51.100.50 (attacker, after local DNS hijack,
//	                               malicious ISP resolver, hosts-file
//	                               tampering, router compromise, browser
//	                               DoH bypass, captive portal rewrite,
//	                               or malware-installed root CA).
//
// Phase B introduces this package as the contract. The comparator logic
// (compare.go) is filled in in Phase B.5. This file defines:
//
//   - the [Identity] struct that travels on the verdict-api response
//   - construction helpers from the raw request fields
//   - private-IP classification (RFC1918, loopback, link-local, ULA, CGNAT)
//
// Membership of an IP in the "private" set is NOT itself a verdict — it is
// a fact the comparator uses together with whether the host is a public
// domain. See [reasons.PublicDomainPrivateIP].
package connid

import (
	"net"
	"strings"
)

// Identity is the connection-identity evidence object that travels on the
// verdict-api response and is rendered in the evidence UI.
//
// All fields are optional. A response with the zero value means "the
// extension did not provide browser_remote_ip" — connection identity is
// simply absent, not "failed".
type Identity struct {
	// Domain is the host portion of the URL under verdict.
	Domain string `json:"domain,omitempty"`

	// BrowserRemoteIP is the IP the browser actually connected to,
	// captured by the extension via chrome.webRequest.onResponseStarted.
	BrowserRemoteIP string `json:"browser_remote_ip,omitempty"`

	// XGGResolverIPsForClient is what the XGenGuardian resolver returned
	// to this client for this domain within the recent TTL window.
	// Empty when the client doesn't use XGG DNS or the ledger is cold.
	XGGResolverIPsForClient []string `json:"xgg_resolver_ips_for_client,omitempty"`

	// BackendResolverIPs is what an independent trusted resolver returned
	// when verdict-api looked the host up. Used as a second opinion when
	// the XGG resolver ledger is empty.
	BackendResolverIPs []string `json:"backend_resolver_ips,omitempty"`

	// CNAMEChain is the CNAME chain observed by the backend resolver.
	// Useful for showing the user "you reached a CDN" instead of a bare IP.
	CNAMEChain []string `json:"cname_chain,omitempty"`

	// BrowserRemoteASN is the ASN of BrowserRemoteIP.
	BrowserRemoteASN uint32 `json:"browser_remote_asn,omitempty"`

	// ExpectedASNs is the set of ASNs the backend considers legitimate
	// for the domain (CDN ownership, historical infrastructure, registry).
	ExpectedASNs []uint32 `json:"expected_asns,omitempty"`

	// TLSValidForHost — the extension or backend confirmed the TLS
	// certificate served on this connection is valid for Domain.
	TLSValidForHost bool `json:"tls_valid_for_host,omitempty"`

	// DNSPathConsistent — BrowserRemoteIP ∈ XGGResolverIPsForClient
	// (or, when ledger is cold, ∈ BackendResolverIPs).
	DNSPathConsistent bool `json:"dns_path_consistent,omitempty"`

	// CDNConsistent — BrowserRemoteASN ∈ ExpectedASNs, even if the exact
	// IP differs (CDN geo/anycast/EDNS-CS rotation).
	CDNConsistent bool `json:"cdn_consistent,omitempty"`

	// Confidence is a 0.0–1.0 score combining the booleans above with
	// the strength of the evidence (e.g. one observation vs many).
	Confidence float64 `json:"connection_identity_confidence,omitempty"`
}

// IsPrivateIP reports whether ip is an RFC1918 private address, loopback,
// link-local, IPv6 ULA (fc00::/7), IPv6 link-local (fe80::/10), or carrier
// NAT (100.64.0.0/10). The empty string and unparsable inputs return false
// — "we couldn't decide" rather than "yes private".
//
// This is the substrate for PUBLIC_DOMAIN_PRIVATE_IP. The reason code only
// fires when (Domain is a public registrable domain) AND (BrowserRemoteIP
// is private) — the second half lives here.
func IsPrivateIP(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsPrivate() {
		return true
	}
	// net.IP.IsPrivate covers RFC1918 + IPv6 ULA (fc00::/7) but NOT
	// carrier-grade NAT (100.64.0.0/10 per RFC6598). A public domain
	// resolving into CGNAT space is the same red flag.
	if v4 := parsed.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}
