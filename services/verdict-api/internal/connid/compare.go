package connid

// Compare against the XGG resolver ledger. Phase B.5a — this is the
// minimum-viable comparator. It answers two questions:
//
//   - Is the browser's actual remote IP one of the IPs the XGG resolver
//     recently returned to this client for this domain? (DNS path match)
//
//   - When the user opted into XGG DNS but the ledger is empty for this
//     (client, domain), did they bypass us via browser DoH / VPN DNS /
//     system override? (Expected resolver bypassed)
//
// CDN/ASN comparison and TLS-identity comparison (the CDN_ASN_*,
// TLS_IDENTITY_MISMATCH, LOCAL_RESOLVER_HIJACK_SUSPECTED reason codes)
// require ASN lookup tables and TLS introspection that don't exist
// yet — they land in Phase B.5b once those data sources do.

import (
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

// LedgerEntry is what an iledger reader returns. Kept here as a tiny
// interface so connid doesn't import internal/iledger (and create an
// import cycle if iledger ever needs connid types).
type LedgerEntry struct {
	IP string
}

// CompareInput carries everything CompareLedger needs.
type CompareInput struct {
	// ClientOptedIntoXGGDNS — set when the request includes evidence the
	// user routes through the XGG resolver (e.g. their configured DNS or a
	// signed beacon). When this is true and the ledger is empty, we
	// suspect resolver bypass.
	ClientOptedIntoXGGDNS bool

	// BrowserRemoteIP — what the extension reported via chrome.webRequest.
	BrowserRemoteIP string

	// LedgerEntries — recent rows from the XGG resolver ledger for
	// (client, domain). Nil/empty means "ledger cold."
	LedgerEntries []LedgerEntry
}

// CompareResult is the outcome of the ledger comparison: any reason
// codes to emit plus the boolean fields the verdict-api response carries.
type CompareResult struct {
	ReasonCodes       []reasons.Code
	DNSPathConsistent bool
}

// CompareLedger runs the ledger comparison and returns the reason codes
// the policy should emit plus the DNS-path-consistent flag for the
// evidence UI.
//
// Behavior:
//
//   - BrowserRemoteIP empty            → no codes (extension didn't capture)
//   - ledger has IP among entries      → USER_DNS_PATH_MATCH, consistent=true
//   - ledger non-empty but IP missing  → USER_DNS_PATH_MISMATCH
//   - ledger empty + opted-in client   → EXPECTED_RESOLVER_BYPASSED
//   - ledger empty + non-XGG client    → no codes (we have no opinion)
func CompareLedger(in CompareInput) CompareResult {
	if in.BrowserRemoteIP == "" {
		return CompareResult{}
	}
	if len(in.LedgerEntries) == 0 {
		if in.ClientOptedIntoXGGDNS {
			return CompareResult{
				ReasonCodes: []reasons.Code{reasons.ExpectedResolverBypassed},
			}
		}
		return CompareResult{}
	}
	for _, e := range in.LedgerEntries {
		if e.IP == in.BrowserRemoteIP {
			return CompareResult{
				ReasonCodes:       []reasons.Code{reasons.UserDNSPathMatch},
				DNSPathConsistent: true,
			}
		}
	}
	return CompareResult{
		ReasonCodes: []reasons.Code{reasons.UserDNSPathMismatch},
	}
}
