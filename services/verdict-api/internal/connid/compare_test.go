package connid

import (
	"testing"

	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

func contains(codes []reasons.Code, want reasons.Code) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

func TestCompareLedger_NoBrowserIP_NoCodes(t *testing.T) {
	r := CompareLedger(CompareInput{
		LedgerEntries: []LedgerEntry{{IP: "1.2.3.4"}},
	})
	if len(r.ReasonCodes) != 0 || r.DNSPathConsistent {
		t.Errorf("no browser IP must produce no codes; got %+v", r)
	}
}

func TestCompareLedger_Match_EmitsMatchAndConsistent(t *testing.T) {
	r := CompareLedger(CompareInput{
		BrowserRemoteIP: "203.0.113.10",
		LedgerEntries: []LedgerEntry{
			{IP: "203.0.113.10"}, {IP: "203.0.113.11"},
		},
	})
	if !r.DNSPathConsistent {
		t.Errorf("match should set DNSPathConsistent=true")
	}
	if !contains(r.ReasonCodes, reasons.UserDNSPathMatch) {
		t.Errorf("expected USER_DNS_PATH_MATCH; got %v", r.ReasonCodes)
	}
}

func TestCompareLedger_Mismatch_EmitsMismatch(t *testing.T) {
	r := CompareLedger(CompareInput{
		BrowserRemoteIP: "198.51.100.50",
		LedgerEntries: []LedgerEntry{
			{IP: "203.0.113.10"}, {IP: "203.0.113.11"},
		},
	})
	if r.DNSPathConsistent {
		t.Errorf("mismatch must not set DNSPathConsistent")
	}
	if !contains(r.ReasonCodes, reasons.UserDNSPathMismatch) {
		t.Errorf("expected USER_DNS_PATH_MISMATCH; got %v", r.ReasonCodes)
	}
}

func TestCompareLedger_EmptyLedger_OptedInClient_EmitsBypass(t *testing.T) {
	r := CompareLedger(CompareInput{
		BrowserRemoteIP:       "198.51.100.50",
		ClientOptedIntoXGGDNS: true,
	})
	if !contains(r.ReasonCodes, reasons.ExpectedResolverBypassed) {
		t.Errorf("opted-in + empty ledger should emit EXPECTED_RESOLVER_BYPASSED; got %v", r.ReasonCodes)
	}
}

func TestCompareLedger_EmptyLedger_NonOptedInClient_NoCodes(t *testing.T) {
	r := CompareLedger(CompareInput{
		BrowserRemoteIP: "198.51.100.50",
	})
	if len(r.ReasonCodes) != 0 {
		t.Errorf("non-opted-in client + empty ledger should emit nothing; got %v", r.ReasonCodes)
	}
}
