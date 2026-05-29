package brandgraph

import (
	"testing"

	"github.com/xgenguardian/services/verdict-api/internal/trustreg"
)

// TestBackfill_BrandgraphCoversAllTrustreg — after init backfill,
// brandgraph.IsAnyTrust must return true for every trustreg-trusted host.
// If this drifts, Phase C.2 call-site switches silently lose trust on
// real brands.
func TestBackfill_BrandgraphCoversAllTrustreg(t *testing.T) {
	for _, e := range trustreg.Entries() {
		for _, h := range e.Hosts {
			if !IsAnyTrust(h) {
				t.Errorf("brandgraph missing trustreg host %q (brand=%s)", h, e.Brand)
			}
		}
	}
}

// TestBackfill_PreservesCuratedScope — gstatic.com was curated as
// ScopeScriptSource in the brandgraph stub before backfill. The
// backfill must NOT overwrite it with ScopeFullTrust just because
// trustreg also lists gstatic.com.
//
// This is the load-bearing invariant: brandgraph's whole purpose is
// tighter-than-trustreg scopes. If backfill clobbers curated scopes,
// the migration regressed the model.
func TestBackfill_PreservesCuratedScope(t *testing.T) {
	// gstatic.com is in trustreg as a Google host and in the
	// brandgraph stub as ScopeScriptSource via the suffix
	// .gstatic.com. A login query against e.g. assets.gstatic.com
	// must NOT match — it's a CDN, not a login destination.
	m := Trust("assets.gstatic.com", ScopeLogin)
	if m.Brand != "" {
		t.Errorf("assets.gstatic.com must not be trusted for login; got %+v", m)
	}
	m = Trust("assets.gstatic.com", ScopeScriptSource)
	if m.Brand != "google" {
		t.Errorf("assets.gstatic.com must be trusted for script-source; got %+v", m)
	}
}

// TestBackfill_FullTrustHostsAreLogin — a brand's primary login host
// (e.g. accounts.google.com, login.live.com) should match ScopeLogin
// because it was curated that way in the stub. Trustreg backfill
// must not regress this either.
func TestBackfill_FullTrustHostsAreLogin(t *testing.T) {
	for _, host := range []string{"accounts.google.com", "login.live.com", "appleid.apple.com"} {
		m := Trust(host, ScopeLogin)
		if m.Brand == "" {
			t.Errorf("login host %q should match ScopeLogin after backfill; got %+v", host, m)
		}
	}
}
