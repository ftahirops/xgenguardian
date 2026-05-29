// Backfill from trustreg — Phase C.1.
//
// brandgraph is the long-term home for scope-aware trust. trustreg held
// flat hostname lists. The two co-exist during migration so call sites
// can move one at a time. To keep behavior identical while we move them,
// the brandgraph stub maps must contain at least everything trustreg
// knows — otherwise switching a call site from trustreg.IsTrusted to
// brandgraph.IsAnyTrust silently strips trust from real brands.
//
// Backfill rule: every trustreg host/suffix that is NOT already in the
// curated brandgraph stub gets a ScopeFullTrust entry. Curated entries
// (e.g. gstatic.com = ScopeScriptSource) are preserved — the whole point
// of brandgraph is to express tighter scopes than trustreg could.
//
// This runs at package init() so the in-process stub is correct before
// any call site can read it. Postgres-backed Store, when wired, still
// wins via liveStore() in Trust/IsAnyTrust/BrandFor.

package brandgraph

import "github.com/xgenguardian/services/verdict-api/internal/trustreg"

func init() {
	backfillFromTrustreg()
}

func backfillFromTrustreg() {
	for _, e := range trustreg.Entries() {
		for _, h := range e.Hosts {
			h = normalize(h)
			if h == "" {
				continue
			}
			if _, exists := stubLookup[h]; exists {
				continue
			}
			stubLookup[h] = Match{
				Brand:      e.Brand,
				Scope:      ScopeFullTrust,
				Confidence: "high",
			}
		}
		for _, s := range e.Suffixes {
			s = normalize(s)
			if s == "" {
				continue
			}
			// trustreg stores suffixes with leading dot ("\.google.com"
			// becomes ".google.com" after normalize); the stub map uses
			// the same form so HasSuffix in Trust() works directly.
			if _, exists := stubSuffixLookup[s]; exists {
				continue
			}
			stubSuffixLookup[s] = Match{
				Brand:      e.Brand,
				Scope:      ScopeFullTrust,
				Confidence: "high",
			}
		}
	}
}
