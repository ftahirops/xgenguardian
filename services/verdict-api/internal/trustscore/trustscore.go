// Package trustscore aggregates positive-evidence signals into a single
// 0.0–1.0 trust score plus a list of named contributors. Phase D of
// docs/final-engine-architecture-plan.md §14.
//
// Why this exists
//
// The Phase A audit found we were patching false positives by adding
// hosts to trustreg — a binary "trust this brand for everything" hammer.
// That doesn't scale and it doesn't reflect reality: a 12-year-old
// domain with no feed hits and valid HTTPS is *probably fine* even if
// it isn't a top-50 brand, and a top-50 brand can still be compromised.
//
// trustscore is the principled middle: it consults the evidence we
// already collect (RDAP, vendor DNS, feeds, brand/org membership, TLS)
// and emits one number the policy can use to soften soft rules. It is
// NOT a verdict and it is NEVER allowed to suppress hard evidence:
//   - hidden cross-origin iframes on an untrusted page → WARN
//   - hidden cross-origin iframes on a 10-year-old, clean-feed,
//     valid-HTTPS page → trust score 0.8, soft signal suppressed
//   - credential exfiltration on the same 10-year-old page → BLOCK
//     (hard rule, ignores trust)
//
// Design constraints
//
//   - Pure function. No I/O. No global state. No caching here — the
//     caller (verdict-api pipeline) already caches the underlying
//     features it passes in.
//   - Bounded. Score is clamped to [0.0, 1.0]. Negative contributors
//     subtract; positive contributors add.
//   - Explainable. Every weight that contributed comes back as a
//     Contributor row so the evidence UI can show *why* a score was
//     high or low.
//   - Cheap to extend. Adding a new signal is one struct field + one
//     scoring block + one test row.
//
// Phase D ships the score with currently-available signals only:
// domain age, feed cleanliness, vendor DNS cleanliness, brand/org
// membership, HTTPS validity. Phase D.4 (= plan Phase E) wires it
// into soft-rule suppression. Tranco rank, ASN reputation, nameserver
// stability, and CT-log stability are listed in the plan §14 as
// "later features" — they land when we have those data sources.
package trustscore

// Signals is the input to Score. All fields are optional; zero values
// produce no contribution either way. The caller assembles this from
// existing ContextOutput / brandgraph / RDAP / TLS data.
type Signals struct {
	// DomainAgeDays — registered-age of the domain, from RDAP. 0 with
	// DomainAgeKnown=false means "we don't know."
	DomainAgeDays  int
	DomainAgeKnown bool

	// FeedClean — true when no threat-intel feed listed this domain in
	// the lookback window. False when any feed (high, medium, or low
	// tier) had a hit. Caller is responsible for deciding whether a
	// stale feed row should still count as "not clean."
	FeedClean bool

	// VendorDNSClean — true when no protective-DNS provider sinkholed
	// the domain. False when at least one provider blocked (consensus
	// blocks are a hard-rule path; here we only care that the trust
	// stays positive when *all* vendors agree the domain is fine).
	VendorDNSClean bool

	// BrandgraphFullTrust — host matched brandgraph at scope full-trust
	// (a curated canonical brand domain like google.com).
	BrandgraphFullTrust bool

	// BrandgraphAnyScope — host matched brandgraph under some scope but
	// not full-trust (e.g. gstatic.com matching ScopeScriptSource only).
	// Worth less than full trust — it's a real brand relationship, but
	// only for one action.
	BrandgraphAnyScope bool

	// OrggraphKnown — host belongs to a known organization in orggraph.
	// Independent of brandgraph: an org member that isn't a brand
	// canonical (e.g. moviesanywhere.com inside Disney) still carries
	// a small positive signal that the operator is real.
	OrggraphKnown bool

	// HTTPSValid — TLS certificate chain validated for the host. Phase B
	// connection identity. Absent (false) does not subtract — it just
	// doesn't add — because plenty of legitimate HTTP-only pages exist
	// in dev/intranet contexts.
	HTTPSValid bool

	// HistoricalCleanCount — number of prior ALLOW verdicts for this
	// host in our own scan history. Caps at 50 in the scoring math so a
	// single brand can't dominate the score.
	HistoricalCleanCount int
}

// Contributor is one row of the explanation: a short stable label and
// the weight it added (positive) or subtracted (negative). The evidence
// UI renders these as a sorted list.
type Contributor struct {
	Label  string
	Weight float64
}

// Result is the trust-score output.
type Result struct {
	// Score is clamped to [0.0, 1.0]. 0.5 is neutral.
	Score float64
	// Contributors lists every signal that moved the score, in input order.
	// Empty when no signal fired.
	Contributors []Contributor
}

// Score computes the trust score from Signals.
//
// Weighting rationale (kept conservative — these tune in Phase D.4 once
// we have real soft-rule suppression telemetry):
//
//   - domain age is the strongest single positive (an 8+ year old domain
//     is rarely a phishing kit)
//   - feed cleanliness and vendor-DNS cleanliness are independent
//     corroborators; both clean is meaningful
//   - brandgraph full-trust adds the most among membership signals;
//     scope-only and orggraph-only add less
//   - HTTPS validity is small — it's table stakes, not strong evidence
//   - historical clean verdicts add slowly to avoid one-brand dominance
//
// The starting neutral is 0.30, not 0.50: a domain we have zero positive
// evidence for is mildly suspect by default. This matters when the
// caller multiplies score against a soft-signal weight — neutral
// shouldn't equal "definitely safe."
func Score(s Signals) Result {
	out := Result{Score: 0.30}

	add := func(label string, w float64) {
		out.Contributors = append(out.Contributors, Contributor{Label: label, Weight: w})
		out.Score += w
	}

	if s.DomainAgeKnown {
		switch {
		case s.DomainAgeDays >= 365*8:
			add("domain age ≥ 8 years", 0.30)
		case s.DomainAgeDays >= 365*3:
			add("domain age ≥ 3 years", 0.20)
		case s.DomainAgeDays >= 365:
			add("domain age ≥ 1 year", 0.10)
		case s.DomainAgeDays >= 90:
			add("domain age ≥ 90 days", 0.03)
		case s.DomainAgeDays < 30:
			add("domain registered < 30 days", -0.10)
		}
	}

	if s.FeedClean {
		add("no threat-feed hits", 0.10)
	}
	if s.VendorDNSClean {
		add("no protective-DNS blocks", 0.10)
	}

	if s.BrandgraphFullTrust {
		add("curated brand domain", 0.20)
	} else if s.BrandgraphAnyScope {
		add("known scoped brand relationship", 0.10)
	}
	if s.OrggraphKnown {
		add("member of known organization", 0.05)
	}

	if s.HTTPSValid {
		add("HTTPS certificate valid", 0.03)
	}

	if s.HistoricalCleanCount > 0 {
		n := s.HistoricalCleanCount
		if n > 50 {
			n = 50
		}
		// 0.002 per prior clean → 0.10 cap at 50 verdicts.
		add("historical clean verdicts", 0.002*float64(n))
	}

	if out.Score < 0.0 {
		out.Score = 0.0
	}
	if out.Score > 1.0 {
		out.Score = 1.0
	}
	return out
}
