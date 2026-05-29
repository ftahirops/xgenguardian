// Package policy — Phase F shadow-engine harness.
//
// Shadow mode runs a *candidate* policy alongside the production policy on
// the same inputs and reports the diff. The user-facing verdict is always
// the production result; the candidate's output never leaks into the
// response. This is the rollout mechanism for future engine changes — any
// non-trivial policy change should ride in shadow for a week of production
// traffic and be reviewed against:
//
//   - per-reason-code diff distribution
//   - verdict-change distribution (which way did the candidate move?)
//   - latency overhead (candidate must stay within budget)
//   - corpus + RUAT + SLO regressions
//
// Promotion (candidate → production) happens by swapping the call in
// pipeline.go to invoke the new function as `Apply` and decommissioning
// the old one. Shadow is the *evidence* for that swap, not a feature flag
// that ships two engines forever.
package policy

import (
	"sort"
	"time"
)

// CandidateFn is the shape of a candidate policy. It must be pure (given
// the same Inputs, produce the same Result) and must not mutate the
// Inputs struct — the production engine is called on the same value
// immediately afterward.
type CandidateFn func(Inputs) Result

// Diff describes how a candidate engine's output differs from production
// on the same Inputs. The zero value (no diff fields set) means the
// engines agreed perfectly.
type Diff struct {
	// VerdictChanged is true when production and candidate disagree on the
	// final verdict (ALLOW/WARN/BLOCK/ISOLATE). This is the headline
	// disagreement — every flip here is a candidate review item.
	VerdictChanged bool

	// ProductionVerdict / CandidateVerdict — captured for the log line so
	// reviewers don't need to re-resolve from upstream context.
	ProductionVerdict Verdict
	CandidateVerdict  Verdict

	// ReasonsAdded — reason codes the candidate emitted but production did
	// not. Sorted, deduped.
	ReasonsAdded []string

	// ReasonsRemoved — reason codes production emitted but candidate did
	// not. Sorted, deduped.
	ReasonsRemoved []string

	// ConfidenceDelta — candidate.Confidence - production.Confidence.
	// Useful for spotting "same verdict, drifting confidence" cases.
	ConfidenceDelta float64

	// ProductionLatencyNs / CandidateLatencyNs — wall-clock execution
	// time for each engine on this single call. Per-call jitter is
	// noisy; aggregate via the histogram metric for budget tracking.
	ProductionLatencyNs int64
	CandidateLatencyNs  int64
}

// IsClean reports whether the engines agreed observably — same verdict,
// same set of reason codes. Confidence drift alone does not count as
// a diff for promotion purposes (the production verdict is unchanged).
func (d Diff) IsClean() bool {
	return !d.VerdictChanged &&
		len(d.ReasonsAdded) == 0 &&
		len(d.ReasonsRemoved) == 0
}

// Kind returns the most salient diff category for the metric label.
// Order of precedence: verdict_changed > reasons_added > reasons_removed
// > clean. A candidate that both adds and removes reasons but keeps the
// verdict is recorded as "reasons_added" — the additive change is the
// more reviewable signal.
func (d Diff) Kind() string {
	switch {
	case d.VerdictChanged:
		return "verdict_changed"
	case len(d.ReasonsAdded) > 0:
		return "reasons_added"
	case len(d.ReasonsRemoved) > 0:
		return "reasons_removed"
	default:
		return "clean"
	}
}

// Compare diffs two Result snapshots from the same Inputs. Pure function
// over its arguments; callers populate the latency fields themselves.
func Compare(prod, cand Result) Diff {
	d := Diff{
		ProductionVerdict: prod.Verdict,
		CandidateVerdict:  cand.Verdict,
		VerdictChanged:    prod.Verdict != cand.Verdict,
		ConfidenceDelta:   cand.Confidence - prod.Confidence,
	}
	d.ReasonsAdded, d.ReasonsRemoved = diffReasonCodes(prod.ReasonCodes, cand.ReasonCodes)
	return d
}

// RunShadow runs production Apply and the supplied candidate on the same
// Inputs, returns the production result, and the diff. The production
// result is what callers must return to the user — the candidate result
// is discarded after the diff is computed.
//
// If candidate is nil, RunShadow is exactly equivalent to Apply (and a
// zero Diff is returned). Callers gate the candidate by env / config so
// the no-op path costs only one extra nil-check per request.
func RunShadow(in Inputs, candidate CandidateFn) (Result, Diff) {
	start := time.Now()
	prod := Apply(in)
	prodNs := time.Since(start).Nanoseconds()

	if candidate == nil {
		return prod, Diff{
			ProductionVerdict:   prod.Verdict,
			CandidateVerdict:    prod.Verdict,
			ProductionLatencyNs: prodNs,
		}
	}

	candStart := time.Now()
	cand := candidate(in)
	candNs := time.Since(candStart).Nanoseconds()

	d := Compare(prod, cand)
	d.ProductionLatencyNs = prodNs
	d.CandidateLatencyNs = candNs
	return prod, d
}

// diffReasonCodes returns (onlyInB, onlyInA) — codes the candidate added
// (onlyInB) and codes production had that the candidate dropped (onlyInA).
// Output is sorted and deduplicated so test assertions and log lines are
// stable across runs.
func diffReasonCodes(a, b []string) (added, removed []string) {
	aset := make(map[string]struct{}, len(a))
	for _, x := range a {
		aset[x] = struct{}{}
	}
	bset := make(map[string]struct{}, len(b))
	for _, x := range b {
		bset[x] = struct{}{}
	}
	for x := range bset {
		if _, ok := aset[x]; !ok {
			added = append(added, x)
		}
	}
	for x := range aset {
		if _, ok := bset[x]; !ok {
			removed = append(removed, x)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
