// Package risk — normalized 0..1 risk-score model + per-mode threshold
// mapping. Phase 1 of the §23.3 threshold migration: emit the candidate
// score in shadow without enforcing it. The production verdict still
// comes from the existing soft-rule accumulator (policy.softAccum) and
// the per-rule reason-code branches in policy.Apply. This file is the
// candidate replacement, computed in parallel and surfaced through the
// shadow-engine harness (Phase F) for diff review.
//
// Five-phase migration plan (from DeepTrust §23.3):
//
//	Phase 1  log normalized candidate score in shadow         ← we are here
//	Phase 2  compare old accumulator verdict vs normalized
//	         verdict on the smoke corpus, weekly
//	Phase 3  tune thresholds until FP/FN deltas pass budget
//	Phase 4  enforce normalized score only after shadow
//	         approval (corpus + RUAT + SLO unchanged)
//	Phase 5  remove the old accumulator
//
// The normalized score consumes ALL signals at the verdict layer —
// soft-rule fires, support-scam score, homoglyph-match, trust score
// contributions — and yields a single number per request that's
// trivially compared to per-mode thresholds. The advantage over the
// current unbounded-sum accumulator: a single comparable number with
// per-mode policy (Safe/Normal/Strict/Ultra) rather than one global
// threshold.
package risk

// Inputs is everything the normalizer needs to score the page. Mirror
// of the (subset of) fields policy.Apply already reads — kept loosely
// coupled so the package stays testable without importing policy.
type Inputs struct {
	// SoftRisk — current soft accumulator total (unbounded). The
	// normalizer caps this at a configurable saturation point to
	// produce a bounded contribution.
	SoftRisk float64

	// SupportScamScore — from internal/supportscam (Wave 3 Phase 1).
	// Already in [0, 1.5].
	SupportScamScore float64

	// HomoglyphHardFired — true when the Stage-IS hard rule fired.
	// Equivalent to a "near-certain impersonation" signal — the
	// normalizer treats it as a strong floor (>= 0.85) without
	// dominating; the policy rule already handles the verdict.
	HomoglyphHardFired bool

	// TrustScore — Phase D positive evidence aggregate. In [0, 1].
	// Suppresses noisy soft signals (but never the hard floor).
	TrustScore float64

	// SensitivePage — page class is login/payment/oauth/install.
	// Sensitive pages get a fixed-floor adjustment so the
	// thresholds for WARN/BLOCK are tighter on credential-collecting
	// pages than on read-only content.
	SensitivePage bool

	// FreshDomain — RDAP says <7d AND known.
	FreshDomain bool

	// VendorDNSWarn — exactly one provider blocked (< consensus).
	VendorDNSWarn bool
}

// Result is the normalizer output. Phase 1 callers attach this to the
// shadow trace; it does not drive enforcement.
type Result struct {
	// Score — final normalized [0, 1] number. 0 is "definitely safe
	// by every signal we have"; 1 is "every signal independently
	// says block."
	Score float64

	// Contributors — each input's contribution to the final score,
	// in display order (largest first). Lets the trace show the user
	// "the score came from these signals."
	Contributors []Contributor
}

// Contributor is one named signal + its contribution to Score. Stable
// labels so the trace and tests can pin behavior.
type Contributor struct {
	Label string
	Weight float64
}

// Compute is the normalizer. Pure function. The math is intentionally
// simple: each signal contributes a clamped slice; the slices sum;
// trust suppresses soft contribution only.
//
// Phase-1 design notes:
//   - We do NOT collapse hard-rule fires (vendor-DNS consensus, feed
//     high, raw-IP binary, PUBLIC_DOMAIN_PRIVATE_IP) into the score.
//     Those are pre-score verdict short-circuits and stay in policy.Apply.
//   - We DO include the soft-rule accumulator + the new support-scam
//     score + the homoglyph hard floor. These are the signals the
//     §23.3 migration cares about — turning "unbounded sum vs single
//     threshold" into "[0,1] vs per-mode thresholds."
//   - Trust suppression follows the same rule as the existing soft-rule
//     gating: trust subtracts from the soft+context contribution, never
//     from the homoglyph floor.
func Compute(in Inputs) Result {
	r := Result{}

	// Soft-rule contribution — saturating curve so that very large
	// unbounded sums don't dominate the score. Cap at 0.50 so soft
	// rules alone can produce WARN in Safe mode but never BLOCK.
	if in.SoftRisk > 0 {
		soft := in.SoftRisk / (in.SoftRisk + 1.0) // saturating in [0, 1)
		// Trust suppresses up to 50% of the soft contribution.
		suppress := in.TrustScore * 0.5
		if suppress > 1.0 {
			suppress = 1.0
		}
		soft *= (1.0 - suppress)
		if soft > 0.50 {
			soft = 0.50
		}
		if soft > 0 {
			r.Score += soft
			r.Contributors = append(r.Contributors, Contributor{
				Label:  "soft_accumulator",
				Weight: soft,
			})
		}
	}

	// Support-scam — already in [0, 1.5]. Normalize to [0, 0.45]
	// so a maxed-out support-scam alone is below BLOCK in Safe mode
	// (0.55) but above WARN (0.30). Composite scams cross BLOCK via
	// the dedicated SS-stage hard rule, not this normalizer.
	if in.SupportScamScore > 0 {
		ss := in.SupportScamScore / 1.5 * 0.45
		if ss > 0.45 {
			ss = 0.45
		}
		r.Score += ss
		r.Contributors = append(r.Contributors, Contributor{
			Label:  "support_scam",
			Weight: ss,
		})
	}

	// Homoglyph floor — when the IS hard rule fired, the score is
	// floored to 0.85. We do NOT add on top — the IS rule already
	// emits the verdict; the normalizer is observability, and this
	// floor exists so any future "normalized only" policy still
	// produces the same verdict.
	if in.HomoglyphHardFired && r.Score < 0.85 {
		add := 0.85 - r.Score
		r.Score = 0.85
		r.Contributors = append(r.Contributors, Contributor{
			Label:  "homoglyph_floor",
			Weight: add,
		})
	}

	// Page-class adjustment — sensitive pages add a 0.05 baseline
	// to the score so the WARN threshold is effectively 0.05 lower
	// on credential-collecting pages.
	if in.SensitivePage {
		r.Score += 0.05
		r.Contributors = append(r.Contributors, Contributor{
			Label:  "sensitive_page",
			Weight: 0.05,
		})
	}

	// Fresh-domain — small bump on its own; the verdict-driving
	// fresh-domain hard rule still runs in policy.Apply.
	if in.FreshDomain {
		r.Score += 0.10
		r.Contributors = append(r.Contributors, Contributor{
			Label:  "fresh_domain",
			Weight: 0.10,
		})
	}

	// Vendor-DNS single hit — too noisy to BLOCK on its own; bump
	// score so it compounds with other signals.
	if in.VendorDNSWarn {
		r.Score += 0.08
		r.Contributors = append(r.Contributors, Contributor{
			Label:  "vendor_dns_warn",
			Weight: 0.08,
		})
	}

	if r.Score > 1.0 {
		r.Score = 1.0
	}
	return r
}

// Mode is one of the operator-facing protection modes. The thresholds
// table is the canonical mapping from DeepTrust §15.
type Mode string

const (
	ModeNormal   Mode = "normal"
	ModeSafe     Mode = "safe"
	ModeStrict   Mode = "strict"
	ModeParanoid Mode = "paranoid"
)

// Thresholds returns the warn/block thresholds for a mode. Per the
// DeepTrust §15 per-mode table.
func Thresholds(m Mode) (warn, block float64) {
	switch m {
	case ModeNormal:
		return 0.70, 0.95
	case ModeSafe:
		return 0.55, 0.85
	case ModeStrict:
		return 0.45, 0.80
	case ModeParanoid:
		return 0.35, 0.75
	}
	// Default to Safe — the mode the extension ships with.
	return 0.55, 0.85
}

// CandidateVerdict maps Score → verdict band under the given mode.
// Phase 1 callers compare this against the production verdict in the
// shadow diff; Phase 4 callers will use this for enforcement.
type CandidateVerdict string

const (
	CandidateAllow CandidateVerdict = "ALLOW"
	CandidateWarn  CandidateVerdict = "WARN"
	CandidateBlock CandidateVerdict = "BLOCK"
)

// VerdictFor maps a Result.Score to a candidate verdict under mode m.
// No ISOLATE band here — that's a sensitive-page-specific decision
// made by the policy rules around the score, not by the score alone.
func VerdictFor(score float64, m Mode) CandidateVerdict {
	warn, block := Thresholds(m)
	switch {
	case score >= block:
		return CandidateBlock
	case score >= warn:
		return CandidateWarn
	}
	return CandidateAllow
}
