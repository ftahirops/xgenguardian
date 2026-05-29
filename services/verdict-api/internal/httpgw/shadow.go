// shadow.go — Phase F shadow-engine wiring for the HTTP gateway.
//
// Production binds `policy.Apply` as the user-facing engine. Shadow mode
// runs a second engine on the same Inputs and emits diff metrics + a
// structured log line per diverging call. The candidate's verdict is
// NEVER returned to the user.
//
// Enable via XGG_SHADOW_ENABLED=1. With no candidate registered, the
// shadow path no-ops (identity-equivalent to plain policy.Apply).
//
// Registering a candidate: today there's no second engine to test
// (Phase E is the production engine), so shadowCandidate() returns nil
// unless XGG_SHADOW_ENABLED=1 AND an alternate engine is wired in. The
// wiring stays here so future engine changes can flip it on without
// re-touching pipeline.go.
package httpgw

import (
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/metrics"
	"github.com/xgenguardian/services/verdict-api/internal/policy"
)

// shadowCandidate returns the candidate policy to run alongside
// production, or nil if shadow mode is disabled. Returning nil makes
// RunShadow degenerate to plain Apply with one extra nil-check.
//
// Default candidate is policy.Apply itself — running the production
// engine on both sides. This is intentional: it proves the wiring works
// (clean-diff metrics non-zero, latency observed on both sides) without
// changing behavior or risking a verdict diff. When a real candidate
// lands, swap this for a reference to the candidate function.
func shadowCandidate() policy.CandidateFn {
	if goGetenv("XGG_SHADOW_ENABLED") != "1" {
		return nil
	}
	return policy.Apply
}

// recordShadowDiff emits the metric pair for one shadow run and, when
// the diff is non-clean, a single structured log line with the diff
// payload. Sampling/dedup is up to the metrics backend — every diff
// gets a counter increment so weekly review can compute distributions.
func recordShadowDiff(domain string, diff policy.Diff) {
	kind := diff.Kind()
	metrics.ShadowDiffTotal.WithLabelValues(kind).Inc()
	if diff.ProductionLatencyNs > 0 {
		metrics.ShadowLatency.WithLabelValues("production").Observe(float64(diff.ProductionLatencyNs) / 1e9)
	}
	if diff.CandidateLatencyNs > 0 {
		metrics.ShadowLatency.WithLabelValues("candidate").Observe(float64(diff.CandidateLatencyNs) / 1e9)
	}
	if diff.IsClean() {
		return
	}
	log.Info().
		Str("domain", domain).
		Str("kind", kind).
		Str("prod_verdict", string(diff.ProductionVerdict)).
		Str("cand_verdict", string(diff.CandidateVerdict)).
		Strs("reasons_added", diff.ReasonsAdded).
		Strs("reasons_removed", diff.ReasonsRemoved).
		Float64("confidence_delta", diff.ConfidenceDelta).
		Int64("prod_ns", diff.ProductionLatencyNs).
		Int64("cand_ns", diff.CandidateLatencyNs).
		Msg("shadow engine diff")
}
