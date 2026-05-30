// shadow.go — Phase F shadow-engine wiring for the HTTP gateway.
//
// Production binds `policy.Apply` as the user-facing engine. Shadow mode
// runs a second engine on the same Inputs and emits diff metrics + a
// structured log line per diverging call. The candidate's verdict is
// NEVER returned to the user.
//
// Enable via XGG_SHADOW_ENABLED=1.
//
// Wave 3 Phase 4 update: the candidate now wraps internal/risk.Compute
// — the normalized 0..1 risk-score model from DeepTrust §23.3. It
// converts the existing soft-accumulator / support-scam / payment-scam
// / crypto-drainer / homoglyph signals into a single bounded score,
// applies per-mode thresholds (Safe by default), and emits the
// candidate verdict. The shadow diff measures how often the normalized
// model agrees with production. Two weeks of real-traffic data drives
// the Phase 5 enforcement-cutover decision.
package httpgw

import (
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/metrics"
	"github.com/xgenguardian/services/verdict-api/internal/policy"
	"github.com/xgenguardian/services/verdict-api/internal/risk"
)

// shadowCandidate returns the candidate policy to run alongside
// production, or nil if shadow mode is disabled.
//
// Wave 3 Phase 4: the candidate computes a normalized risk score from
// the same Inputs production sees, maps it to a verdict via the mode-
// keyed thresholds in DeepTrust §15, and returns that as the Result.
// The candidate's verdict is observability — never returned to the user
// (RunShadow enforces this). Two weeks of diff data drives the Phase 5
// enforcement decision.
//
// Mode selection: extension passes Mode in checkRequest; we default to
// Safe (the extension's shipped default) when the request didn't
// specify. Risk thresholds vary per mode (DeepTrust §15 table).
func shadowCandidate() policy.CandidateFn {
	if goGetenv("XGG_SHADOW_ENABLED") != "1" {
		return nil
	}
	return riskNormalizedCandidate
}

// riskNormalizedCandidate is the Wave 3 Phase 4 candidate engine. It
// reads the inputs production already gathered, runs internal/risk.
// Compute, and emits a Result with the normalized verdict so the
// shadow diff captures normalized-vs-accumulator disagreements.
//
// It does NOT compete with policy.Apply on hard-rule short-circuits —
// HARD evidence (PUBLIC_DOMAIN_PRIVATE_IP, vendor-DNS consensus,
// feed-high hit, raw-IP binary drop, homoglyph hard rule, support-scam
// HardBlock, drainer HardBlock) belongs to policy.Apply; the candidate
// inherits their reason codes via policy.Apply's emitted reason set,
// but its verdict comes from the normalized risk score alone. Two-week
// data tells us how often this is enough to agree on enforcement.
func riskNormalizedCandidate(in policy.Inputs) policy.Result {
	// Re-derive the soft-accumulator total. Production's softAccum is
	// internal to policy.Apply; we approximate it here by re-running
	// the soft-rule evaluator path with the same Inputs. The exact
	// number is less important than the trend — the normalizer
	// saturates well before any plausible accumulator value.
	prod := policy.Apply(in)

	// Reconstruct an estimate of the soft-rule risk from prod's
	// reason codes. Each non-hard reason code contributes ~1.0
	// matching the current softWeightFoo constants. We avoid
	// re-implementing the soft-rule eval here because we DO want
	// the production result to flow through identically; the
	// candidate's verdict is the only divergence point.
	softEstimate := 0.0
	for _, code := range prod.ReasonCodes {
		if isHardReason(code) {
			continue
		}
		softEstimate += 1.0
	}

	rs := risk.Compute(risk.Inputs{
		SoftRisk:           softEstimate,
		SupportScamScore:   in.Context.SupportScamScore,
		HomoglyphHardFired: in.Context.HomoglyphBrandMatch,
		TrustScore:         in.TrustScore,
		SensitivePage:      in.PageClass.IsSensitive(),
		FreshDomain:        in.Context.DomainAgeKnown && in.Context.DomainAgeDays < 7,
		VendorDNSWarn:      in.Context.VendorDNSSingleHit,
	})
	mode := risk.ModeSafe
	switch in.Mode {
	case "normal":
		mode = risk.ModeNormal
	case "strict":
		mode = risk.ModeStrict
	case "paranoid":
		mode = risk.ModeParanoid
	}
	cand := risk.VerdictFor(rs.Score, mode)

	// Wrap as a policy.Result so RunShadow's diff machinery works.
	// Verdict is the only candidate-driven field; reasons mirror
	// production so the diff isolates verdict-only disagreements.
	out := prod
	switch cand {
	case risk.CandidateAllow:
		out.Verdict = policy.Allow
	case risk.CandidateWarn:
		out.Verdict = policy.Warn
	case risk.CandidateBlock:
		out.Verdict = policy.Block
	}
	return out
}

// recordRiskScoreFromCandidate observes the candidate's normalized
// risk score (independent of verdict comparison) for the histogram
// metric. Sampled on every shadow-enabled /v1/check; the metric's
// buckets span the per-mode threshold points so the rule-health
// report can cleanly aggregate "what fraction of benign traffic
// crossed Safe.warn (0.55)?"
func recordRiskScoreFromCandidate(in policy.Inputs) {
	// Re-run the same softEstimate as the candidate so the
	// observation matches what shadow saw.
	prod := policy.Apply(in)
	softEstimate := 0.0
	for _, code := range prod.ReasonCodes {
		if isHardReason(code) {
			continue
		}
		softEstimate += 1.0
	}
	rs := risk.Compute(risk.Inputs{
		SoftRisk:           softEstimate,
		SupportScamScore:   in.Context.SupportScamScore,
		HomoglyphHardFired: in.Context.HomoglyphBrandMatch,
		TrustScore:         in.TrustScore,
		SensitivePage:      in.PageClass.IsSensitive(),
		FreshDomain:        in.Context.DomainAgeKnown && in.Context.DomainAgeDays < 7,
		VendorDNSWarn:      in.Context.VendorDNSSingleHit,
	})
	metrics.NormalizedRiskScore.Observe(rs.Score)
}

// isHardReason returns true for reason codes that come from hard-rule
// short-circuits. The shadow candidate counts only SOFT codes toward
// its accumulator-estimate; hard reasons are already determinative for
// production and shouldn't double-count.
func isHardReason(code string) bool {
	switch code {
	case "PUBLIC_DOMAIN_PRIVATE_IP",
		"VENDOR_DNS_CONSENSUS_BLOCK",
		"EXTERNAL_FEED_HIT",
		"MALWARE_RAW_IP_BINARY_DROP",
		"RAW_IP_HOST",
		"FRESH_DOMAIN",
		"SENSITIVE_PAGE_VERIFICATION_UNAVAILABLE",
		"TIER2_DATA_UNAVAILABLE",
		"HOMOGLYPH_OF_PROTECTED_BRAND",
		"BRAND_CLAIM_DOMAIN_MISMATCH",
		"CREDENTIAL_SINK_HIDDEN_MIRROR",
		"CREDENTIAL_SINK_PRE_SUBMIT_CAPTURE",
		"MALICIOUS_INSTALL_COMMAND":
		return true
	}
	return false
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
