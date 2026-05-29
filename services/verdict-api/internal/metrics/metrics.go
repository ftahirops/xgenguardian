// Package metrics — Prometheus metric declarations for verdict-api.
//
// All metrics use the "xgg_" prefix for namespacing. Call MustRegister
// once at startup with prometheus.DefaultRegisterer.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Verdict pipeline counters and histograms.
var (
	// VerdictTotal counts verdicts emitted by the policy engine, labeled by
	// verdict (ALLOW/BLOCK/WARN/ISOLATE/CLEAN/ANALYZING) and protection mode.
	VerdictTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_verdict_total",
			Help: "Verdicts emitted by the policy engine.",
		},
		[]string{"verdict", "mode"},
	)

	// VerdictLatency tracks the full pipeline latency, labeled by tier.
	// Tier label is one of: "tier1_only", "tier2", "cached".
	VerdictLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "xgg_verdict_latency_seconds",
			Help:    "Pipeline duration from request arrival to verdict return.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30},
		},
		[]string{"tier"},
	)

	// VerdictCacheTotal counts verdict cache hits vs misses.
	VerdictCacheTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_verdict_cache_total",
			Help: "Verdict cache hits and misses.",
		},
		[]string{"result"},
	)

	// RenderCacheTotal counts sandbox render cache hits vs misses.
	RenderCacheTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_render_cache_total",
			Help: "Sandbox render cache hits and misses.",
		},
		[]string{"result"},
	)

	// VendorDNSLatency tracks the time taken for vendor DNS consensus queries
	// (including Redis cache lookup + live query when a miss occurs).
	VendorDNSLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "xgg_vendordns_latency_seconds",
			Help:    "Vendor DNS consensus query duration (cache + live combined).",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2},
		},
	)

	// VendorDNSBlockTotal counts when 2+ providers block a domain. The label
	// "providers" is the string count of blocking providers (e.g. "2", "3").
	VendorDNSBlockTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_vendordns_block_total",
			Help: "Vendor DNS consensus blocks (≥2 providers agree).",
		},
		[]string{"providers"},
	)

	// RateLimitHitTotal counts rate-limit denials by kind: "client" or "ip".
	RateLimitHitTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_ratelimit_hit_total",
			Help: "Rate-limit denials by kind (client vs ip).",
		},
		[]string{"kind"},
	)

	// Tier1Score records the distribution of Tier-1 score values for tuning.
	Tier1Score = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "xgg_tier1_score",
			Help:    "Tier-1 score distribution (0.0–1.0) for threshold tuning.",
			Buckets: prometheus.LinearBuckets(0, 0.05, 21), // 0.00 to 1.00 in 0.05 steps
		},
	)

	// SandboxFailuresTotal counts sandbox call failures by reason.
	// Reason labels: "timeout", "502", "unreachable", "auth", "other".
	SandboxFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_sandbox_failures_total",
			Help: "Sandbox (sandbox-render) call failures by reason.",
		},
		[]string{"reason"},
	)

	// RedisErrorsTotal counts Redis operation errors by op: "GET", "SET".
	RedisErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_redis_errors_total",
			Help: "Redis operation errors by op type.",
		},
		[]string{"op"},
	)

	// RuleFiredTotal — every time a policy rule appends a reason code to
	// the verdict, this counter increments with the reason code as the
	// label. The Phase-A baseline metric for "which rules cause the most
	// FPs/FNs in production." A weekly rule-health report compares
	// xgg_rule_fired_total against xgg_rule_override_total (TODO: requires
	// extension telemetry pipeline) to surface the rules that fire most
	// often relative to user overrides.
	RuleFiredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_rule_fired_total",
			Help: "Verdict-engine rule emissions by reason code. Use with xgg_rule_override_total (when extension telemetry lands) to compute per-rule override rate.",
		},
		[]string{"code"},
	)

	// ShadowDiffTotal — Phase F. Counts shadow-engine outcomes by kind:
	//   "clean"            — candidate matched production exactly
	//   "verdict_changed"  — verdict flipped
	//   "reasons_added"    — same verdict, candidate added reason codes
	//   "reasons_removed"  — same verdict, candidate dropped reason codes
	// A weekly review of verdict_changed + reasons_added is the gate to
	// promote a candidate engine to production.
	ShadowDiffTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_shadow_diff_total",
			Help: "Shadow-engine diff outcomes by kind (clean/verdict_changed/reasons_added/reasons_removed).",
		},
		[]string{"kind"},
	)

	// ShadowLatency — Phase F. Per-engine wall-clock for shadow runs.
	// Label engine ∈ {"production","candidate"}. Used to budget the
	// candidate before promotion (must not exceed production p99 by
	// more than a small margin).
	ShadowLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "xgg_shadow_engine_latency_seconds",
			Help:    "Per-engine policy.Apply wall-clock during shadow runs.",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		},
		[]string{"engine"},
	)
)

// MustRegister registers all verdict-api metrics with the given registerer.
// Panics if a metric with the same name is already registered (programming
// error). Call once at program startup.
func MustRegister(r prometheus.Registerer) {
	r.MustRegister(
		VerdictTotal,
		VerdictLatency,
		VerdictCacheTotal,
		RenderCacheTotal,
		VendorDNSLatency,
		VendorDNSBlockTotal,
		RateLimitHitTotal,
		Tier1Score,
		SandboxFailuresTotal,
		RedisErrorsTotal,
		RuleFiredTotal,
		ShadowDiffTotal,
		ShadowLatency,
	)
}
