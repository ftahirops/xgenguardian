// Package metrics — Prometheus metric declarations for resolver.
//
// All metrics use the "xgg_" prefix for namespacing. Call MustRegister
// once at startup with prometheus.DefaultRegisterer.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// DNSQueriesTotal counts DNS queries labeled by rcode (NOERROR, NXDOMAIN,
	// REFUSED, SERVFAIL, etc.) so operators can track policy enforcement ratios.
	DNSQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_dns_queries_total",
			Help: "DNS queries resolved, labeled by rcode (NOERROR, NXDOMAIN, REFUSED, etc.).",
		},
		[]string{"rcode"},
	)

	// DNSLatency tracks per-query resolution duration end-to-end.
	DNSLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "xgg_dns_latency_seconds",
			Help:    "DNS query resolution duration from receipt to response.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		},
	)

	// VerdictAPICallsTotal counts calls from resolver to verdict-api, labeled by
	// result: "success", "timeout", or "error".
	VerdictAPICallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_verdict_api_calls_total",
			Help: "Resolver → verdict-api HTTP calls, labeled by result.",
		},
		[]string{"result"},
	)
)

// MustRegister registers all resolver metrics with the given registerer.
func MustRegister(r prometheus.Registerer) {
	r.MustRegister(
		DNSQueriesTotal,
		DNSLatency,
		VerdictAPICallsTotal,
	)
}
