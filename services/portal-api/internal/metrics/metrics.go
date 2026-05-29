// Package metrics — Prometheus metric declarations for portal-api.
//
// All metrics use the "xgg_" prefix for namespacing. Call MustRegister
// once at startup with prometheus.DefaultRegisterer.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// EvidenceRequestsTotal counts /v1/evidence/:id requests labeled by HTTP status.
	EvidenceRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xgg_evidence_requests_total",
			Help: "HTTP requests to /v1/evidence/:id labeled by HTTP status code.",
		},
		[]string{"status"},
	)

	// EvidenceLatency tracks request duration for evidence endpoint requests.
	EvidenceLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "xgg_evidence_latency_seconds",
			Help:    "Request duration for /v1/evidence/:id.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
		},
	)

	// PresignErrorsTotal counts MinIO presign failures.
	PresignErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "xgg_presign_errors_total",
			Help: "MinIO presign URL generation failures.",
		},
	)
)

// MustRegister registers all portal-api metrics with the given registerer.
func MustRegister(r prometheus.Registerer) {
	r.MustRegister(
		EvidenceRequestsTotal,
		EvidenceLatency,
		PresignErrorsTotal,
	)
}
