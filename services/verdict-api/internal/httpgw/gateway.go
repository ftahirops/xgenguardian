// Package httpgw — HTTP gateway for verdict-api.
//
// The browser-facing portal and any non-gRPC caller hits this gateway.
// It is a thin JSON wrapper around the same internal verdict pipeline
// the gRPC server uses.
//
// Routes:
//   GET  /healthz
//   POST /v1/check       { "url": "https://..." }     -> verdict JSON
//   POST /v1/rescan      { "url": "https://..." }     -> forces re-scan
//   GET  /v1/domain/{d}                               -> domain verdict
package httpgw

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/feeds"
	"github.com/xgenguardian/services/verdict-api/internal/oauthreg"
	"github.com/xgenguardian/services/verdict-api/internal/rdap"
	"github.com/xgenguardian/services/verdict-api/internal/registry"
)

type Server struct {
	Pg          *pgxpool.Pool
	Rdb         *redis.Client
	Brands      *registry.Cache
	RDAP        *rdap.Client          // optional; nil disables domain-age signal
	WebRisk     *feeds.WebRiskClient  // optional; nil disables corroborator
	OAuthReg    *oauthreg.Cache       // optional; nil disables OAuth check
	Tier1Budget time.Duration

	// sandboxCoalescer dedups in-flight sandbox renders by normalized URL.
	// Lazy-initialized on first use so tests that don't render don't
	// need to instantiate. See coalesce.go.
	sandboxCoalescer     *coalescer
	sandboxCoalescerOnce sync.Once
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/v1/check", s.check)
	mux.HandleFunc("/v1/rescan", s.rescan)
	mux.HandleFunc("/v1/scan",   s.scan)
	mux.HandleFunc("/v1/stream", s.stream)
	// Copy-button mediation endpoint: extension calls this on every copy
	// from a code block. Must respond fast (<100ms target) — no sandbox,
	// no DB writes, pure in-memory pattern matching + installreg lookup.
	mux.HandleFunc("/v1/command-check", s.commandCheck)
	return cors(mux)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

type checkRequest struct {
	URL          string `json:"url"`
	ClientID     string `json:"client_id,omitempty"`
	ForceRescan  bool   `json:"force_rescan,omitempty"`
	// OpenerURL — popup-lineage context (§3.1). Empty for top-level navigations.
	OpenerURL    string `json:"opener_url,omitempty"`
	// Paranoid — Executive Mode flag passed by the extension per-request.
	// strictness.Apply uses this to elevate unknown/B/C grades to ISOLATE.
	Paranoid     bool   `json:"paranoid,omitempty"`
}

type checkResponse struct {
	Verdict         string    `json:"verdict"`
	Confidence      float64   `json:"confidence"`
	Grade           string    `json:"grade,omitempty"`
	PageClass       string    `json:"page_class,omitempty"`
	EvidenceID      string    `json:"evidence_id,omitempty"`
	Signals         []signal  `json:"signals,omitempty"`
	ReasonCodes     []string  `json:"reason_codes,omitempty"`
	LLMExplanation  string    `json:"llm_explanation,omitempty"`
	BlockReason     string    `json:"block_reason,omitempty"`
	VisualTopBrand  string    `json:"visual_top_brand,omitempty"`
	VisualTopScore  float64   `json:"visual_top_score,omitempty"`
	ScreenshotURL   string    `json:"screenshot_url,omitempty"`
	// StrictnessApplied — true when Executive Mode bumped the verdict.
	// Lets analytics separate friction from real detection.
	StrictnessApplied bool   `json:"strictness_applied,omitempty"`
	// IsChallengePage — sandbox saw a Cloudflare/Turnstile/captcha wall.
	IsChallengePage   bool   `json:"is_challenge_page,omitempty"`
	ScannedAt       time.Time `json:"scanned_at"`
}

type signal struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, "bad request: url required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	resp := s.runPipeline(ctx, req)

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	log.Info().Str("url", req.URL).Str("verdict", resp.Verdict).Msg("check")
}

func (s *Server) rescan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req checkRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.ForceRescan = true
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp := s.runPipeline(ctx, req)
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// scan — scheduler-dispatched async scan (§6 drift / TTL revalidation).
// Same payload shape as /v1/check + a tier hint. The result is persisted but
// the response is intentionally lean (the caller is the scheduler, not a
// browser).
type scanRequest struct {
	URL     string `json:"url"`
	Tier    string `json:"tier,omitempty"`    // "light" | "medium" | "deep"
	Reason  string `json:"reason,omitempty"`  // "ttl_expired" | "drift:cert,form" | "manual"
}

type scanResponse struct {
	URL        string    `json:"url"`
	Verdict    string    `json:"verdict"`
	Grade      string    `json:"grade,omitempty"`
	EvidenceID string    `json:"evidence_id,omitempty"`
	ScannedAt  time.Time `json:"scanned_at"`
}

func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	// Reuse the full pipeline. Tier-2 always runs for `deep`, never for
	// `light`. For `medium` we use the same heuristic as on-demand scans.
	cr := checkRequest{URL: req.URL, ClientID: "scheduler", ForceRescan: true}
	resp := s.runPipelineWithTier(ctx, cr, req.Tier)

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(scanResponse{
		URL:        req.URL,
		Verdict:    resp.Verdict,
		Grade:      resp.Grade,
		EvidenceID: resp.EvidenceID,
		ScannedAt:  resp.ScannedAt,
	})
	log.Info().
		Str("url", req.URL).
		Str("tier", req.Tier).
		Str("reason", req.Reason).
		Str("verdict", resp.Verdict).
		Msg("scheduler-driven scan")
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("access-control-allow-origin", "*")
		w.Header().Set("access-control-allow-methods", "GET, POST, OPTIONS")
		w.Header().Set("access-control-allow-headers", "content-type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
