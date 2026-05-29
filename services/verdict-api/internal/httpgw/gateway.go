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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/connid"
	"github.com/xgenguardian/services/verdict-api/internal/feeds"
	"github.com/xgenguardian/services/verdict-api/internal/internalauth"
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

	// SharedHTTPClient is a connection-pooled HTTP client shared across all
	// sandbox-render and visual-match calls. Initialize with NewSharedHTTPClient
	// in main.go. When nil, postJSON falls back to a per-call client (no
	// connection reuse — only acceptable in tests).
	SharedHTTPClient *http.Client

	// sandboxCoalescer dedups in-flight sandbox renders by normalized URL.
	// Lazy-initialized on first use so tests that don't render don't
	// need to instantiate. See coalesce.go.
	sandboxCoalescer     *coalescer
	sandboxCoalescerOnce sync.Once
}

// Routes returns the HTTP handler for the verdict-api HTTP gateway.
//
// Endpoint classification:
//   - /healthz             — public, no auth (operational probe)
//   - /metrics             — public, no auth (Prometheus scrape target)
//   - /v1/check            — PUBLIC (browser extension → verdict-api over internet)
//   - /v1/rescan           — PUBLIC (browser extension rescan button)
//   - /v1/command-check    — PUBLIC (content-script copy-button mediation)
//   - /v1/telemetry/override — PUBLIC, opt-in via XGG_TELEMETRY_ENABLED;
//                              extension/portal posts override + FP/FN reports
//   - /v1/scan             — INTERNAL (scheduler only); requires X-Internal-Token
//   - /v1/stream           — INTERNAL (SSE live feed); requires X-Internal-Token
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)

	// Prometheus metrics endpoint — no authentication per standard scraping
	// convention. The service binds 127.0.0.1:18080 and UFW restricts external
	// access; operators should firewall /metrics if exposing on a public IP.
	mux.Handle("/metrics", promhttp.Handler())

	// Public endpoints — called by the browser extension from the internet;
	// embedding a shared secret in extension code would be trivially extractable.
	// /v1/check and /v1/command-check have per-client-id and per-IP rate limiting
	// (Fix #13). /v1/rescan is not rate-limited (it requires a prior check result
	// to exist and is already throttled by the 90s pipeline budget).
	mux.HandleFunc("/v1/check", s.rateLimitMiddleware(s.check))
	mux.HandleFunc("/v1/rescan", s.rescan)
	mux.HandleFunc("/v1/command-check", s.rateLimitMiddleware(s.commandCheck))

	// Phase G — opt-in data-flywheel endpoint. Rate-limited like /v1/check.
	// Opt-in is enforced inside the handler (telemetryEnabled).
	mux.HandleFunc("/v1/telemetry/override", s.rateLimitMiddleware(s.telemetryOverride))

	// Internal-only endpoints — require X-Internal-Token.
	mux.Handle("/v1/scan", internalauth.Middleware(http.HandlerFunc(s.scan)))
	mux.Handle("/v1/stream", internalauth.Middleware(http.HandlerFunc(s.stream)))
	// /v1/deep-scan is bandwidth-intensive (fans out to multiple sandbox renders).
	// Requires X-Internal-Token — not exposed to the public extension API.
	mux.Handle("/v1/deep-scan", internalauth.Middleware(http.HandlerFunc(s.deepScan)))

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
	// Mode — extension's protection-mode selector (normal/safe/family/strict/
	// paranoid). Defaults to "normal" if absent. Determines which category
	// feed_entries auto-BLOCK.
	Mode         string `json:"mode,omitempty"`
	// Categories — per-category allow/block overrides keyed by category name
	// (adult, gambling, piracy, crack_keygen, malvertising, popunder).
	// Maps to feed_entries.category. true = block in this category, false =
	// allow. When not provided we use the mode's defaults.
	Categories   map[string]bool `json:"categories,omitempty"`
	// BrowserRemoteIP — IP the browser actually connected to, captured by
	// chrome.webRequest.onResponseStarted in the extension. Phase B
	// connection identity. Empty string = extension didn't capture it; the
	// connection-identity path is then absent rather than failed.
	BrowserRemoteIP string `json:"browser_remote_ip,omitempty"`
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
	// Cached — true when the response was served from the Redis verdict cache.
	// Lets the extension / block page show "Last scanned X ago" using ScannedAt.
	Cached bool `json:"cached,omitempty"`
	// DomainAgeDays — registered-age of the domain in days (from RDAP). 0
	// with DomainAgeKnown=false means we didn't look up or RDAP failed.
	// Surfaced so the block page can render the "registered N days ago" badge.
	DomainAgeDays  int  `json:"domain_age_days,omitempty"`
	DomainAgeKnown bool `json:"domain_age_known,omitempty"`
	// VendorDNSBlockedBy — names of the protective-DNS providers that
	// blocked this domain. Empty means no provider blocked. Surfaced so
	// the block page can show "Cloudflare + Quad9 both block this".
	VendorDNSBlockedBy []string `json:"vendor_dns_blocked_by,omitempty"`
	// ClearanceChecks — per-gate pass/warn/fail/unknown for the
	// transparency grid the block page renders. Always populated. In Ultra
	// mode it gates the verdict; in other modes it's informational only.
	// Keys: feed, vendor_dns, domain_age, hostname_shape, visual, identity,
	// behavior, trust.
	ClearanceChecks map[string]string `json:"clearance_checks,omitempty"`
	// ConnectionIdentity — Phase B evidence object answering "did the
	// browser actually connect to a legitimate endpoint for this domain?"
	// Absent (nil) when the extension didn't supply browser_remote_ip.
	ConnectionIdentity *connid.Identity `json:"connection_identity,omitempty"`

	// TrustScore — Phase D. Positive-evidence aggregate in [0.0, 1.0]
	// combining domain age, feed/vendor-DNS cleanliness, brand/org
	// membership, HTTPS validity. Surfaced for the evidence UI;
	// suppresses soft signals only (never hard rules).
	TrustScore float64 `json:"trust_score,omitempty"`
	// TrustContributors — labeled signals that moved the score.
	// Rendered in the evidence UI as "trust came from X, Y, Z."
	TrustContributors []trustContributor `json:"trust_contributors,omitempty"`

	// DecisionTrace — append-only log of every meaningful rule the engine
	// evaluated for this URL. Each step records the stage, the reason
	// code (if any), the outcome (fired/suppressed/pass/skip/fail), and
	// a short human detail. Surfaced so the user can see exactly how
	// we decided — the block page renders this as a transparency table
	// and the livetail tool prints it line-by-line.
	DecisionTrace []decisionStep `json:"decision_trace,omitempty"`

	// WrapperChain — when the original URL came through an email-gateway
	// wrapper (Microsoft SafeLinks, Proofpoint URL Defense, Mimecast,
	// Cisco Secure Email, Barracuda, Symantec, Gmail), each hop the
	// pipeline unwrapped is listed here in order. The engine analyzes
	// the FINAL unwrapped target (not the wrapper), but the chain is
	// surfaced so the warn/block page can show "this came in via
	// SafeLinks; the real destination is <target>." Empty for ordinary
	// URLs that didn't need unwrapping.
	WrapperChain []wrapperHop `json:"wrapper_chain,omitempty"`
}

// wrapperHop describes one URL-wrapper hop the unwrapper resolved.
// Stable on the wire so downstream UIs and the livetail tool can
// render it without versioned conditionals.
type wrapperHop struct {
	Wrapper string `json:"wrapper"` // "safelinks" | "proofpoint" | "mimecast" | ...
	URL     string `json:"url"`     // the wrapper URL we observed
}

// decisionStep is the wire-format mirror of policy.DecisionStep.
type decisionStep struct {
	Stage   string  `json:"stage"`
	Code    string  `json:"code,omitempty"`
	Outcome string  `json:"outcome"`
	Detail  string  `json:"detail,omitempty"`
	Weight  float64 `json:"weight,omitempty"`
}

// trustContributor is the wire-format mirror of policy.TrustContributor.
// Kept here so the public JSON contract is owned by the gateway package
// rather than leaking internal/policy types.
type trustContributor struct {
	Label  string  `json:"label"`
	Weight float64 `json:"weight"`
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

	// 90s deadline. Reasoning: Tier-2 sandbox-render has a real-world p95 of
	// 15-20s and ours uses 45s timeout + 30s retry. The previous 8s parent
	// deadline silently aborted every Tier-2 invocation, disabling visual-
	// match / YARA / sink / behavior detection on the on-demand check path.
	// Extension-side timeout is 25s (holding.html) so the engine still has
	// budget to coalesce a slow scan while the user sees the manual-isolate
	// escape on the holding page. The extra time allows the sandbox-render
	// to actually complete and the policy engine to act on its evidence.
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	t0 := time.Now()
	resp := s.runPipeline(ctx, req)
	latencyMs := time.Since(t0).Milliseconds()

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	// Rich per-check log line — consumed by tools/livetail/livetail.sh for
	// human-readable streaming. Every field below is safe to publish: URL
	// is sanitized (query stripped), and no client_id / IP is included.
	log.Info().
		Str("url", sanitizeURLForLog(req.URL)).
		Str("verdict", resp.Verdict).
		Float64("confidence", resp.Confidence).
		Str("grade", resp.Grade).
		Str("page_class", resp.PageClass).
		Strs("reason_codes", resp.ReasonCodes).
		Float64("trust_score", resp.TrustScore).
		Int("domain_age_days", resp.DomainAgeDays).
		Bool("cached", resp.Cached).
		Bool("is_challenge_page", resp.IsChallengePage).
		Bool("strictness_applied", resp.StrictnessApplied).
		Str("visual_top_brand", resp.VisualTopBrand).
		Float64("visual_top_score", resp.VisualTopScore).
		Strs("vendor_dns_blocked_by", resp.VendorDNSBlockedBy).
		Interface("clearance", resp.ClearanceChecks).
		Interface("decision_trace", resp.DecisionTrace).
		Str("block_reason", resp.BlockReason).
		Int64("latency_ms", latencyMs).
		Msg("check")
}

func (s *Server) rescan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, "bad request: url required", http.StatusBadRequest)
		return
	}
	req.ForceRescan = true
	// Same 90s budget — rescan is on-demand and benefits from a full Tier-2.
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
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
