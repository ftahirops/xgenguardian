// pipeline.go — Tier-1 + Tier-2 orchestration wired into the HTTP gateway.
//
// Phase-1 behavior:
//   1. Resolve URL → domain.
//   2. Run Tier-1 in parallel via internal/tier1 (≤250ms budget).
//   3. If Tier-1 is decisive (score ≥0.85 or ≤0.05) → short-circuit.
//   4. Else dispatch sandbox-render + visual-match (≤6s).
//   5. Fuse all signals via internal/fusion → return verdict.
package httpgw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/oauthreg"
	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
	"github.com/xgenguardian/services/verdict-api/internal/policy"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
	"github.com/xgenguardian/services/verdict-api/internal/tier1"
)

// yaraWeight converts a YARA rule's declared severity into a fusion weight.
// "critical" + "high" → strong contributions; "medium"/"low" → corroborators.
func yaraWeight(sev string) float64 {
	switch strings.ToLower(sev) {
	case "critical":
		return 0.7
	case "high":
		return 0.5
	case "medium":
		return 0.3
	case "low":
		return 0.15
	}
	return 0.25
}

// newEvidenceID returns a v4-shaped uuid string. We don't need a uuid lib —
// 16 random bytes formatted as 8-4-4-4-12 hex satisfies the evidence_id
// UUID column and matches what sandbox-render generates.
func newEvidenceID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// fallbackKeywords — baseline coverage for popular brands the operator may
// not have seeded into the visual registry yet. Always merged with whatever
// the brand cache returns; brand-cache keywords ADD to this set, they don't
// replace it.
var fallbackKeywords = []string{
	"paypal", "google", "microsoft", "apple", "amazon", "github", "facebook",
	"instagram", "linkedin", "chase", "wellsfargo", "bofa", "bankofamerica",
	"hsbc", "amex", "americanexpress", "citi", "citibank",
	"coinbase", "binance", "kraken", "metamask",
	"netflix", "spotify", "dropbox", "box", "slack", "zoom", "discord",
	"adobe", "atlassian", "jira", "confluence", "bitbucket",
	"twitter", "tiktok", "snapchat", "reddit", "pinterest",
	"ebay", "shopify", "walmart", "alibaba", "aliexpress",
	"dhl", "fedex", "ups", "usps",
	"salesforce", "okta", "zoho", "docusign", "hubspot", "servicenow",
	"icloud", "outlook", "office365", "gmail",
}

func (s *Server) keywords() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 64)
	for _, k := range fallbackKeywords {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	if s.Brands != nil {
		for _, k := range s.Brands.AllKeywords() {
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}

func (s *Server) runPipeline(ctx context.Context, req checkRequest) checkResponse {
	return s.runPipelineWithTier(ctx, req, "")
}

// runPipelineWithTier is the real worker. `tierHint` is one of
// "" (auto, the default for /v1/check), "light", "medium", "deep". The
// scheduler passes "light"/"medium"/"deep" via /v1/scan.
func (s *Server) runPipelineWithTier(ctx context.Context, req checkRequest, tierHint string) checkResponse {
	domain := domainFromURL(req.URL)
	if domain == "" {
		return checkResponse{
			Verdict: "CLEAN", Confidence: 0,
			Signals:   []signal{{Name: "parse_error", Detail: "unparseable URL"}},
			ScannedAt: time.Now().UTC(),
		}
	}

	in := fusion.Inputs{Domain: domain, URL: req.URL}

	// --- Tier 1 (synchronous, ≤250ms) ---
	t1ctx, cancel := context.WithTimeout(ctx, s.Tier1Budget)
	t1 := tier1.Run(t1ctx, domain, s.keywords())
	cancel()

	for _, sig := range t1.Signals {
		in.Tier1Signals = append(in.Tier1Signals, fusion.Signal{
			Name: sig.Name, Weight: sig.Weight, Detail: sig.Detail,
		})
	}

	// --- Async corroborators (run in parallel with Tier-2) ---
	// RDAP populates DomainAge for the universal phishing rule's third clause.
	// Web Risk + feed_entries populate fusion.Inputs.GSBClean / BlocklistHit.
	//
	// feedHit holds the tiered result. Mutated by exactly one goroutine
	// (the feed-lookup one); the WaitGroup join below provides the
	// happens-before for subsequent reads.
	var (
		corroboratorsWG sync.WaitGroup
		feedSources     []string
		feedHit         FeedHit
	)
	corroboratorsWG.Add(3)
	go func() {
		defer corroboratorsWG.Done()
		if s.RDAP == nil {
			return
		}
		rdctx, c := context.WithTimeout(ctx, 4*time.Second)
		defer c()
		info, err := s.RDAP.Lookup(rdctx, domain)
		if err == nil {
			in.DomainAge = info.Age()
		}
	}()
	go func() {
		defer corroboratorsWG.Done()
		if s.WebRisk == nil {
			return
		}
		wrctx, c := context.WithTimeout(ctx, 3*time.Second)
		defer c()
		cleanPtr, _, err := s.WebRisk.Lookup(wrctx, req.URL)
		if err == nil {
			in.GSBClean = cleanPtr
		}
	}()
	go func() {
		defer corroboratorsWG.Done()
		fctx, c := context.WithTimeout(ctx, 2*time.Second)
		defer c()
		hit, _ := queryFeedHit(fctx, s.Pg, req.URL, domain)
		feedHit = hit
		// BlocklistHit on Inputs stays as a "any hit" flag for the legacy
		// fusion path. The new staged-policy decision below consults
		// feedHit's tier breakdown directly.
		if hit.Hit() {
			in.BlocklistHit = true
			feedSources = hit.Sources
		}
	}()

	// --- Tier 2 (dispatch sandbox + visual-match) ---
	// Skipped entirely for `light`; forced for `deep`; auto for `""` and `medium`.
	runTier2 := tierHint != "light" && (tierHint == "deep" || tierHint == "medium" || shouldRunTier2(t1.Score, req.URL))

	var render *renderResponse
	// Direct-download fallback: when the URL points at a binary that
	// Chromium can't render (e.g. raw .exe/.jar/.sh links), sandbox-render
	// will 502. We still want to BLOCK these. Surface the extension as a
	// signal before sandbox runs so the verdict has something to attach to.
	if isDL, ext := looksLikeDirectDownload(req.URL); isDL {
		in.RiskyDownloads = 1
		in.RiskyDownloadHint = req.URL
		in.Tier1Signals = append(in.Tier1Signals, fusion.Signal{
			Name:   "direct_download_url",
			Weight: 0.45,
			Detail: "URL is a direct " + ext + " download — Chromium can't render it as a page",
		})
	}
	// Raw-IP host: by itself a strong "this is not a normal website" signal;
	// combined with a binary path it's a near-certain malware drop. Fires
	// independent of any feed match so we catch Mirai-style botnet URLs the
	// feeds haven't ingested yet.
	if isRawIPHost(req.URL) {
		in.Tier1Signals = append(in.Tier1Signals, fusion.Signal{
			Name:   "raw_ip_host",
			Weight: 0.40,
			Detail: "URL points at a raw IP address rather than a domain",
		})
		if isDL, _ := looksLikeDirectDownload(req.URL); isDL {
			in.Tier1Signals = append(in.Tier1Signals, fusion.Signal{
				Name:   "raw_ip_binary_drop",
				Weight: 0.50,
				Detail: "Raw IP + direct-binary path — commodity malware drop pattern",
			})
		}
	}
	if runTier2 {
		// Sandbox-render does full networkidle wait + screenshot + MinIO
		// upload + YARA scan. Real-world p95 is 15-20s. The previous 6s
		// budget was silently timing out every Tier-2 call, leaving render=nil
		// and disabling the entire visual-match / forms / YARA / behavior
		// signal stack. fp-bench surfaced this as TP plateauing on phishing.
		//
		// Retry once on failure: short-lived phishing infra is flaky, the
		// first request often hits a TLS handshake quirk or slow DNS that
		// the second request clears. One retry doubles render success on
		// flaky URLs without doubling load on healthy ones. fp-bench TP
		// jumps ~10 pp absolute with this in place.
		r, err := s.callSandboxWithRetry(ctx, req.URL)
		if err != nil {
			log.Warn().Err(err).Str("url", req.URL).Msg("sandbox call failed (after retry)")
		}
		if err == nil && r != nil {
			render = r
			in.HasPasswordForm = anyPasswordForm(r.Forms)
			in.CrossOriginPost, in.CrossOriginTarget = anyCrossOrigin(r.Forms)
			in.RiskyDownloads, in.RiskyDownloadHint = riskyDownloads(r.Downloads)
			// YARA matches → fusion signals. Weight scales with severity.
			// We piggy-back on Tier1Signals (the field is just "extra signals
			// fusion sums into the score"); name prefix `yara_` lets codes.go
			// map every match to the canonical YARA_SIGNATURE_MATCH unless
			// the rule itself declared a stronger reason_code.
			for _, m := range r.YaraMatches {
				in.Tier1Signals = append(in.Tier1Signals, fusion.Signal{
					Name:   "yara_" + m.Rule,
					Weight: yaraWeight(m.Severity),
					Detail: m.Description,
				})
			}
			// Behavioural-abuse signals: popup storms, alert loops, fullscreen
			// traps, clipboard hijack, auto-downloads (UNIFIED-PLAN.md §5.2).
			behaviorSigs, _ := behaviorSignals(r.Behavior)
			in.Tier1Signals = append(in.Tier1Signals, behaviorSigs...)
			if r.ScreenshotURL != "" && !r.IsChallengePage {
				// CLIP inference on CPU + image fetch from MinIO can run 2-8s
				// per page. Old 3s timeout was below the p50 latency and was
				// silently dropping every visual signal. 15s comfortably
				// covers p99 even under load.
				vctx, cancelV := context.WithTimeout(ctx, 15*time.Second)
				match, vErr := s.callVisualMatch(vctx, r.ScreenshotURL)
				cancelV()
				if vErr != nil {
					log.Warn().Err(vErr).Str("url", req.URL).Msg("visual-match call failed")
				}
				if vErr == nil && match != nil && len(match.Top) > 0 {
					in.VisualTopBrand = match.Top[0].BrandName
					in.VisualTopScore = match.Top[0].Score
					if s.Brands != nil {
						if b := s.Brands.Lookup(in.VisualTopBrand); b != nil {
							in.BrandCanonicalDomains = b.CanonicalDomains
							in.BrandLegitimateASNs = b.LegitimateASNs
							in.BrandLegitimateIssuers = b.LegitimateIssuers
						}
					}
				}
				// pHash near-duplicate match: deterministic visual-similarity
				// path that fires when the rendered page is pixel-near-identical
				// to a seeded brand screenshot. Distance <= 8 (of 64 bits) is
				// "near-certain visual replica" — promote VisualTopBrand if
				// CLIP didn't already settle on the same brand, and bump the
				// score so the policy treats it as a confident replica claim.
				if match != nil && match.PHashMatch != nil && match.PHashMatch.Distance <= 8 {
					in.PHashMatchBrand = match.PHashMatch.MatchedBrand
					in.PHashMatchDistance = match.PHashMatch.Distance
					// If CLIP returned a different/weaker top brand, prefer pHash.
					if in.VisualTopBrand == "" || in.VisualTopBrand != match.PHashMatch.MatchedBrand {
						in.VisualTopBrand = match.PHashMatch.MatchedBrand
						// pHash distance to "score" mapping: 0 = 1.0, 8 = 0.85.
						// Maps near-duplicates above the high-match threshold.
						in.VisualTopScore = 1.0 - (float64(match.PHashMatch.Distance) * 0.019)
						if s.Brands != nil {
							if b := s.Brands.Lookup(in.VisualTopBrand); b != nil {
								in.BrandCanonicalDomains = b.CanonicalDomains
								in.BrandLegitimateASNs = b.LegitimateASNs
								in.BrandLegitimateIssuers = b.LegitimateIssuers
							}
						}
					}
				}
				if match != nil && match.FaviconMatch != nil {
					in.FaviconMatchBrand = match.FaviconMatch.MatchedBrand
				}
			}
		}
	}

	// Wait for the async corroborators before fusion so their signals land.
	corroboratorsWG.Wait()

	// fusion.Score still produces useful intermediates the policy engine
	// consumes — VisualTopBrand, VisualTopScore, raw signals (which we
	// surface to analysts in the response). The DECISION moves to
	// policy.Apply (dev spec §13 staged-policy engine).
	out := fusion.Score(in)

	// isChallenge is consumed by the response struct further down.
	isChallenge := render != nil && render.IsChallengePage

	// OAuth lookup (input to policy.ContextOutput).
	var oauthDec *oauthreg.Decision
	if s.OAuthReg != nil {
		oauthDec = s.OAuthReg.Inspect(req.URL)
	}

	// --- Decision: staged policy (new) or legacy fusion (env-flagged fallback) ---
	var (
		finalVerdict      string
		codes             []string
		blockReason       string
		strictnessApplied bool
		confidence        float64
		pageClass         string
		grade             string
	)
	if useLegacyPolicy() {
		finalVerdict, codes, blockReason, strictnessApplied, confidence, pageClass, grade =
			legacyDecision(req, in, out, render, feedSources, oauthDec)
	} else {
		policyIn := buildPolicyInputs(req, in, out, render, feedSources, feedHit, oauthDec)
		policyOut := policy.Apply(policyIn)
		finalVerdict = string(policyOut.Verdict)
		codes = policyOut.ReasonCodes
		blockReason = policyOut.BlockReason
		strictnessApplied = containsCode(codes, reasons.BlockedByStrictnessPolicy)
		confidence = policyOut.Confidence
		pageClass = string(policyIn.PageClass)
		grade = chooseGrade(finalVerdict, confidence)
	}

	// Translate fusion signals to HTTP-API signals (raw for analysts).
	sigs := make([]signal, 0, len(out.Signals))
	for _, sg := range out.Signals {
		sigs = append(sigs, signal{Name: sg.Name, Weight: sg.Weight, Detail: sg.Detail})
	}

	// --- Persist evidence + url + scan_history ---
	evidenceID := ""
	if render != nil {
		evidenceID = render.EvidenceID
	}
	if evidenceID == "" {
		evidenceID = newEvidenceID()
	}
	if err := persistScan(ctx, s.Pg, in, out, render, codes, evidenceID, finalVerdict, pageClass, grade, t1.Score); err != nil {
		log.Warn().Err(err).Str("url", req.URL).Msg("persist failed")
		// Don't surface to the caller — verdict still returns; analytics will catch.
	}

	resp := checkResponse{
		Verdict:           finalVerdict,
		Confidence:        confidence,
		Grade:             grade,
		PageClass:         pageClass,
		EvidenceID:        evidenceID,
		Signals:           sigs,
		ReasonCodes:       codes,
		BlockReason:       blockReason,
		VisualTopBrand:    out.TopBrand,
		VisualTopScore:    out.TopScore,
		StrictnessApplied: strictnessApplied,
		IsChallengePage:   isChallenge,
		ScannedAt:         time.Now().UTC(),
	}
	if render != nil {
		resp.ScreenshotURL = render.ScreenshotURL
	}

	event := map[string]any{
		"ts":               resp.ScannedAt,
		"url":              req.URL,
		"domain":           domain,
		"verdict":          resp.Verdict,
		"confidence":       resp.Confidence,
		"visual_top_brand": resp.VisualTopBrand,
		"visual_top_score": resp.VisualTopScore,
		"signals":          resp.Signals,
		"client_id":        req.ClientID,
		"evidence_id":      resp.EvidenceID,
	}

	// Publish to the live activity feed (best-effort; SSE subscribers consume).
	if s.Rdb != nil {
		PublishVerdict(ctx, s.Rdb, event)
	}

	// Append to the on-disk session log if SESSION_LOG_DIR is set.
	writeSessionLog(event)

	return resp
}

// --- Tier-2 helpers ---

type renderResponse struct {
	EvidenceID       string            `json:"evidence_id"`
	ScreenshotURL    string            `json:"screenshot_url"`
	DOMURL           string            `json:"dom_url"`
	HARURL           string            `json:"har_url"`
	Forms            []formExtract     `json:"forms"`
	FinalURL         string            `json:"final_url"`
	Title            string            `json:"title"`
	Downloads        []downloadFinding `json:"downloads"`
	IsChallengePage  bool              `json:"is_challenge_page"`
	ChallengeKind    string            `json:"challenge_kind"`
	YaraMatches      []yaraMatch       `json:"yara_matches"`
	YaraMs           int               `json:"yara_ms"`
	Behavior         map[string]int    `json:"behavior"`
	PostMessageCount int               `json:"post_message_count"`
	// Sink — runtime credential-sink data (Package 4 / dev spec §3).
	// Mirrors the JS-side window.__xgg_sink shape.
	Sink             sinkObservation   `json:"sink"`
	// ShellCmd — IOCs extracted from <pre>/<code> blocks on docs-style
	// pages. Used to catch the Straiker-class "docs page IS the weapon"
	// attack where the malicious payload is just text in the page.
	ShellCmd         shellCmdObservation `json:"shellcmd"`
}

// shellCmdObservation — mirrors sandbox-render's shellcmd dict.
type shellCmdObservation struct {
	ReasonCodes      []string             `json:"reason_codes"`
	HasHardFail      bool                 `json:"has_hard_fail"`
	SoftSignalCount  int                  `json:"soft_signal_count"`
	// CommandsSeen — every <pre>/<code> block where any shellcmd pattern
	// fired. Each entry has the block ID and the (truncated) raw text.
	// installreg.MatchCommand consumes Text to award OfficialMatch when
	// a canonical vendor install template is recognized.
	CommandsSeen     []shellCmdCommand    `json:"commands_seen"`
}

type shellCmdCommand struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// sinkObservation — runtime data from the page-injected sink instrumentation.
// Populated when sandbox-render successfully reads window.__xgg_sink.
type sinkObservation struct {
	Destinations             []sinkDest     `json:"destinations"`
	CrossOrigin              bool           `json:"cross_origin"`
	PreSubmitCapture         bool           `json:"pre_submit_capture"`
	MultiDestination         bool           `json:"multi_destination"`
	HiddenMirror             bool           `json:"hidden_mirror"`
	InvisibleCredentialField bool           `json:"invisible_credential_field"`
	PointerEventsTrick       bool           `json:"pointer_events_trick"`
	CaptureModes             map[string]int `json:"capture_modes"`
	SensitiveListeners       int            `json:"sensitive_listeners"`
	MutationReplacedInput    int            `json:"mutation_replaced_input"`
}

type sinkDest struct {
	Origin string `json:"origin"`
	Method string `json:"method"`
	Mode   string `json:"mode"`  // "fetch" | "xhr" | "beacon" | "websocket"
	Cross  bool   `json:"cross"`
}

type yaraMatch struct {
	Rule        string   `json:"rule"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`     // low | medium | high | critical
	ReasonCode  string   `json:"reason_code"`  // canonical reasons.Code; falls back to YARA_SIGNATURE_MATCH
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

type downloadFinding struct {
	URL         string `json:"url"`
	Extension   string `json:"extension"`
	ContentType string `json:"content_type"`
	SizeHint    int64  `json:"size_hint"`
	SHA256      string `json:"sha256"`
	Risky       bool   `json:"risky"`
}

type formExtract struct {
	Action         string `json:"action"`
	ActionOrigin   string `json:"action_origin"`
	HasPassword    bool   `json:"has_password"`
	HasEmail       bool   `json:"has_email"`
	IsCrossOrigin  bool   `json:"is_cross_origin"`
}

// callSandboxWithRetry calls callSandbox up to twice. Most sandbox failures
// on real phishing infra are transient: TLS handshake aborts, slow DNS via
// DoH, MinIO upload races. A single retry recovers most of them without
// hammering healthy sites.
//
// Coalescing: concurrent callers for the same normalized URL share a single
// underlying sandbox call. This prevents N simultaneous renders of the
// same URL under fp-bench / extension burst load. See coalesce.go.
func (s *Server) callSandboxWithRetry(ctx context.Context, target string) (*renderResponse, error) {
	s.sandboxCoalescerOnce.Do(func() {
		s.sandboxCoalescer = newCoalescer()
	})
	key := normalizeURLForCoalesce(target)
	return s.sandboxCoalescer.do(ctx, key, func() (*renderResponse, error) {
		return s.callSandboxWithRetryUncoalesced(ctx, target)
	})
}

// callSandboxWithRetryUncoalesced — the actual retry logic, separated so
// the coalescer can wrap it. Callers should use callSandboxWithRetry.
func (s *Server) callSandboxWithRetryUncoalesced(ctx context.Context, target string) (*renderResponse, error) {
	t2ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	r, err := s.callSandbox(t2ctx, target)
	cancel()
	if err == nil && r != nil && r.ScreenshotURL != "" {
		return r, nil
	}
	if ctx.Err() != nil {
		return r, err
	}
	t2ctx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	r2, err2 := s.callSandbox(t2ctx2, target)
	cancel2()
	if err2 == nil && r2 != nil && r2.ScreenshotURL != "" {
		return r2, nil
	}
	if r != nil {
		return r, err
	}
	return r2, err2
}

func (s *Server) callSandbox(ctx context.Context, target string) (*renderResponse, error) {
	body, _ := json.Marshal(map[string]any{"url": target})
	// Inner HTTP timeout aligned with the outer ctx budget (45s). Was 6s,
	// which clamped every sandbox call below the actual p50.
	r, err := postJSON(ctx, sandboxRenderURL()+"/render", body, 45*time.Second)
	if err != nil {
		return nil, err
	}
	var rr renderResponse
	if err := json.Unmarshal(r, &rr); err != nil {
		return nil, err
	}
	return &rr, nil
}

type matchResponse struct {
	Top []struct {
		BrandName string  `json:"brand_name"`
		PageLabel string  `json:"page_label"`
		Score     float64 `json:"score"`
	} `json:"top"`
	FaviconMatch *struct {
		MatchedBrand string `json:"matched_brand"`
	} `json:"favicon_match"`
	// PHashMatch — pHash nearest-neighbor result from visual-match. Cheaper
	// and more deterministic than CLIP: Hamming distance <= 8 (of 64 bits)
	// is "near-duplicate page". Catches replicas where CLIP's score
	// hovers below threshold but the rendered page IS visually identical.
	PHashMatch *struct {
		MatchedBrand   string `json:"matched_brand"`
		PageLabel      string `json:"page_label"`
		Distance       int    `json:"distance"`
		PHashDistance  int    `json:"phash_distance"`
		DHashDistance  int    `json:"dhash_distance"`
	} `json:"phash_match"`
}

func (s *Server) callVisualMatch(ctx context.Context, screenshotURL string) (*matchResponse, error) {
	body, _ := json.Marshal(map[string]any{"image_url": screenshotURL})
	// Inner HTTP timeout matches the outer ctx budget. Was 3s, raised to 15s
	// after fp-bench surfaced silent timeouts on CPU-CLIP inference.
	r, err := postJSON(ctx, visualMatchURL()+"/match", body, 15*time.Second)
	if err != nil {
		return nil, err
	}
	var mr matchResponse
	if err := json.Unmarshal(r, &mr); err != nil {
		return nil, err
	}
	return &mr, nil
}

func postJSON(ctx context.Context, url string, body []byte, timeout time.Duration) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	req.Header.Set("content-type", "application/json")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, errors.New(resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// --- pure helpers ---

func domainFromURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	return strings.TrimSuffix(h, ".")
}

func shouldRunTier2(t1Score float64, raw string) bool {
	if t1Score >= 0.2 {
		return true
	}
	// Raw-IP hosts are never legitimate for normal browsing — every reachable
	// content site uses a domain. Direct IP hits are commodity malware drops,
	// Mirai-style botnet binaries, or attacker-controlled C2. Always Tier-2.
	if isRawIPHost(raw) {
		return true
	}
	// Developer-tool install lures: URL looks like /docs or /install for
	// Claude / OpenAI / JetBrains / Cursor / Cline / etc. The page itself
	// is the weapon (shell command for copy-paste) so we MUST render +
	// shellcmd-scan before letting it through. Catches the Straiker class.
	if pageclass.LooksLikeDevToolInstallLure(raw) {
		return true
	}
	rl := strings.ToLower(raw)
	for _, hint := range []string{
		// Credential / sensitive page patterns.
		"login", "signin", "verify", "secure", "account", "wallet",
		// Direct-download patterns — sandbox usually can't render the
		// binary, but YARA / Content-Type / download analysis still apply.
		"download", ".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1",
		".vbs", ".jar", ".apk", ".dmg", ".iso", ".lnk",
		// Shared-hosting platforms widely abused for one-off droppers
		// and brand-impersonation clones. Tier-2 these to give visual-match
		// a chance — bare-domain feed lookup is suppressed for these.
		".vercel.app", ".netlify.app", ".pages.dev", ".workers.dev",
		".herokuapp.com", "githubusercontent.com", "cdn.discordapp.com",
		"telegra.ph", "ngrok.io", "ngrok-free.app", ".cfargotunnel.com",
		".github.io", ".gitlab.io", ".blogspot.com", ".wordpress.com",
		".webflow.io", ".lovable.app", ".square.site", ".godaddysites.com",
		".firebaseapp.com", ".web.app", ".replit.dev", ".fly.dev",
		".myshopify.com", ".wixsite.com", ".weebly.com",
		"backblazeb2.com", ".r2.dev",
	} {
		if strings.Contains(rl, hint) {
			return true
		}
	}
	// Suspicious TLDs commonly used for short-lived attack infra.
	for _, sus := range []string{
		".cam", ".boo", ".tk", ".ml", ".ga", ".cf", ".gq",
		".click", ".top", ".xyz", ".rest", ".buzz", ".loan", ".work",
	} {
		if strings.HasSuffix(strings.SplitN(rl, "/", 4)[2], sus) {
			return true
		}
	}
	return false
}

// looksLikeDirectDownload returns true when the URL path ends in (or contains)
// a known-risky executable / archive extension. Used as a fallback signal
// when sandbox-render can't render the URL (because it's a direct binary).
func looksLikeDirectDownload(raw string) (bool, string) {
	rl := strings.ToLower(raw)
	for _, ext := range []string{
		".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
		".jar", ".apk", ".dmg", ".iso", ".img", ".lnk",
		".7z", ".rar", ".zip", ".tar.gz", ".gz",
		".hta", ".chm", ".jnlp", ".doc", ".docm", ".xls", ".xlsm",
		".ppt", ".pptm", ".pdf",
		// IoT-malware shell variants from URLhaus.
		".sh", ".elf", ".mips", ".arm", ".mpsl", ".x86", ".powerpc",
	} {
		if strings.HasSuffix(rl, ext) || strings.Contains(rl, ext+"?") {
			return true, ext
		}
	}
	// Mirai/Gafgyt-style botnet drops use bare architecture names as the last
	// path segment with no extension (e.g. http://1.2.3.4/x86, /arm5, /mips,
	// /sh4). These show up daily in URLhaus and were previously missed
	// because the leading dot wasn't there. Match only when path-suffix is
	// the architecture name as a complete segment.
	if arch, ok := pathSuffixMatchesArch(rl); ok {
		return true, arch
	}
	return false, ""
}

// isRawIPHost — true when the URL host is a literal IPv4 or IPv6 address.
// Legitimate browser destinations always use a domain; raw IP hosts are
// commodity malware drops, C2 beacons, or attacker-controlled servers.
func isRawIPHost(raw string) bool {
	// Lightweight host extractor: strip scheme, take up to first '/' or '?',
	// then optionally strip trailing :port.
	s := raw
	if i := strings.Index(s, "://"); i > 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i > 0 {
		s = s[:i]
	}
	// IPv6 is wrapped in []
	if strings.HasPrefix(s, "[") && strings.Contains(s, "]") {
		s = s[1:strings.Index(s, "]")]
		return net.ParseIP(s) != nil
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		s = s[:i]
	}
	return net.ParseIP(s) != nil
}

// pathSuffixMatchesArch — true when the last path segment matches a known
// CPU-architecture token used by IoT-malware binary drops.
func pathSuffixMatchesArch(rl string) (string, bool) {
	// Trim query / fragment.
	if i := strings.IndexAny(rl, "?#"); i > 0 {
		rl = rl[:i]
	}
	idx := strings.LastIndex(rl, "/")
	if idx < 0 || idx == len(rl)-1 {
		return "", false
	}
	seg := rl[idx+1:]
	for _, arch := range []string{
		"x86", "x86_64", "x86-64", "amd64",
		"arm", "arm5", "arm6", "arm7", "aarch64",
		"mips", "mipsel", "mpsl",
		"sh4", "m68k", "powerpc", "ppc", "spc", "sparc",
		"i486", "i586", "i686", "i", "i6", "i7",
	} {
		if seg == arch {
			return arch, true
		}
	}
	return "", false
}

func anyPasswordForm(fs []formExtract) bool {
	for _, f := range fs {
		if f.HasPassword {
			return true
		}
	}
	return false
}

func riskyDownloads(ds []downloadFinding) (int, string) {
	n := 0
	hint := ""
	for _, d := range ds {
		if d.Risky {
			n++
			if hint == "" {
				hint = d.URL
			}
		}
	}
	return n, hint
}

func anyCrossOrigin(fs []formExtract) (bool, string) {
	for _, f := range fs {
		if f.HasPassword && f.IsCrossOrigin {
			return true, f.Action
		}
	}
	return false, ""
}

func sandboxRenderURL() string {
	if v := osGetenv("SANDBOX_RENDER_URL"); v != "" {
		return v
	}
	return "http://localhost:8002"
}

func visualMatchURL() string {
	if v := osGetenv("VISUAL_MATCH_URL"); v != "" {
		return v
	}
	return "http://localhost:8003"
}

// osGetenv is a tiny indirection so we don't pull "os" into this file's
// import list when the test build re-stubs it.
func osGetenv(k string) string {
	return goGetenv(k)
}
