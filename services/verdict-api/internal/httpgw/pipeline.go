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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/brandgraph"
	"github.com/xgenguardian/services/verdict-api/internal/connid"
	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/iledger"
	"github.com/xgenguardian/services/verdict-api/internal/internalauth"
	"github.com/xgenguardian/services/verdict-api/internal/metrics"
	"github.com/xgenguardian/services/verdict-api/internal/oauthreg"
	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
	"github.com/xgenguardian/services/verdict-api/internal/policy"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
	"github.com/xgenguardian/services/verdict-api/internal/tier1"
	"github.com/xgenguardian/services/verdict-api/internal/vendordns"
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
	pipelineStart := time.Now()

	domain := domainFromURL(req.URL)
	if domain == "" {
		return checkResponse{
			Verdict: "CLEAN", Confidence: 0,
			Signals:   []signal{{Name: "parse_error", Detail: "unparseable URL"}},
			ScannedAt: time.Now().UTC(),
		}
	}

	// --- Verdict cache (Cache 1): check before running any pipeline logic ---
	// ForceRescan and paranoid mode always bypass the cache.
	if !req.ForceRescan {
		if cached := getVerdictCache(ctx, s.Rdb, req.URL, req.Paranoid, req.Mode); cached != nil {
			metrics.VerdictCacheTotal.WithLabelValues("hit").Inc()
			metrics.VerdictLatency.WithLabelValues("cached").Observe(time.Since(pipelineStart).Seconds())
			mode := req.Mode
			if mode == "" {
				mode = "normal"
			}
			metrics.VerdictTotal.WithLabelValues(cached.Verdict, mode).Inc()
			return *cached
		}
	}
	metrics.VerdictCacheTotal.WithLabelValues("miss").Inc()

	in := fusion.Inputs{Domain: domain, URL: req.URL}

	// --- Tier 1 (synchronous, ≤250ms) ---
	t1ctx, cancel := context.WithTimeout(ctx, s.Tier1Budget)
	t1 := tier1.Run(t1ctx, domain, s.keywords())
	cancel()
	metrics.Tier1Score.Observe(t1.Score)

	for _, sig := range t1.Signals {
		in.Tier1Signals = append(in.Tier1Signals, fusion.Signal{
			Name: sig.Name, Weight: sig.Weight, Detail: sig.Detail,
		})
	}

	// --- Async corroborators (run in parallel with Tier-2) ---
	// RDAP populates DomainAge for the universal phishing rule's third clause.
	// Web Risk + feed_entries populate fusion.Inputs.GSBClean / BlocklistHit.
	//
	// Each goroutine writes ONLY to its own local variable, never to `in`
	// directly. A single serial merge block after corroboratorsWG.Wait()
	// copies all locals into `in`. This eliminates the data race between
	// corroborator goroutines and the Tier-2 block that also mutates `in`
	// while the corroborators are running.
	var (
		corroboratorsWG sync.WaitGroup
		feedSources     []string
		feedHit         FeedHit
		vendorDNS       vendordns.ConsensusResult
		// per-goroutine locals — written only by their respective goroutine
		rdapAge      time.Duration
		webRiskClean *bool
	)
	corroboratorsWG.Add(4)
	go func() {
		defer corroboratorsWG.Done()
		if s.RDAP == nil {
			return
		}
		rdctx, c := context.WithTimeout(ctx, 4*time.Second)
		defer c()
		info, err := s.RDAP.Lookup(rdctx, domain)
		if err == nil {
			rdapAge = info.Age() // local; merged into in.DomainAge after Wait
		}
	}()
	go func() {
		defer corroboratorsWG.Done()
		// Multi-vendor DNS consensus. Cached in Redis with 1h TTL — DNS
		// blocklists change relatively slowly so we don't need to re-query
		// 8 providers on every request to the same domain.
		vt0 := time.Now()
		vendorDNS = queryVendorDNSCached(ctx, s.Rdb, domain)
		metrics.VendorDNSLatency.Observe(time.Since(vt0).Seconds())
		if vendorDNS.Hit() {
			metrics.VendorDNSBlockTotal.WithLabelValues(fmt.Sprintf("%d", len(vendorDNS.BlockedBy))).Inc()
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
			webRiskClean = cleanPtr // local; merged into in.GSBClean after Wait
		}
	}()
	go func() {
		defer corroboratorsWG.Done()
		fctx, c := context.WithTimeout(ctx, 2*time.Second)
		defer c()
		feedHit, _ = queryFeedHit(fctx, s.Pg, req.URL, domain)
		// feedHit is read only after Wait(); feedSources likewise.
	}()

	// --- Tier 2 (dispatch sandbox + visual-match) ---
	// Skipped entirely for `light`; forced for `deep`; auto for `""` and `medium`.
	// Opener-driven escalation: when the navigation was opened FROM a known
	// URL shortener (bit.ly etc.), the user clicked through an obfuscated
	// link — we don't know what the original sharer intended. Force Tier-2
	// on the landing page even when Tier-1 says fine, so we get the full
	// visual + behavior signal stack. Shorteners themselves don't get
	// suspicious-redirect-flagged because the redirect IS the service.
	openerIsShortener := false
	if req.OpenerURL != "" {
		if h := domainFromURL(req.OpenerURL); h != "" && isURLShortener(h) {
			openerIsShortener = true
		}
	}

	// SHORTCUT 1 — the URL itself is a known URL shortener landing page
	// (bit.ly home, t.co home). These don't get Tier-2 forced even when
	// shouldRunTier2 says yes; the user will navigate AWAY in a moment
	// (that's the whole point of a shortener) and the destination URL
	// will go through the full pipeline. Spending 20s rendering bit.ly's
	// home page just stalls the user.
	//
	// SHORTCUT 2 — the URL is on the trusted-identity registry AND no
	// strong tier-1 signal fired. Trusted brands (signal.org, github.com,
	// google.com) routinely have install-page-looking paths that force
	// Tier-2 under shouldRunTier2's install-lure check. We don't need to
	// re-render every signal.org/download visit — trustreg already
	// vetted the host.
	isShortenerLanding := isURLShortener(domain)
	isTrustedHost := brandgraph.IsAnyTrust(domain)

	forceTier2 := tierHint == "deep" || tierHint == "medium"
	autoTier2 := shouldRunTier2(t1.Score, req.URL) || openerIsShortener
	runTier2 := tierHint != "light" && (forceTier2 || (autoTier2 && !isShortenerLanding && !(isTrustedHost && t1.Score < 0.4)))


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

		// --- Render cache (Cache 2): check before calling sandbox ---
		//
		// ForceRescan + Paranoid both bypass the verdict cache; the render
		// cache must follow the same rule. Otherwise a "force rescan" on a
		// URL whose render was cached 3 hours ago re-runs Tier-1 + policy
		// against STALE Tier-2 evidence (4h TTL), defeating the purpose of
		// the rescan. Worst case: URL turned malicious 2h ago, ALLOW render
		// is still cached, ForceRescan re-runs policy on the old clean DOM
		// and confidently returns ALLOW again.
		var r *renderResponse
		var err error
		var cached *renderResponse
		if !req.ForceRescan && !req.Paranoid {
			cached = getRenderCache(ctx, s.Rdb, req.URL, domain)
		}
		if cached != nil {
			metrics.RenderCacheTotal.WithLabelValues("hit").Inc()
			r = cached
		} else {
			metrics.RenderCacheTotal.WithLabelValues("miss").Inc()
			r, err = s.callSandboxWithRetry(ctx, req.URL)
			if err != nil {
				log.Warn().Err(err).Str("url", sanitizeURLForLog(req.URL)).Msg("sandbox call failed (after retry)")
				// Classify sandbox failure reason for metrics.
				reason := classifySandboxError(err)
				metrics.SandboxFailuresTotal.WithLabelValues(reason).Inc()
			}
			// Store render result in Redis for future requests (fail-open on error).
			if err == nil && r != nil {
				setRenderCache(s.Rdb, req.URL, domain, r)
			}
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

	// Merge corroborator results into `in`. Done serially after the join so
	// concurrent writes to in.DomainAge / in.GSBClean / in.BlocklistHit are
	// impossible by construction.
	in.DomainAge = rdapAge
	in.GSBClean = webRiskClean
	if feedHit.Hit() {
		in.BlocklistHit = true
		feedSources = feedHit.Sources
	}

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
		_clearance        map[string]string
		// Phase D: trust score + contributors lifted out so the response
		// assembly block can surface them in the evidence UI.
		trustScore   float64
		trustContrib []policy.TrustContributor
	)
	if useLegacyPolicy() {
		finalVerdict, codes, blockReason, strictnessApplied, confidence, pageClass, grade =
			legacyDecision(req, in, out, render, feedSources, oauthDec)
	} else {
		policyIn := buildPolicyInputs(req, in, out, render, feedSources, feedHit, oauthDec, vendorDNS)
		// Phase F: when XGG_SHADOW_ENABLED=1, run the configured candidate
		// engine in parallel and emit a diff metric + log line. The
		// production verdict is always what we return to the user; the
		// candidate's output never leaks. Default-off → zero overhead.
		var policyOut policy.Result
		if cand := shadowCandidate(); cand != nil {
			out, diff := policy.RunShadow(policyIn, cand)
			policyOut = out
			recordShadowDiff(policyIn.Domain, diff)
		} else {
			policyOut = policy.Apply(policyIn)
		}
		finalVerdict = string(policyOut.Verdict)
		codes = policyOut.ReasonCodes
		blockReason = policyOut.BlockReason
		strictnessApplied = containsCode(codes, reasons.BlockedByStrictnessPolicy)
		confidence = policyOut.Confidence
		pageClass = string(policyIn.PageClass)
		grade = chooseGrade(finalVerdict, confidence)
		// Stash policy clearance checks for response assembly below.
		_clearance = policyOut.ClearanceChecks
		trustScore = policyIn.TrustScore
		trustContrib = policyIn.TrustContributors
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
	// Extras land in evidence.signals JSON so the portal-api evidence
	// endpoint can surface them to the block page without a schema migration
	// for every new field.
	persistExtras := map[string]any{}
	if vendorDNS.Hit() {
		persistExtras["vendor_dns_blocked_by"] = vendorDNS.BlockedBy
	}
	if in.DomainAge > 0 {
		persistExtras["domain_age_days"] = int(in.DomainAge.Hours() / 24)
	}
	if len(_clearance) > 0 {
		persistExtras["clearance_checks"] = _clearance
	}
	if err := persistScan(ctx, s.Pg, in, out, render, codes, evidenceID, finalVerdict, pageClass, grade, t1.Score, persistExtras); err != nil {
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
	// Surface domain age from RDAP so the block page can render
	// "Registered N days ago" badges.
	if in.DomainAge > 0 {
		resp.DomainAgeKnown = true
		resp.DomainAgeDays = int(in.DomainAge.Hours() / 24)
	}
	if vendorDNS.Hit() {
		resp.VendorDNSBlockedBy = vendorDNS.BlockedBy
	}
	if len(_clearance) > 0 {
		resp.ClearanceChecks = _clearance
	}
	// Phase D: surface the trust score + contributors so the evidence UI
	// can show *why* a verdict softened or didn't. Always populated (even
	// at zero) so the UI always has a slot to render.
	resp.TrustScore = trustScore
	if len(trustContrib) > 0 {
		out := make([]trustContributor, 0, len(trustContrib))
		for _, c := range trustContrib {
			out = append(out, trustContributor{Label: c.Label, Weight: c.Weight})
		}
		resp.TrustContributors = out
	}
	// Phase B: surface connection identity to the response when the extension
	// supplied browser_remote_ip. Compares the browser's actual remote IP
	// against the XGG resolver's returned-IP ledger (Phase B.4) and emits
	// USER_DNS_PATH_MATCH / USER_DNS_PATH_MISMATCH / EXPECTED_RESOLVER_BYPASSED.
	//
	// Note: these are informational signals on this response, NOT verdict-
	// changing. The verdict-changing hard rule (PUBLIC_DOMAIN_PRIVATE_IP) is
	// already enforced upstream in policy.Apply. ASN-based CDN_ASN_MATCH /
	// MISMATCH and TLS_IDENTITY_MISMATCH land in Phase B.5b once we have
	// ASN/TLS data sources.
	if req.BrowserRemoteIP != "" {
		id := &connid.Identity{
			Domain:          domain,
			BrowserRemoteIP: req.BrowserRemoteIP,
		}
		// Ledger comparison. Best-effort: a Redis miss doesn't change the
		// verdict — connection identity is then simply "absent" on that
		// dimension, not "failed."
		ledgerCtx, ledgerCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		ledgerEntries, ledgerErr := iledger.Recent(ledgerCtx, s.Rdb, req.ClientID, domain)
		ledgerCancel()
		if ledgerErr != nil {
			log.Debug().Err(ledgerErr).Str("domain", domain).Msg("iledger read failed; treating as cold")
		}
		ledgerInput := connid.CompareInput{
			BrowserRemoteIP:       req.BrowserRemoteIP,
			ClientOptedIntoXGGDNS: false, // Phase B.5b: derive from request once the extension signals it
		}
		for _, e := range ledgerEntries {
			ledgerInput.LedgerEntries = append(ledgerInput.LedgerEntries, connid.LedgerEntry{IP: e.IP})
			id.XGGResolverIPsForClient = append(id.XGGResolverIPsForClient, e.IP)
		}
		cmp := connid.CompareLedger(ledgerInput)
		id.DNSPathConsistent = cmp.DNSPathConsistent
		for _, c := range cmp.ReasonCodes {
			resp.ReasonCodes = append(resp.ReasonCodes, string(c))
			metrics.RuleFiredTotal.WithLabelValues(string(c)).Inc()
		}
		resp.ConnectionIdentity = id
	}

	event := map[string]any{
		"ts":               resp.ScannedAt,
		"url":              sanitizeURLForLog(req.URL), // strip query/fragment (tokens, passwords, OAuth state)
		"url_host":         domain,                    // analytics-friendly host grouping
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

	// --- Verdict cache write (Cache 1): store result for future requests ---
	// Use context.Background() so a cancelled request context doesn't prevent
	// the cache write from completing.
	setVerdictCache(s.Rdb, req.URL, req.Paranoid, req.Mode, resp)

	// --- Metrics: emit verdict counter + pipeline latency ---
	mode := req.Mode
	if mode == "" {
		mode = "normal"
	}
	metrics.VerdictTotal.WithLabelValues(resp.Verdict, mode).Inc()

	// Per-rule emission counter (Phase A). Every reason code on the final
	// verdict bumps xgg_rule_fired_total{code=<CODE>}. This is the baseline
	// signal for the rule-health report: when paired with
	// xgg_rule_override_total (TODO from extension telemetry pipeline) it
	// surfaces which rules cause the most user overrides per fire. Without
	// this, rule tuning stays emotional.
	for _, code := range resp.ReasonCodes {
		metrics.RuleFiredTotal.WithLabelValues(code).Inc()
		// Phase G — per-rule × per-final-verdict count. Lets the rule-
		// health report distinguish "rule R contributed to BLOCK 80% of
		// the time vs WARN 20%" rather than treating every fire equally.
		metrics.RuleVerdictTotal.WithLabelValues(code, resp.Verdict).Inc()
	}

	tierLabel := "tier1_only"
	if resp.Cached {
		tierLabel = "cached"
	} else if runTier2 {
		tierLabel = "tier2"
	}
	metrics.VerdictLatency.WithLabelValues(tierLabel).Observe(time.Since(pipelineStart).Seconds())

	return resp
}

// classifySandboxError maps a sandbox call error to a reason label for metrics.
func classifySandboxError(err error) string {
	if err == nil {
		return "other"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "timeout"):
		return "timeout"
	case strings.Contains(msg, "502"):
		return "502"
	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host"):
		return "unreachable"
	case strings.Contains(msg, "401") || strings.Contains(msg, "Unauthorized"):
		return "auth"
	default:
		return "other"
	}
}

// --- Tier-2 helpers ---

// --- Phase 6 DOM-inventory finding types ---
// These mirror sandbox-render's new RenderResponse fields; the parallel
// agent owns their population; we own policy consumption.

type linkFinding struct {
	URL             string `json:"url"`
	Text            string `json:"text,omitempty"`
	Visible         bool   `json:"visible"`
	SameOrigin      bool   `json:"same_origin"`
	Extension       string `json:"extension,omitempty"`
	IsRiskyDownload bool   `json:"is_risky_download"`
	Rel             string `json:"rel,omitempty"`
	TargetBlank     bool   `json:"target_blank"`
	HasDownloadAttr bool   `json:"has_download_attr"`
}

type iframeFinding struct {
	Src           string `json:"src"`
	SameOrigin    bool   `json:"same_origin"`
	Visible       bool   `json:"visible"`
	Sandbox       string `json:"sandbox,omitempty"`
	SrcdocSnippet string `json:"srcdoc_snippet,omitempty"`
	Dimensions    []int  `json:"dimensions,omitempty"` // [w, h]
}

type hiddenElementFinding struct {
	Tag             string `json:"tag"`
	Reason          string `json:"reason"`
	HrefOrSrc       string `json:"href_or_src,omitempty"`
	InnerTextSample string `json:"inner_text_sample,omitempty"`
}

type suspiciousJSFinding struct {
	Indicator   string `json:"indicator"`
	Detail      string `json:"detail,omitempty"`
	ScriptIndex int    `json:"script_index"`
}

type overlayFinding struct {
	ZIndex           int    `json:"z_index"`
	CoveragePct      int    `json:"coverage_pct"`
	Transparent      bool   `json:"transparent"`
	InterceptsClicks bool   `json:"intercepts_clicks"`
	HrefOrListener   string `json:"href_or_listener,omitempty"`
}

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
	Sink             sinkObservation     `json:"sink"`
	// ShellCmd — IOCs extracted from <pre>/<code> blocks on docs-style
	// pages. Used to catch the Straiker-class "docs page IS the weapon"
	// attack where the malicious payload is just text in the page.
	ShellCmd         shellCmdObservation `json:"shellcmd"`
	// Phase 6 DOM inventory — populated by sandbox-render's new extractor.
	Links          []linkFinding          `json:"links,omitempty"`
	IFrames        []iframeFinding        `json:"iframes,omitempty"`
	HiddenElements []hiddenElementFinding `json:"hidden_elements,omitempty"`
	SuspiciousJS   []suspiciousJSFinding  `json:"suspicious_js,omitempty"`
	Overlays       []overlayFinding       `json:"overlays,omitempty"`
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
	r, err := s.postJSON(ctx, sandboxRenderURL()+"/render", body, 45*time.Second)
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
	r, err := s.postJSON(ctx, visualMatchURL()+"/match", body, 15*time.Second)
	if err != nil {
		return nil, err
	}
	var mr matchResponse
	if err := json.Unmarshal(r, &mr); err != nil {
		return nil, err
	}
	return &mr, nil
}

// postJSON sends a JSON POST to url and returns the response body.
// Timeout is applied via context.WithTimeout on the request so the
// shared client's transport can reuse connections across calls.
func (s *Server) postJSON(ctx context.Context, url string, body []byte, timeout time.Duration) ([]byte, error) {
	// Apply per-call timeout via context rather than on the Client itself,
	// which allows the shared transport to reuse idle connections.
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, _ := http.NewRequestWithContext(rctx, http.MethodPost, url, strings.NewReader(string(body)))
	req.Header.Set("content-type", "application/json")
	// Attach the inter-service shared secret so sandbox-render and visual-match
	// can validate that requests originate from verdict-api (Audit Finding #3).
	internalauth.AddToken(req)

	// Use the shared pooled client when available; fall back to a per-call
	// client only in tests where SharedHTTPClient is not initialised.
	httpClient := s.SharedHTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, errors.New(resp.Status)
	}
	// A legitimate sandbox response is typically 50-200 KB; 4 MB is well above
	// any plausible response. Anything larger is a misbehaving upstream or an
	// attack attempting to OOM the verdict-api process.
	return io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
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
	// Page-class-driven force: any URL whose path matches a sensitive page
	// class (login/payment/oauth/mfa/admin/install-lure) MUST run Tier-2
	// even when Tier-1 score is low. Without this we get the
	// SENSITIVE_PAGE_VERIFICATION_UNAVAILABLE ISOLATE class on every
	// legitimate /billing /checkout /oauth /mfa URL with a calm Tier-1
	// signal. The string-pattern list below covers a SUBSET; the
	// pageclass module is the authoritative classifier.
	if pageclass.FromURL(raw).IsSensitive() {
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
