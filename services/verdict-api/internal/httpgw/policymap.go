// policymap.go — adapter between the existing pipeline state (fusion.Inputs,
// renderResponse, brand registry, feed lookup, oauth registry) and the new
// staged policy engine.
//
// This is the cutover point: the pipeline still gathers data the same way
// (Tier-1, sandbox, visual-match, RDAP, feeds, OAuth), but the final
// decision is made by `policy.Apply()` instead of `fusion.Score()` +
// `codesFromFusion()` + `strictness.Apply()`.
//
// Set USE_LEGACY_POLICY=1 to fall back to the old path (kept for the
// migration safety net).
package httpgw

import (
	"os"
	"net/url"
	"strings"

	"github.com/xgenguardian/services/verdict-api/internal/connid"
	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/installreg"
	"github.com/xgenguardian/services/verdict-api/internal/oauthreg"
	"github.com/xgenguardian/services/verdict-api/internal/orggraph"
	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
	"github.com/xgenguardian/services/verdict-api/internal/brandgraph"
	"github.com/xgenguardian/services/verdict-api/internal/cryptodrainer"
	"github.com/xgenguardian/services/verdict-api/internal/paymentscam"
	"github.com/xgenguardian/services/verdict-api/internal/policy"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
	"github.com/xgenguardian/services/verdict-api/internal/supportscam"
	"github.com/xgenguardian/services/verdict-api/internal/trustscore"
	"github.com/xgenguardian/services/verdict-api/internal/vendordns"
)

// useLegacyPolicy is true when USE_LEGACY_POLICY env is set. Operator panic
// button to revert to the pre-staged-policy code path. Remove in Phase 3
// once we've confidence in the new engine.
func useLegacyPolicy() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("USE_LEGACY_POLICY")))
	return v == "1" || v == "true" || v == "yes"
}

// buildPolicyInputs maps current pipeline state into the policy-engine input
// struct. The mapping is deliberately conservative: when the pipeline can't
// verify something (sandbox 502, no visual-match match, no RDAP info), we
// emit `Unknown=true` rather than `Bound=true`. The policy engine then
// applies fail-closed for sensitive pages.
func buildPolicyInputs(
	req checkRequest,
	in fusion.Inputs,
	out fusion.Output,
	render *renderResponse,
	feedSources []string,
	feedHit FeedHit, // tiered feed lookup result
	oauthDec *oauthreg.Decision,
	vendorDNS vendordns.ConsensusResult,
	tier2Requested bool, // pipeline asked for sandbox evidence (regardless of outcome)
) policy.Inputs {
	// Stage A: page class.
	urlClass := pageclass.FromURL(req.URL)
	hints := pageclass.DOMHints{}
	if render != nil {
		hints.HasPasswordField = anyPasswordForm(render.Forms)
		// Email/OTP/payment detection from forms — currently we only know
		// has_email; OTP / payment field detection lands in Package 4
		// (CredentialSinkTrust) when we instrument input fields properly.
		for _, f := range render.Forms {
			if f.HasEmail {
				hints.HasEmailField = true
			}
		}
		if b := render.Behavior; b != nil {
			hints.ForcedFullscreen = b["fullscreen_req"] >= 1
			hints.PopupStorm = b["popup_open"] >= 3
			hints.AlertLoop = b["alert"]+b["confirm"]+b["prompt"] >= 2
			hints.HasDownloadTrigger = b["auto_download"] >= 1
		}
	}
	if oauthDec != nil {
		hints.HasOAuthClientID = true
	}
	// Shell-command IOC findings — any pattern hit (hard or soft) tells
	// the page-classifier that the page contains an install command,
	// which promotes it to DeveloperToolInstallLure so the policy applies
	// the dev-install ruleset (and downstream verdict pages show the
	// dev-tool-specific block reason).
	if render != nil && (render.ShellCmd.HasHardFail || render.ShellCmd.SoftSignalCount > 0) {
		hints.HasInstallShellCommand = true
	}
	cls := pageclass.Refine(urlClass, hints)

	// Stage B: replica claim.
	// High match (>=0.85) is a confident "this looks like brand X" claim.
	// Weak match (0.70-0.85) is a soft signal — useful when corroborated with
	// untrusted-host + page-class; on its own it doesn't move the verdict.
	// BrandNameInURL — independent text-channel corroborator: the brand
	// keyword shows up in URL or page title (CLIP can't read text, so this
	// is independent evidence). Lets the borderline path (0.62-0.70) fire.
	replica := policy.ReplicaOutput{
		Brand:          out.TopBrand,
		PageClass:      cls,
		Score:          out.TopScore,
		IsHighMatch:    out.TopScore >= 0.85,
		IsWeakMatch:    out.TopScore >= 0.70 && out.TopScore < 0.85,
		BrandNameInURL: brandNameInURL(out.TopBrand, req.URL, renderTitle(render)),
	}

	// Stage C: identity binding.
	// "Bound" requires every checked dimension to match the brand's allow-list.
	// "Unknown" when the brand has no allow-list to compare against, OR when
	// we have no brand to compare against at all.
	identity := policy.IdentityOutput{BrandName: replica.Brand}
	switch {
	case replica.Brand == "":
		// No replica claim → identity is not applicable. Treat as bound so
		// the B+C rule doesn't fire (which is correct — non-imitation pages
		// don't need identity binding).
		identity.Bound = true
	case len(in.BrandCanonicalDomains) == 0:
		// Replica matched a brand but we have no canonical_domains list to
		// compare to. Genuine "unknown".
		identity.Unknown = true
	default:
		identity = identityFromBrandData(in, render)
	}
	// Domain must always match — even when ASN/cert data is missing.
	if replica.Brand != "" && !domainInList(in.Domain, in.BrandCanonicalDomains) {
		identity.MismatchDomain = true
		identity.Bound = false
	}

	// Stage D: credential-sink trust. Two data sources:
	//   1. Static form-action analysis (always available).
	//   2. Runtime sink instrumentation from window.__xgg_sink (Package 4).
	//
	// The runtime data is much stronger because it catches kits that
	// don't use <form> elements at all — keystroke listeners → fetch,
	// JS-only credential POSTs, multi-destination exfil.
	sink := policy.SinkOutput{}
	if render != nil {
		// 1. Static form-action analysis (legacy).
		for _, f := range render.Forms {
			if f.HasPassword && f.IsCrossOrigin {
				sink.CrossOrigin = true
				if f.ActionOrigin != "" {
					sink.Destinations = appendUnique(sink.Destinations, f.ActionOrigin)
				}
				sink.CaptureMode = "form"
			}
		}

		// 2. Runtime data — promote whatever the in-page instrumentation saw.
		rs := render.Sink
		if rs.CrossOrigin {
			sink.CrossOrigin = true
		}
		if rs.PreSubmitCapture {
			sink.PreSubmitCapture = true
			sink.CaptureMode = "listener"
		}
		if rs.MultiDestination {
			sink.MultiDestination = true
		}
		if rs.HiddenMirror || rs.InvisibleCredentialField || rs.PointerEventsTrick {
			sink.HiddenMirror = true
		}
		// Merge runtime destinations (cross-origin only) into the static set.
		for _, d := range rs.Destinations {
			if d.Cross {
				sink.Destinations = appendUnique(sink.Destinations, d.Origin)
			}
		}
		if rs.SensitiveListeners > 0 && sink.CaptureMode == "" {
			sink.CaptureMode = "listener"
		}

		// Cross-origin sink with a non-brand-allowlisted target is the
		// strongest "this is exfiltrating to a stranger" signal.
		if sink.CrossOrigin && len(in.BrandCanonicalDomains) > 0 {
			allTrusted := true
			for _, dst := range sink.Destinations {
				if !originMatchesBrand(dst, in.BrandCanonicalDomains) {
					allTrusted = false
					break
				}
			}
			if !allTrusted {
				sink.UntrustedEndpoint = true
			}
		}
	} else {
		// No render → sink trust is unknown. Policy uses VerificationAvailable
		// to decide fail-open vs fail-closed.
		sink.Unknown = true
	}

	// Stage F: context (feeds, OAuth, behavior, YARA, drift, challenge).
	ctx := policy.ContextOutput{
		// Tier-2 / sandbox health gate. policy.Apply uses these two
		// fields to ESCALATE sensitive pages to ISOLATE when Tier-2
		// evidence was needed but not collected — closes the silent
		// fake-safety bug class. A render is "available" when the
		// pipeline got either a fresh render OR a cached render back.
		Tier2Requested: tier2Requested,
		Tier2Available: render != nil,
	}

	// Wave 3 / Phase 1 — Support-scam scoring. Today the inputs are
	// URL + SLD + page title (when render available). Phase 2 adds
	// visible DOM text from sandbox-render; Phase 3 adds OCR text.
	// host-in-brandgraph short-circuits the brand-impersonation
	// category so legitimate Microsoft support pages on microsoft.com
	// don't fire.
	sld := pageclassExtractSLD(req.URL)
	title := renderTitle(render)
	var visibleText, ocrText string
	if render != nil {
		visibleText = render.VisibleText
		ocrText = render.OCRText
	}
	ssRes := supportscam.Score(supportscam.Inputs{
		URL:              req.URL,
		SLD:              sld,
		Title:            title,
		VisibleText:      visibleText,
		OCRText:          ocrText,
		Host:             in.Domain,
		HostInBrandgraph: brandgraph.IsAnyTrust(in.Domain),
	})
	ctx.SupportScamScore = ssRes.Score
	ctx.SupportScamCategories = supportScamCategoryNames(ssRes)

	// Payment-scam scorer (Wave 3 Phase 2). Same inputs as support-scam.
	psRes := paymentscam.Score(paymentscam.Inputs{
		URL:              req.URL,
		SLD:              sld,
		Title:            title,
		VisibleText:      visibleText,
		OCRText:          ocrText,
		Host:             in.Domain,
		HostInBrandgraph: brandgraph.IsAnyTrust(in.Domain),
	})
	ctx.PaymentScamScore = psRes.Score
	ctx.PaymentScamCategories = paymentScamCategoryNames(psRes)

	// Crypto-drainer scorer (Wave 3 Phase 2). Adds ScriptIndicators
	// from sandbox-render's suspicious_js findings so EIP-1193 method
	// signatures (eth_signTypedData_v4, setApprovalForAll, etc.) on
	// untrusted hosts contribute.
	var scriptIndicators []string
	if render != nil {
		for _, s := range render.SuspiciousJS {
			scriptIndicators = append(scriptIndicators, s.Indicator)
		}
	}
	cdRes := cryptodrainer.Score(cryptodrainer.Inputs{
		URL:              req.URL,
		SLD:              sld,
		Title:            title,
		VisibleText:      visibleText,
		OCRText:          ocrText,
		Host:             in.Domain,
		HostInBrandgraph: brandgraph.IsAnyTrust(in.Domain),
		ScriptIndicators: scriptIndicators,
	})
	ctx.CryptoDrainerScore = cdRes.Score
	ctx.CryptoDrainerCategories = cryptoDrainerCategoryNames(cdRes)
	// Domain age (from RDAP). in.DomainAge is time.Duration; 0 means unknown
	// (RDAP lookup failed, no registration date in response, or RDAP not
	// configured). DomainAgeKnown lets the policy distinguish "we know it's
	// 0 days old" (a brand-new domain) from "we never asked".
	if in.DomainAge > 0 {
		ctx.DomainAgeKnown = true
		ctx.DomainAgeDays = int(in.DomainAge.Hours() / 24)
	}
	// VendorDNS — 8-provider protective-DNS consensus. ConsensusBlocks()
	// returns true when ≥2 providers blocked (high-confidence). A single
	// vendor hit is advisory only.
	if vendorDNS.ConsensusBlocks() {
		ctx.VendorDNSBlocked = true
		ctx.VendorDNSBlockedBy = vendorDNS.BlockedBy
	} else if vendorDNS.Hit() {
		ctx.VendorDNSSingleHit = true
		ctx.VendorDNSBlockedBy = vendorDNS.BlockedBy
	}
	if in.BlocklistHit {
		ctx.FeedHit = true
		ctx.FeedSources = feedSources
		// Tier breakdown: lets the decision matrix apply the consensus
		// rule (single-high = block, ≥2 medium = block, single-medium = WARN/Tier-2).
		ctx.FeedHighSources = feedHit.HighSources
		ctx.FeedMediumSources = feedHit.MediumSources
		ctx.FeedLowSources = feedHit.LowSources
		ctx.FeedCategories = feedHit.Categories
	}
	if render != nil {
		ctx.IsChallengePage = render.IsChallengePage
		ctx.ChallengeKind = render.ChallengeKind
		if render.Behavior != nil {
			tripped := 0
			if render.Behavior["popup_open"] >= 3 {
				ctx.BehaviorPopupStorm = true
				tripped++
			}
			if render.Behavior["alert"]+render.Behavior["confirm"]+render.Behavior["prompt"] >= 2 {
				tripped++
			}
			if render.Behavior["fullscreen_req"] >= 1 {
				tripped++
			}
			if render.Behavior["clipboard_write"] >= 1 {
				ctx.BehaviorClipboardHijack = true
				tripped++
			}
			if render.Behavior["auto_download"] >= 1 {
				tripped++
			}
			if tripped >= 3 {
				ctx.BehaviorScareware = true
			}
		}
		// YARA per-rule reason codes are populated from the render response.
		if len(render.YaraMatches) > 0 {
			ctx.YaraReasonCodes = codesFromYaraMatches(render.YaraMatches)
		}
	}
	if oauthDec != nil && !oauthDec.Known && oauthDec.SuspiciousScopes {
		ctx.OAuthHighRiskUnknown = true
		ctx.OAuthAppName = oauthDec.AppName
		ctx.OAuthClientID = oauthDec.ClientID
	}
	// Path drift is Package 5; leave false for now.

	// Raw-IP host + IoT-malware binary-drop path. Computed from the request
	// URL independently of any feed/sandbox signal so we catch botnet drops
	// that haven't been ingested by URLhaus yet (which is most of them on
	// any given day).
	if isRawIPHost(req.URL) {
		ctx.RawIPHost = true
		if isDL, _ := looksLikeDirectDownload(req.URL); isDL {
			ctx.RawIPBinaryDrop = true
		}
	}

	// Phase B: connection identity. Stash the browser_remote_ip the
	// extension reported plus a private-IP flag so the policy can fire
	// PUBLIC_DOMAIN_PRIVATE_IP. The full comparison logic (CDN ASN,
	// resolver ledger, TLS) lands in Phase B.5; this is the minimum
	// surface area needed for the first hard rule.
	if req.BrowserRemoteIP != "" {
		ctx.BrowserRemoteIP = req.BrowserRemoteIP
		ctx.BrowserRemoteIPIsPrivate = connid.IsPrivateIP(req.BrowserRemoteIP)
	}

	// Tier-1 hostname-shape signals → SuspiciousHostnameSignals flag.
	// Combine DGA + random_host so policy reacts to both consistently.
	var hostHints []string
	for _, s := range in.Tier1Signals {
		switch s.Name {
		case "dga_classifier_hit":
			hostHints = append(hostHints, "DGA classifier")
		case "random_host":
			hostHints = append(hostHints, "random-host heuristic")
		case "homoglyph_match":
			// Strong Tier-1 brand-impersonation signal. Two flavors both
			// land here:
			//   weight 0.85 — pure confusable substitution (g00gle → google
			//                 via 0→o, paypa1 → paypal via 1→l).
			//   weight 0.70 — Levenshtein ≤2 typo (gooogle → google by
			//                 inserting an o; paypall → paypal by deletion).
			// Both are high-confidence impersonation tells; both deserve
			// the same hard rule in policy.Apply. Pre-Wave-3 the
			// threshold was 0.85 and gooogle.example slipped through
			// despite Tier-1 emitting weight 0.70 — caught by smoke
			// corpus case typo-google-letter-swap.
			if s.Weight >= 0.70 {
				ctx.HomoglyphBrandMatch = true
				// Detail format is e.g. "'g00gle' → 'google' matches brand keyword 'google'"
				// or "edit distance 1 from brand keyword 'google' (via gooogle)".
				// In both shapes the last single-quoted token is the brand.
				ctx.HomoglyphBrandName = extractHomoglyphBrand(s.Detail)
			}
		}
	}
	if len(hostHints) > 0 {
		ctx.SuspiciousHostnameSignals = true
		ctx.SuspiciousHostnameDetail = "Triggered: " + strings.Join(hostHints, " + ")
	}

	// Shell-command IOC findings from sandbox-render (Straiker attack class).
	if render != nil {
		ctx.ShellCmdHardFail = render.ShellCmd.HasHardFail
		ctx.ShellCmdSoftSignals = render.ShellCmd.SoftSignalCount
		ctx.ShellCmdReasonCodes = render.ShellCmd.ReasonCodes

		// Positive-trust path: check each surfaced command against the
		// Official Install Registry. Tracks vetted vs unvetted counts so
		// the "all commands are official vendor templates" case can fully
		// suppress hard-fail signals (legit vendors publish irm|iex etc.).
		vetted, unvetted := 0, 0
		for _, c := range render.ShellCmd.CommandsSeen {
			if m := installreg.MatchCommand(in.Domain, c.Text); m != nil {
				if !ctx.OfficialInstallMatch {
					ctx.OfficialInstallBrand = m.Brand
					ctx.OfficialInstallLabel = m.Label
				}
				ctx.OfficialInstallMatch = true
				vetted++
			} else {
				unvetted++
			}
		}
		// If every surfaced command was a recognized vendor template, the
		// IOC patterns that fired were firing on those vendor commands —
		// not on attacker-controlled additions. Clear the hard-fail flag
		// in that case so policy.Apply doesn't downgrade to WARN.
		if ctx.OfficialInstallMatch && unvetted == 0 {
			ctx.ShellCmdHardFail = false
			ctx.ShellCmdSoftSignals = 0
			ctx.ShellCmdReasonCodes = nil
		}
		// Telemetry-only: host has templates but none matched. Indicates
		// the vendor likely changed their install command — log so we can
		// refresh the template before users hit FPs.
		if !ctx.OfficialInstallMatch &&
			installreg.HasTemplatesForHost(in.Domain) &&
			len(render.ShellCmd.CommandsSeen) > 0 {
			ctx.OfficialMatchMissOnTrusted = true
		}
	}

	// Phase 6: populate deep DOM signals from sandbox-render's DOM inventory.
	if render != nil {
		// RiskyDownloadCount — links flagged by sandbox-render as risky downloads.
		for _, l := range render.Links {
			if l.IsRiskyDownload {
				ctx.RiskyDownloadCount++
			}
		}

		// HiddenSuspiciousCount — hidden anchors/iframes/forms whose href is
		// either CROSS-ORIGIN or points at a risky-extension binary. Three
		// orthogonal filters keep this from false-positing on legit sites:
		//
		//   1. Same-origin (.example.com → example.com) is NOT cross-origin.
		//      Collapsed dropdown menus on a single domain are common.
		//
		//   2. Same-ORGANIZATION (Disney's moviesanywhere.com → disney.com)
		//      is NOT cross-origin. The orggraph package maps multi-brand
		//      organizations to a single org-id; SameOrgHosts returns true
		//      across all of an org's domains. This is the structural fix
		//      replacing per-brand suffix entries in trustreg.
		//
		//   3. Risky-extension hrefs (links to .exe / .msi / .dmg etc.) ARE
		//      counted regardless of cross-origin status — even same-org
		//      hidden download links warrant scrutiny.
		pageHost := strings.ToLower(in.Domain)
		for _, h := range render.HiddenElements {
			if h.HrefOrSrc == "" {
				continue
			}
			if h.Tag != "a" && h.Tag != "iframe" && h.Tag != "form" {
				continue
			}
			isCrossOrigin := false
			if u, err := url.Parse(h.HrefOrSrc); err == nil && u.Host != "" {
				targetHost := strings.ToLower(u.Host)
				// Strip :port for comparison.
				if i := strings.IndexByte(targetHost, ':'); i >= 0 {
					targetHost = targetHost[:i]
				}
				sameHost := strings.EqualFold(targetHost, pageHost) ||
					strings.HasSuffix(targetHost, "."+pageHost)
				sameOrg := orggraph.SameOrgHosts(targetHost, pageHost)
				if !sameHost && !sameOrg {
					isCrossOrigin = true
				}
			}
			isRiskyExt := false
			if strings.ContainsAny(h.HrefOrSrc, ".") {
				lower := strings.ToLower(h.HrefOrSrc)
				for _, ext := range []string{".exe", ".msi", ".scr", ".bat",
					".cmd", ".com", ".pif", ".ps1", ".vbs", ".jse", ".wsf",
					".jar", ".dll", ".apk", ".dmg", ".pkg", ".iso", ".lnk"} {
					if strings.Contains(lower, ext) {
						isRiskyExt = true
						break
					}
				}
			}
			if isCrossOrigin || isRiskyExt {
				ctx.HiddenSuspiciousCount++
			}
		}

		// ObfuscatedJSIndicators — distinct, non-"external" indicator strings.
		seen := map[string]struct{}{}
		for _, j := range render.SuspiciousJS {
			if j.Indicator == "external" {
				continue
			}
			if _, dup := seen[j.Indicator]; !dup {
				seen[j.Indicator] = struct{}{}
				ctx.ObfuscatedJSIndicators = append(ctx.ObfuscatedJSIndicators, j.Indicator)
			}
		}

		// HasCrossOriginIframe — hidden iframe from a different origin.
		for _, f := range render.IFrames {
			if !f.SameOrigin && !f.Visible {
				ctx.HasCrossOriginIframe = true
				break
			}
		}

		// HasClickjackOverlay — full-viewport transparent overlay.
		for _, o := range render.Overlays {
			if o.CoveragePct >= 25 && o.Transparent && o.InterceptsClicks {
				ctx.HasClickjackOverlay = true
				break
			}
		}
	}

	// Phase C.3 — scope-aware trust. Each Trust(host, scope) is a cheap
	// in-memory map lookup so doing all 6 in a row is fine. The bool
	// here is "matched the brand AND the scope" (Match.Brand != "").
	trustedLogin := brandgraph.Trust(in.Domain, brandgraph.ScopeLogin).Brand != ""
	trustedPayment := brandgraph.Trust(in.Domain, brandgraph.ScopePayment).Brand != ""
	trustedOAuth := brandgraph.Trust(in.Domain, brandgraph.ScopeOAuthRedirect).Brand != ""
	trustedScript := brandgraph.Trust(in.Domain, brandgraph.ScopeScriptSource).Brand != ""
	trustedCDN := brandgraph.Trust(in.Domain, brandgraph.ScopeCDN).Brand != ""
	trustedDocs := brandgraph.Trust(in.Domain, brandgraph.ScopeDocs).Brand != ""
	trustedFullBrand := brandgraph.Trust(in.Domain, brandgraph.ScopeFullTrust).Brand != ""
	trustedAny := brandgraph.IsAnyTrust(in.Domain)

	// Phase D.2 — assemble the trust-score Signals from data we already
	// extracted into ctx and from brandgraph/orggraph. Pure aggregation;
	// no I/O here. The Score function is bounded + clamped.
	tsSignals := trustscore.Signals{
		DomainAgeDays:       ctx.DomainAgeDays,
		DomainAgeKnown:      ctx.DomainAgeKnown,
		FeedClean:           !ctx.FeedHit,
		VendorDNSClean:      !ctx.VendorDNSBlocked && !ctx.VendorDNSSingleHit,
		BrandgraphFullTrust: trustedFullBrand,
		BrandgraphAnyScope:  trustedAny && !trustedFullBrand,
		OrggraphKnown:       orggraph.OrgOf(in.Domain) != "",
		// HTTPSValid is a Phase B.5b deliverable (TLS introspection).
		// Leave false for now; Phase B.5b flips this when the signal exists.
		HTTPSValid: false,
		// HistoricalCleanCount lands when we read prior-verdict counters
		// from Postgres. Leave 0 for now — Phase D.4 hooks it up.
		HistoricalCleanCount: 0,
	}
	tsResult := trustscore.Score(tsSignals)
	trustContribs := make([]policy.TrustContributor, 0, len(tsResult.Contributors))
	for _, c := range tsResult.Contributors {
		trustContribs = append(trustContribs, policy.TrustContributor{
			Label:  c.Label,
			Weight: c.Weight,
		})
	}

	return policy.Inputs{
		URL:                   req.URL,
		Domain:                in.Domain,
		Replica:               replica,
		Identity:              identity,
		Sink:                  sink,
		Context:               ctx,
		PageClass:             cls,
		Paranoid:              req.Paranoid,
		Mode:                  req.Mode,
		CategoryBlocks:        req.Categories,
		VerificationAvailable: render != nil || in.BlocklistHit,
		// Legacy aggregate — alias for TrustedAnyScope while Phase D
		// migrates each soft rule to a specific scope.
		TrustedIdentity: trustedAny,
		// Scope-specific fields.
		TrustedForLogin:   trustedLogin,
		TrustedForPayment: trustedPayment,
		TrustedForOAuth:   trustedOAuth,
		TrustedForScript:  trustedScript,
		TrustedForCDN:     trustedCDN,
		TrustedForDocs:    trustedDocs,
		TrustedAnyScope:   trustedAny,
		// Phase D.2: trust score + contributors. No rule consults these
		// yet — Phase E refactors soft rules to ask for the score.
		TrustScore:        tsResult.Score,
		TrustContributors: trustContribs,
	}
}

// identityFromBrandData populates the per-dimension Mismatch* flags by
// comparing the actual page's hosting against the brand's allow-list.
// Domain is checked by the caller (always).
func identityFromBrandData(in fusion.Inputs, render *renderResponse) policy.IdentityOutput {
	out := policy.IdentityOutput{BrandName: in.VisualTopBrand}

	// ASN check — only flags if we have actual ASN data AND brand has an
	// allow-list. Otherwise leave unflagged (avoids false positives when
	// either side of the comparison is empty).
	if in.ASN != 0 && len(in.BrandLegitimateASNs) > 0 {
		matched := false
		for _, a := range in.BrandLegitimateASNs {
			if a == in.ASN {
				matched = true
				break
			}
		}
		if !matched {
			out.MismatchASN = true
		}
		out.HostingASN = in.ASN
	}

	// Cert issuer check — same shape.
	if in.CertIssuer != "" && len(in.BrandLegitimateIssuers) > 0 {
		issuerL := strings.ToLower(in.CertIssuer)
		matched := false
		for _, allowed := range in.BrandLegitimateIssuers {
			if strings.Contains(issuerL, strings.ToLower(allowed)) {
				matched = true
				break
			}
		}
		if !matched {
			out.MismatchCert = true
		}
		out.CertIssuer = in.CertIssuer
	}

	// Bound = no per-dimension mismatch fired. Caller still adds
	// MismatchDomain separately; combined Bound state is computed by the
	// caller after stitching both halves.
	out.Bound = !out.MismatchASN && !out.MismatchCert
	return out
}

// domainInList returns true if `domain` is `canon` or an end-subdomain of `canon`.
func domainInList(domain string, canonicals []string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, c := range canonicals {
		c = strings.ToLower(c)
		if d == c || strings.HasSuffix(d, "."+c) {
			return true
		}
	}
	return false
}

// originMatchesBrand — true when a form-action origin like
// "https://www.paypal.com" is on the brand's canonical-domain list. We strip
// the scheme + port and reuse domainInList.
func originMatchesBrand(origin string, canonicals []string) bool {
	o := strings.TrimPrefix(origin, "https://")
	o = strings.TrimPrefix(o, "http://")
	if i := strings.IndexAny(o, "/:?"); i >= 0 {
		o = o[:i]
	}
	return domainInList(o, canonicals)
}

func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// policyResultToResponse converts a policy.Result into the wire-format
// checkResponse fields (verdict, codes, etc.). Caller still fills in
// EvidenceID, ScreenshotURL, Signals (raw, for analysts), and ScannedAt.
func policyResultToResponse(out policy.Result, fallbackEvidenceID string) checkResponse {
	return checkResponse{
		Verdict:           out.Verdict.String(),
		Confidence:        out.Confidence,
		ReasonCodes:       out.ReasonCodes,
		BlockReason:       out.BlockReason,
		StrictnessApplied: containsCode(out.ReasonCodes, reasons.BlockedByStrictnessPolicy),
		EvidenceID:        fallbackEvidenceID,
	}
}

func containsCode(xs []string, c reasons.Code) bool {
	want := string(c)
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// brandNameInURL — does the brand's name (or a normalized variant) appear
// in the request URL or page title? Independent text-channel corroborator
// for low-confidence visual matches. Case- and punctuation-insensitive.
//
// Examples that match:
//   brand="Amazon"  url=".github.io/AmazonClone"                -> true
//   brand="Steam"   url="/steam-login"                          -> true
//   brand="Apple"   url="apple-icloud-restore.tld"              -> true
//   brand="Crypto.com" title="Welcome to Crypto.com"            -> true
//
// Examples that do NOT match:
//   brand="Reddit"  url="aviralvishwakarma.github.io/AmazonClone" -> false
//   brand="Amazon"  url="amazingdeals.com"                       -> false (substring guard)
func brandNameInURL(brand, rawurl, title string) bool {
	if brand == "" {
		return false
	}
	key := normalizeBrandKey(brand)
	if key == "" {
		return false
	}
	hay := strings.ToLower(rawurl + " " + title)
	hay = strings.ReplaceAll(hay, "-", " ")
	hay = strings.ReplaceAll(hay, "_", " ")
	hay = strings.ReplaceAll(hay, "/", " ")
	hay = strings.ReplaceAll(hay, ".", " ")
	// Word-boundary-ish: require key to appear with non-alnum on at least
	// one side. Cheap impl: pad the haystack with spaces and check for
	// space+key or key+space.
	hay = " " + hay + " "
	return strings.Contains(hay, " "+key+" ") ||
		strings.Contains(hay, " "+key)
}

// normalizeBrandKey turns "Crypto.com" / "Bank of America" / "TD Bank" into
// space-stripped lowercase tokens we can match in URLs (cryptocom, bankofamerica,
// tdbank). Brands shorter than 4 chars are dropped — too prone to spurious
// substring hits ("ing" everywhere, "td" in many URLs).
func normalizeBrandKey(brand string) string {
	s := strings.ToLower(brand)
	// Drop punctuation
	for _, ch := range []string{".", " ", "-", "_", "+", "/"} {
		s = strings.ReplaceAll(s, ch, "")
	}
	if len(s) < 4 {
		return ""
	}
	return s
}

func renderTitle(r *renderResponse) string {
	if r == nil {
		return ""
	}
	return r.Title
}

// extractHomoglyphBrand pulls the trailing brand keyword out of a Tier-1
// homoglyph signal detail. Detail format is:
//
//	'g00gle' → 'google' matches brand keyword 'google'
//
// We want the last single-quoted token (the matched keyword). Cheap +
// purposely conservative: returns "" if parsing isn't a clean win, so
// downstream UI doesn't render garbage.
func extractHomoglyphBrand(detail string) string {
	last := strings.LastIndex(detail, "'")
	if last < 1 {
		return ""
	}
	first := strings.LastIndex(detail[:last], "'")
	if first < 0 || first >= last-1 {
		return ""
	}
	return detail[first+1 : last]
}

// pageclassExtractSLD wraps pageclass.ExtractSLD so this file's import
// list can keep `pageclass` once and use a stable spelling.
func pageclassExtractSLD(rawurl string) string {
	return pageclass.ExtractSLD(rawurl)
}

// supportScamCategoryNames returns the unique category names that
// fired in a supportscam.Result, in the order produced by the scorer.
// Used by policy.Apply to emit one reason code per category.
func supportScamCategoryNames(r supportscam.Result) []string {
	seen := map[supportscam.Category]struct{}{}
	out := make([]string, 0, len(r.Hits))
	for _, h := range r.Hits {
		if _, dup := seen[h.Category]; dup {
			continue
		}
		seen[h.Category] = struct{}{}
		out = append(out, string(h.Category))
	}
	return out
}

// paymentScamCategoryNames returns unique category names from a
// paymentscam.Result, in the order produced by the scorer.
func paymentScamCategoryNames(r paymentscam.Result) []string {
	seen := map[paymentscam.Category]struct{}{}
	out := make([]string, 0, len(r.Hits))
	for _, h := range r.Hits {
		if _, dup := seen[h.Category]; dup {
			continue
		}
		seen[h.Category] = struct{}{}
		out = append(out, string(h.Category))
	}
	return out
}

// cryptoDrainerCategoryNames returns unique category names from a
// cryptodrainer.Result, in the order produced by the scorer.
func cryptoDrainerCategoryNames(r cryptodrainer.Result) []string {
	seen := map[cryptodrainer.Category]struct{}{}
	out := make([]string, 0, len(r.Hits))
	for _, h := range r.Hits {
		if _, dup := seen[h.Category]; dup {
			continue
		}
		seen[h.Category] = struct{}{}
		out = append(out, string(h.Category))
	}
	return out
}
