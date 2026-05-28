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
	"strings"

	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/installreg"
	"github.com/xgenguardian/services/verdict-api/internal/oauthreg"
	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
	"github.com/xgenguardian/services/verdict-api/internal/policy"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
	"github.com/xgenguardian/services/verdict-api/internal/trustreg"
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
	ctx := policy.ContextOutput{}
	if in.BlocklistHit {
		ctx.FeedHit = true
		ctx.FeedSources = feedSources
		// Tier breakdown: lets the decision matrix apply the consensus
		// rule (single-high = block, ≥2 medium = block, single-medium = WARN/Tier-2).
		ctx.FeedHighSources = feedHit.HighSources
		ctx.FeedMediumSources = feedHit.MediumSources
		ctx.FeedLowSources = feedHit.LowSources
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

	return policy.Inputs{
		URL:                   req.URL,
		Domain:                in.Domain,
		Replica:               replica,
		Identity:              identity,
		Sink:                  sink,
		Context:               ctx,
		PageClass:             cls,
		Paranoid:              req.Paranoid,
		VerificationAvailable: render != nil || in.BlocklistHit,
		TrustedIdentity:       trustreg.IsTrusted(in.Domain),
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
