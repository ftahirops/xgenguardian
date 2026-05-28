// Package policy — staged verdict engine per dev spec §13.
//
// Replaces the flat weighted-sum fusion at the gateway boundary. Each
// stage owns one of the four questions (ReplicaClaim, IdentityBinding,
// CredentialSinkTrust, ContextRisk) and emits its own sub-verdict + reason
// codes. The final verdict comes from explicit decision rules over the
// stage outputs, NOT from summing weights.
//
//   Stage A: classify page class                 (pageclass.FromURL + Refine)
//   Stage B: compute replica score               (visual-match + favicon)
//   Stage C: identity binding                    (domain / ASN / cert / scripts)
//   Stage D: credential-sink trust               (form-action + runtime sinks)
//   Stage E: cloaking diff                       (multi-vantage, optional)
//   Stage F: supporting signals                  (behavior, downloads, feeds)
//   Stage G: final policy + verdict mapping
//
// Why stages instead of weights:
//   - Each stage can fail-stop. A confirmed feed hit short-circuits at F
//     without paying for B-D. A confirmed sink-trust failure BLOCKs even
//     when replica score is low (no need for "the page looks like X" before
//     we BLOCK a page silently sending creds to evil.example).
//   - Reasons stay orthogonal. IDENTITY_MISMATCH_ASN and
//     IDENTITY_MISMATCH_CERT are independent sub-failures of Stage C; they
//     never lump into a single "BRAND_MISMATCH" code.
//   - False positives shrink: a Microsoft tutorial blog with a Microsoft
//     screenshot has replica score high but identity bound (it's a
//     Microsoft-owned domain) so it ALLOWs cleanly.
package policy

import (
	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

// Verdict — final output mapped to the wire format.
type Verdict string

const (
	Allow     Verdict = "ALLOW"
	Warn      Verdict = "WARN"
	Block     Verdict = "BLOCK"
	Isolate   Verdict = "ISOLATE"
	Analyzing Verdict = "ANALYZING"
)

// String — for wire serialisation.
func (v Verdict) String() string { return string(v) }

// ReplicaOutput — Stage B result.
type ReplicaOutput struct {
	Brand       string  // empty when no match
	PageClass   pageclass.Class
	Score       float64 // 0..1; CLIP cosine similarity
	IsHighMatch bool    // score >= high threshold (0.85) — confident replica claim
	IsWeakMatch bool    // weak threshold (0.70) <= score < 0.85 — needs corroboration
	// BrandNameInURL — the brand's keyword appears in the request URL or
	// page title. With BrandNameInURL, even a 0.65-0.70 visual match is a
	// strong phishing tell (the page calls itself the brand AND visually
	// looks like it). CLIP can't read text, so this is independent corroboration.
	BrandNameInURL bool
}

// IdentityOutput — Stage C result. Each Mismatch* field is independent.
type IdentityOutput struct {
	// Bound: true if every checked dimension matched the brand's allow-list.
	// Unknown: true if we couldn't check (RDAP/feed lookup failed).
	Bound, Unknown bool

	MismatchDomain       bool   // hostname not in brand.canonical_domains
	MismatchASN          bool   // hosting ASN not in brand.legitimate_asns
	MismatchCert         bool   // cert issuer not in brand.legitimate_issuers
	MismatchScriptOrigin bool   // scripts loaded from outside brand allowlist
	HostingASN           int    // actual ASN seen
	CertIssuer           string // actual issuer
	BrandName            string
}

// SinkOutput — Stage D result. Tracks WHERE credential data would actually go.
type SinkOutput struct {
	// Trusted: explicit affirmative confirmation that all sinks are in the
	// brand's allow-list. Unknown: we never observed any sink (e.g. page
	// rendered as a CAPTCHA or page has no credential collection).
	Trusted, Unknown bool

	CrossOrigin       bool     // any sink crosses page origin
	UntrustedEndpoint bool     // sink not in brand allowlist
	PreSubmitCapture  bool     // keystroke listener observed
	MultiDestination  bool     // >1 distinct origins receive the same form
	HiddenMirror      bool     // hidden field forwards data to second sink
	Destinations      []string // ordered, deduped sink origins
	CaptureMode       string   // "form" | "fetch" | "xhr" | "beacon" | "ws" | "listener" | "unknown"
}

// ContextOutput — Stage F supporting signals. Sums to *modifiers* on the
// final mapping; never produces a verdict by itself except for the
// hard-feed-hit short-circuit.
type ContextOutput struct {
	FeedHit             bool     // URL or domain on threat feeds (any tier)
	FeedSources         []string // "urlhaus" | "phishdb_github" | "openphish" | ...
	// Source-tier breakdown for the consensus rule:
	//   - FeedHighSources non-empty       → single-source BLOCK justified
	//   - len(FeedMediumSources) >= 2     → multi-source consensus BLOCK
	//   - single medium hit only          → WARN + force Tier-2 (advisory)
	FeedHighSources     []string
	FeedMediumSources   []string
	FeedLowSources      []string
	PathDrift           bool     // previously-trusted domain, new sensitive path
	IsChallengePage     bool     // bot-protection wall (Cloudflare/Turnstile/etc.)
	ChallengeKind       string
	BehaviorScareware   bool     // 3+ abuse classes on one page
	BehaviorPopupStorm  bool
	BehaviorClipboardHijack bool
	OAuthHighRiskUnknown bool    // unknown client_id + sensitive scopes
	OAuthAppName        string
	OAuthClientID       string
	YaraReasonCodes     []string // per-rule reason codes from YARA matches

	// RawIPHost — URL points at a raw IPv4/IPv6 address rather than a domain.
	// On its own a soft signal (some dev/test traffic uses IPs); promotes
	// to BLOCK when combined with RawIPBinaryDrop.
	RawIPHost bool
	// RawIPBinaryDrop — raw IP host + Mirai-style architecture path
	// (e.g. http://1.2.3.4/x86, /arm5, /mips, /sh4). Near-certain malware
	// drop; the canonical signature of IoT botnet C2 infrastructure.
	RawIPBinaryDrop bool
	// ShellCmdHardFail — a sandboxed render of the page found a shell-
	// command IOC that is near-impossible on a legitimate install page
	// (rundll32 over UNC, mshta + remote HTA, PowerShell IEX cradle,
	// certutil urlcache). Direct evidence of "this docs page is the weapon."
	ShellCmdHardFail bool
	// ShellCmdSoftSignals — count of "common in malicious chains but
	// occasionally legitimate" patterns (base64 piped to shell, '&' trick,
	// raw GitHub installer). 2+ soft signals on an untrusted host promote.
	ShellCmdSoftSignals int
	// ShellCmdReasonCodes — per-pattern reason codes from the scan, surfaced
	// to the response for analyst drill-down.
	ShellCmdReasonCodes []string

	// OfficialInstallMatch — true when the page is on a registered vendor
	// host AND publishes a command that matches one of that vendor's
	// canonical install templates AND any URL in the command targets the
	// vendor's canonical hosts. Strong positive trust — gates ALLOW for
	// dev-install-lure pages.
	OfficialInstallMatch bool
	// OfficialInstallBrand — brand awarded by the match, e.g. "anthropic".
	OfficialInstallBrand string
	// OfficialInstallLabel — human label (e.g. "Claude Code official install (macOS/Linux)").
	OfficialInstallLabel string
	// OfficialMatchMissOnTrusted — telemetry-only flag set when a host
	// that *has* registered templates served a command none of them
	// matched. Indicates the vendor likely changed their install command
	// and we need to refresh the template. Does NOT change the verdict.
	OfficialMatchMissOnTrusted bool
}

// Inputs to Apply().
type Inputs struct {
	URL          string
	Domain       string
	Replica      ReplicaOutput
	Identity     IdentityOutput
	Sink         SinkOutput
	Context      ContextOutput

	// PageClass after Refine (Stage A). Stages C/D consult this to decide
	// whether a missing answer should be "unknown but OK" or "unknown but
	// elevate to ISOLATE".
	PageClass    pageclass.Class

	// Paranoid: Executive Mode toggle. Tightens generic mapping.
	Paranoid     bool

	// VerificationAvailable: false when sandbox/visual-match were down,
	// which makes Stages B/C/D unknowable rather than absent.
	VerificationAvailable bool

	// TrustedIdentity — true when the host is in the curated Trusted Identity
	// Registry (top brands: google, microsoft, amazon, apple, paypal, banks
	// etc.). Suppresses fail-closed ISOLATE for sensitive pages and downgrades
	// noisy credential-sink rules that frequently false-positive on legit
	// login flows (GitHub login posts to analytics + captcha + auth, which
	// our hidden-mirror detector treats as suspicious).
	TrustedIdentity bool
}

// Result is what gateway.go turns into the HTTP response.
type Result struct {
	Verdict     Verdict
	Confidence  float64
	ReasonCodes []string
	BlockReason string // human-readable summary for blocked.html

	// StageOutcome maps stage letter → "pass" | "fail" | "unknown" | "skip"
	// for analytics + the report-page drill-down.
	StageOutcome map[string]string
}

// Apply runs Stage G — combines per-stage outputs into the final verdict via
// the explicit decision rules from dev spec §13. No weighted sum here; if
// you can't trace the verdict back to a rule, it's a bug.
func Apply(in Inputs) Result {
	r := Result{
		Verdict:      Allow,
		ReasonCodes:  []string{},
		StageOutcome: map[string]string{},
	}

	// --- Stage F.1: threat-feed lookup with source-tier consensus ---
	//
	// Rule (matches the agreed architecture):
	//   - 1+ HIGH-confidence source hit          -> BLOCK (URLhaus/OpenPhish/Web Risk/curated)
	//   - 2+ distinct MEDIUM source hits         -> BLOCK by consensus
	//   - 1 MEDIUM source hit only               -> advisory: WARN + leave space
	//                                               for downstream rules to upgrade.
	//                                               Don't auto-BLOCK off noisy feeds.
	//   - LOW only                               -> informational; do nothing here.
	//
	// This replaces the previous "any FeedHit = BLOCK" rule which auto-blocked
	// off PhishDB-GitHub entries that had real false positives
	// (https://www.Amazon.com was the canonical case).
	switch {
	case len(in.Context.FeedHighSources) > 0:
		r.Verdict = Block
		r.Confidence = 1.0
		r.BlockReason = "URL or domain is on a high-confidence threat-intel feed (" +
			joinUpTo(in.Context.FeedHighSources, 3) + ")."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.ExternalFeedHit))
		if in.Context.OAuthHighRiskUnknown {
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.OAuthUnverifiedHighScopeApp))
		}
		r.StageOutcome["F"] = "fail-feed-high"
		return r
	case len(in.Context.FeedMediumSources) >= 2:
		r.Verdict = Block
		r.Confidence = 0.9
		r.BlockReason = "URL flagged by multiple independent community feeds (" +
			joinUpTo(in.Context.FeedMediumSources, 3) + ")."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.ExternalFeedHit))
		r.StageOutcome["F"] = "fail-feed-consensus"
		return r
	case len(in.Context.FeedMediumSources) == 1:
		// Advisory only. Set verdict to Warn as a default; deeper rules
		// (visual replica, sink failure, etc.) can still upgrade to BLOCK
		// or downgrade to ALLOW. The reason code surfaces so the report
		// page shows analysts WHY this URL got extra scrutiny.
		r.Verdict = Warn
		r.Confidence = 0.55
		r.BlockReason = "URL flagged by one community feed (" +
			in.Context.FeedMediumSources[0] + "). Treating as advisory."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.ExternalFeedHit))
		r.StageOutcome["F"] = "advisory-feed-single-medium"
		// Fall through — don't `return r` — so subsequent stages can
		// override either direction.
	}

	// --- Stage F.2: OAuth-app reputation (Spec §7 hard rule) ---
	// Real provider domain doesn't save you when the app is unverified +
	// asking for sensitive scopes.
	if in.Context.OAuthHighRiskUnknown {
		r.Verdict = Block
		r.Confidence = 0.9
		r.BlockReason = "Unverified OAuth app '" + in.Context.OAuthAppName +
			"' is requesting sensitive permissions on a real provider page."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.OAuthUnverifiedHighScopeApp))
		r.StageOutcome["F"] = "fail-oauth"
		return r
	}

	// --- Stage F.3: support-scareware composite ---
	if in.Context.BehaviorScareware {
		r.Verdict = Block
		r.Confidence = 0.88
		r.BlockReason = "Multiple scareware behaviours (popups, alerts, fullscreen) — fake tech-support pattern."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.FakeSupportScareware))
		r.StageOutcome["F"] = "fail-scareware"
		return r
	}

	// --- Stage D dominant: credential sink failure ---
	// If the page collects credentials AND the sink is not trusted, BLOCK
	// regardless of replica score. This is the canonical phishing tell
	// independent of "does the page look like a brand".
	//
	// EXCEPTION: trusted-identity hosts (github.com/login, accounts.google.com
	// etc.). Real login flows on these brands routinely POST to multiple
	// endpoints — analytics, captcha, auth — which trips our hidden-mirror
	// and multi-destination detectors. For trusted brands, sink heuristics
	// stay advisory (codes are recorded) but never block on their own; we
	// require an explicit Identity mismatch to flip the verdict (the BLOCK
	// path in the next section).
	if in.PageClass.IsSensitive() && !in.TrustedIdentity {
		if in.Sink.HiddenMirror {
			r.Verdict = Block
			r.Confidence = 0.95
			r.BlockReason = "Hidden form fields are mirroring your credentials to a second destination."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.CredentialSinkHiddenMirror))
			r.StageOutcome["D"] = "fail-mirror"
			return r
		}
		if in.Sink.PreSubmitCapture {
			r.Verdict = Block
			r.Confidence = 0.93
			r.BlockReason = "Page is capturing your input keystrokes and sending them before you press Submit."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.CredentialSinkPreSubmitCapture))
			r.StageOutcome["D"] = "fail-presubmit"
			return r
		}
		if in.Sink.MultiDestination {
			r.Verdict = Block
			r.Confidence = 0.88
			r.BlockReason = "Form would send your credentials to multiple endpoints simultaneously."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.CredentialSinkMultiDestination))
			r.StageOutcome["D"] = "fail-multi"
			return r
		}
		if in.Sink.UntrustedEndpoint {
			r.Verdict = Block
			r.Confidence = 0.9
			r.BlockReason = "Page would send credentials to " + joinUpTo(in.Sink.Destinations, 2) +
				", which is not an endpoint this brand uses."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.CredentialSinkUntrustedEndpoint))
			r.StageOutcome["D"] = "fail-untrusted"
			return r
		}
		if in.Sink.CrossOrigin {
			r.Verdict = Block
			r.Confidence = 0.85
			r.BlockReason = "Page would send credentials to " + joinUpTo(in.Sink.Destinations, 2) +
				", which is a different domain from the page itself."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.CredentialSinkCrossOrigin))
			r.StageOutcome["D"] = "fail-crossorigin"
			return r
		}
	}

	// --- Stage B+C: replica claim AND identity-binding failure ---
	// This is the universal phishing rule, now expressed cleanly: replica
	// high alone is not malicious; the verdict needs the identity-binding
	// failure to flip. Each Identity mismatch gets its own reason code.
	//
	// EXCEPTION: trusted-identity hosts. CLIP can misclassify pages from
	// real brands (e.g. buy.itunes.apple.com matched a different brand at
	// 0.86). When we already know the host is a major brand, a high CLIP
	// match to a different brand is more likely a model error than phishing.
	if in.Replica.IsHighMatch && !in.Identity.Bound && !in.TrustedIdentity {
		if in.Identity.Unknown {
			// Replica high + identity unknown → can't confirm phishing,
			// can't bless either. ISOLATE for sensitive, WARN otherwise.
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.VisualReplicaHigh))
			if in.PageClass.IsSensitive() {
				r.Verdict = Isolate
				r.Confidence = 0.6
				r.BlockReason = "Page looks like " + in.Replica.Brand +
					" but we couldn't verify the hosting. Opening in isolation."
				r.StageOutcome["B+C"] = "unknown-sensitive"
				return r
			}
			r.Verdict = Warn
			r.Confidence = 0.6
			r.BlockReason = "Page looks like " + in.Replica.Brand +
				" but on a domain we don't recognize."
			r.StageOutcome["B+C"] = "unknown"
			return r
		}
		// Identity is explicitly false. BLOCK with whichever mismatches fired.
		r.Verdict = Block
		r.Confidence = 0.9
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.VisualReplicaHigh))
		if in.Identity.MismatchDomain {
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.IdentityMismatchDomain))
		}
		if in.Identity.MismatchASN {
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.IdentityMismatchASN))
		}
		if in.Identity.MismatchCert {
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.IdentityMismatchCert))
		}
		if in.Identity.MismatchScriptOrigin {
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.IdentityMismatchScriptOrigin))
		}
		r.BlockReason = "Page visually replicates " + in.Replica.Brand +
			" but the hosting does not match " + in.Replica.Brand + "'s real infrastructure."
		r.StageOutcome["B+C"] = "fail"
		return r
	}

	// --- Stage B+C borderline: visual score 0.65-0.70 + brand-name-in-URL ---
	// CLIP scores often sit in 0.60-0.70 for brand clones that aren't pixel-
	// perfect. On its own a 0.65 match is too noisy to BLOCK, but combined
	// with "brand keyword appears in URL/title" it's a near-certain phishing
	// tell — the page is literally calling itself the brand AND looks like
	// it. Two independent channels (text + image) agreeing is hard to fake.
	if in.Replica.BrandNameInURL && in.Replica.Score >= 0.62 && in.Replica.Score < 0.85 &&
		!in.TrustedIdentity && !in.Identity.Bound {
		r.Verdict = Block
		r.Confidence = 0.80
		r.BlockReason = "URL and page content both impersonate " + in.Replica.Brand +
			" but the hosting doesn't match."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.VisualReplicaHigh))
		if in.Identity.MismatchDomain {
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.IdentityMismatchDomain))
		}
		r.StageOutcome["B+C"] = "borderline-with-url"
		return r
	}

	// --- Stage B+C weak: low-confidence replica needs corroboration ---
	// CLIP scores on novel phishing often cluster at 0.70-0.85: similar enough
	// to a brand to be suspicious, not similar enough to be confident on its
	// own. We promote to WARN when corroborated by ANY of:
	//   - sensitive page class (login/payment/oauth)
	//   - untrusted-identity host (not in trustreg)
	//   - identity binding explicitly false
	// Trusted-identity hosts are protected: a weak visual match against the
	// real PayPal page from inside paypal.com must never WARN.
	if in.Replica.IsWeakMatch && !in.TrustedIdentity && !in.Identity.Bound {
		// Untrusted host + any weak visual match to a known brand → suspicious.
		// Promote to WARN. Sensitive class bumps to ISOLATE for fail-safety.
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.VisualReplicaHigh))
		if in.PageClass.IsSensitive() {
			r.Verdict = Isolate
			r.Confidence = 0.55
			r.BlockReason = "Page resembles " + in.Replica.Brand +
				" on a domain we don't recognize. Opening in isolation."
			r.StageOutcome["B+C"] = "weak-sensitive"
			return r
		}
		r.Verdict = Warn
		r.Confidence = 0.55
		r.BlockReason = "Page resembles " + in.Replica.Brand +
			" but the hosting doesn't match. Proceed with caution."
		r.StageOutcome["B+C"] = "weak-untrusted"
		return r
	}

	// --- Stage E: anti-cloaking force-ISOLATE ---
	if in.Context.IsChallengePage && in.PageClass.IsSensitive() {
		r.Verdict = Isolate
		r.Confidence = 0.55
		r.BlockReason = "Bot-protection challenge prevented a full scan of a sensitive page."
		r.ReasonCodes = append(r.ReasonCodes,
			string(reasons.CloakingDivergence),
			string(reasons.SensitivePageVerificationUnavailable))
		r.StageOutcome["E"] = "isolate-challenge"
		return r
	}

	// --- Stage F.4: path-drift on a trusted domain ---
	if in.Context.PathDrift && in.PageClass.IsSensitive() {
		r.Verdict = Block
		r.Confidence = 0.85
		r.BlockReason = "Previously-trusted site is now hosting an unexpected sensitive page on a new path."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.PathDriftOnTrustedDomain))
		r.StageOutcome["F"] = "fail-drift"
		return r
	}

	// --- Verification unavailable on a sensitive page → fail-CLOSED ---
	// Dev spec §8: "unknown sensitive pages should not fail open when verdict
	// service is unavailable". Translate to ISOLATE.
	//
	// EXCEPTION: trusted-identity hosts (login.microsoftonline.com,
	// accounts.google.com, github.com, www.amazon.com, banks, etc.) — we
	// already know who they are. A sandbox timeout doesn't change that.
	// Falling through to Allow with a soft confidence avoids the dominant
	// FP class surfaced by fp-bench (ISOLATE on every legit login page).
	if in.PageClass.IsSensitive() && !in.VerificationAvailable && !in.TrustedIdentity {
		r.Verdict = Isolate
		r.Confidence = 0.5
		r.BlockReason = "Could not verify this sensitive page. Opening in isolation as a safety default."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.SensitivePageVerificationUnavailable))
		r.StageOutcome["G"] = "fail-closed-sensitive"
		return r
	}

	// --- Official install command match (positive trust) ---
	// Recognized: page is on a registered vendor host AND publishes a
	// command that exactly matches one of that vendor's canonical install
	// templates AND any URLs in the command target the vendor's canonical
	// hosts. Strong positive trust — confirms the page is legitimately
	// what it claims to be. Confidence high enough to pre-empt soft-signal
	// shellcmd warnings (a real install page legitimately uses curl|sh
	// or similar patterns that would otherwise trip soft-signal warnings).
	//
	// EXCEPTION: even an official match doesn't override a hard-fail
	// (e.g. canonical curl|sh adjacent to a rundll32 UNC block in the same
	// page). We downgrade hard-fail to WARN instead of clearing it.
	if in.Context.OfficialInstallMatch {
		if in.Context.ShellCmdHardFail {
			r.Verdict = Warn
			r.Confidence = 0.7
			r.BlockReason = "Page publishes the official " + in.Context.OfficialInstallBrand +
				" install command, but ALSO contains a separately suspicious command. Inspect before pasting."
			r.ReasonCodes = append(r.ReasonCodes,
				string(reasons.OfficialInstallMatch),
				string(reasons.SuspiciousInstallCommand))
			r.ReasonCodes = append(r.ReasonCodes, in.Context.ShellCmdReasonCodes...)
			r.StageOutcome["F"] = "official+suspicious"
			return r
		}
		r.Verdict = Allow
		r.Confidence = 0.9
		r.BlockReason = "" // explicit empty — analyst panel shows the OfficialInstallLabel below
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.OfficialInstallMatch))
		r.StageOutcome["F"] = "official-match"
		return r
	}

	// --- Malicious install command in <pre>/<code> ---
	// Catches the Straiker "Fake Claude Code" attack class: a docs-style
	// page whose displayed install command embeds rundll32 over UNC, mshta
	// + remote HTA, PowerShell IEX cradle, etc. The page itself is the
	// weapon — user copy-pastes the command and gets compromised.
	//
	// Trusted-identity hosts (real anthropic.com / cline.bot etc.) are
	// excluded — they legitimately publish install commands.
	if in.Context.ShellCmdHardFail && !in.TrustedIdentity {
		r.Verdict = Block
		r.Confidence = 0.93
		r.BlockReason = "This page hides a malicious install command. Do NOT copy or paste anything from it into your terminal."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.MaliciousInstallCommand))
		r.ReasonCodes = append(r.ReasonCodes, in.Context.ShellCmdReasonCodes...)
		r.StageOutcome["F"] = "fail-shellcmd-hard"
		return r
	}
	if in.Context.ShellCmdSoftSignals >= 2 && !in.TrustedIdentity {
		r.Verdict = Warn
		r.Confidence = 0.75
		r.BlockReason = "This page shows a suspicious install command. Verify it against the official vendor documentation before pasting."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.SuspiciousInstallCommand))
		r.ReasonCodes = append(r.ReasonCodes, in.Context.ShellCmdReasonCodes...)
		r.StageOutcome["F"] = "warn-shellcmd-soft"
		return r
	}

	// --- Raw-IP malware drop ---
	// Near-certain Mirai/Gafgyt-style botnet binary distribution: raw IP
	// host + architecture-named path. Skipped for trusted-identity hosts
	// (n/a — trusted hosts always have domains), but checked before YARA
	// so it BLOCKs even when the sandbox can't render the binary.
	if in.Context.RawIPBinaryDrop {
		r.Verdict = Block
		r.Confidence = 0.92
		r.BlockReason = "URL points at a raw IP address with a binary path — commodity botnet malware drop pattern."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.MalwareRawIPBinaryDrop))
		r.StageOutcome["F"] = "fail-raw-ip-drop"
		return r
	}
	// Raw-IP host alone (any path): browsers don't legitimately fetch from
	// bare IPs in normal usage. Dev/test/RFC1918 traffic is on the local
	// network and doesn't reach the verdict service. Public raw-IP URLs
	// in the wild are almost exclusively malware C2, botnet drops, or
	// phishing kits hosted on compromised boxes.
	if in.Context.RawIPHost {
		r.Verdict = Block
		r.Confidence = 0.75
		r.BlockReason = "URL points at a raw IP address — legitimate websites use domain names."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.RawIPHost))
		r.StageOutcome["F"] = "fail-raw-ip"
		return r
	}

	// --- YARA-rule-driven failures (supporting evidence with own reason codes) ---
	if len(in.Context.YaraReasonCodes) > 0 {
		// Promote to WARN at minimum; BLOCK when a critical-severity rule
		// fires (caller already filtered to critical when populating).
		r.Verdict = Warn
		r.Confidence = 0.7
		r.BlockReason = "Page content matches known-malicious patterns."
		r.ReasonCodes = append(r.ReasonCodes, in.Context.YaraReasonCodes...)
		r.StageOutcome["F"] = "yara"
		// Do not return; let later rules upgrade to BLOCK if they fire.
	}

	// --- Behavioral abuse (popup storm / clipboard hijack) → WARN ---
	if in.Context.BehaviorPopupStorm {
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.PopupStormDetected))
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.65
		}
	}
	if in.Context.BehaviorClipboardHijack {
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.ClipboardHijackAttempt))
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.7
		}
	}

	// --- Generic ALLOW path ---
	if r.Verdict == Allow {
		r.Confidence = 0.5
		r.StageOutcome["G"] = "allow"
	}

	// --- Paranoid (Executive Mode) elevation, applied last ---
	// Promotes unknown / B-grade verdicts to ISOLATE for sensitive classes.
	// Sensitive-class TTL caps live elsewhere; here we just tighten the
	// verdict mapping when the user explicitly opted in.
	if in.Paranoid && r.Verdict == Allow && in.PageClass.IsSensitive() &&
		!in.Identity.Bound {
		r.Verdict = Isolate
		r.Confidence = 0.6
		r.BlockReason = "Executive Mode: opening unverified sensitive page in isolation."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.BlockedByStrictnessPolicy))
		r.StageOutcome["G"] = "paranoid-isolate"
	}

	return r
}

// joinUpTo joins up to n entries with ", ", appending "+%d more" if needed.
func joinUpTo(xs []string, n int) string {
	if len(xs) == 0 {
		return "(none)"
	}
	if len(xs) <= n {
		return joinStrings(xs, ", ")
	}
	return joinStrings(xs[:n], ", ") + ", +" + itoa(len(xs)-n) + " more"
}

func joinStrings(xs []string, sep string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	out := xs[0]
	for _, s := range xs[1:] {
		out += sep + s
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
