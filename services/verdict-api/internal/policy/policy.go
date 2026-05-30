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
	"net"
	"strings"

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
	// FeedCategories — content-category labels from feed_entries.category
	// for the rows that matched (adult/gambling/piracy/crack_keygen/
	// malvertising). The policy compares against the user's per-category
	// mode flags before treating the hit as auto-BLOCK.
	FeedCategories      []string
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
	// SuspiciousHostnameSignals — true when Tier-1 hostname-shape detectors
	// fired (DGA classifier OR random-host heuristic). On its own this is
	// advisory WARN; combined with fresh cert / no domain age / untrusted
	// identity it promotes higher.
	SuspiciousHostnameSignals bool
	// SuspiciousHostnameDetail — short reason string surfaced in the block
	// page (e.g. "DGA classifier + random-host heuristic both fired").
	SuspiciousHostnameDetail  string
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

	// DomainAgeDays — registered-age of the domain in whole days, from RDAP.
	// 0 means "unknown" (RDAP lookup failed, no registration date, or fresh
	// boot before RDAP cache populated). Use DomainAgeKnown to distinguish
	// "we asked and got 0" from "we never asked".
	//
	// Thresholds used by the policy:
	//   <7 days   + sensitive page  → ISOLATE  (fresh + login/payment risk)
	//   <30 days  + medium feed hit → promote WARN → BLOCK
	//   <30 days  + suspicious host → promote WARN → ISOLATE
	//   <90 days  + weak replica    → promote replica confidence
	//   ≥730 days + suspicious host → demote ISOLATE → WARN (old domain
	//                                  with weird name is far less suspect)
	DomainAgeDays  int
	DomainAgeKnown bool

	// Phase 6: deep DOM signals from sandbox-render's DOM inventory.
	// Counted/derived in policymap.go from render.Links, render.HiddenElements, etc.

	// RiskyDownloadCount — count of links with IsRiskyDownload=true.
	RiskyDownloadCount int
	// HiddenSuspiciousCount — count of hidden_elements where Tag is
	// "a", "iframe", or "form" AND HrefOrSrc is non-empty.
	HiddenSuspiciousCount int
	// ObfuscatedJSIndicators — distinct indicator strings from suspicious_js,
	// excluding "external" (high-volume noise not indicative alone).
	ObfuscatedJSIndicators []string
	// HasCrossOriginIframe — any iframe where !SameOrigin && !Visible.
	// Kept as a structural flag for legacy paths; the Wave-3-tuned rule
	// reads HiddenCrossOriginIframeCount below to require corroboration
	// before firing (single analytics iframe doesn't fire alone).
	HasCrossOriginIframe bool
	// HiddenCrossOriginIframeCount — Wave 3 tuning. Number of iframes
	// matching !SameOrigin && !Visible. Major content sites (BBC, NYT,
	// Wikipedia) embed 1-2 hidden cross-origin iframes for analytics
	// (Google Analytics, Tag Manager, Adobe DTM). Real phishing kits
	// embedding hidden cross-origin iframes for credential mirrors
	// typically have 3+. Rule fires at >= 3 to bias toward the malicious
	// pattern without false-positiving on every analytics-using page.
	HiddenCrossOriginIframeCount int
	// HasClickjackOverlay — any overlay where CoveragePct>=25 && Transparent
	// && InterceptsClicks.
	HasClickjackOverlay bool

	// VendorDNSBlocked — true when at least 2 independent protective-DNS
	// providers (Cloudflare Family/Security, Quad9, AdGuard Default/Family,
	// OpenDNS, CleanBrowsing) returned a sinkhole/NXDOMAIN for the domain.
	// Treated as Tier-0 hard BLOCK — these providers maintain massive,
	// continuously-updated threat lists (malware, phishing, scams, ad/
	// malvertising networks). Two-of-eight agreement is near-zero false-
	// positive rate.
	VendorDNSBlocked bool
	// VendorDNSSingleHit — true when exactly one provider blocks.
	// Advisory: surfaces the signal but doesn't auto-BLOCK alone (single-
	// vendor false positives do happen, especially with strict family DNS
	// filters that overreach on borderline content). Other rules can use
	// this to upgrade a borderline verdict.
	VendorDNSSingleHit bool
	// VendorDNSBlockedBy — names of the providers that returned a block.
	// Surfaced to the block page so the user sees "Cloudflare + Quad9
	// both block this domain" rather than an opaque "DNS says no".
	VendorDNSBlockedBy []string

	// BrowserRemoteIP — Phase B: the IP the browser actually connected to,
	// reported by the extension. Empty when the extension didn't supply it
	// (older extension, request from portal/scheduler, webRequest unavailable).
	BrowserRemoteIP string
	// BrowserRemoteIPIsPrivate — true when BrowserRemoteIP is in RFC1918,
	// loopback, link-local, IPv6 ULA, or CGNAT space. Used together with
	// "domain is public" to fire PUBLIC_DOMAIN_PRIVATE_IP.
	BrowserRemoteIPIsPrivate bool

	// SupportScamScore — Wave 3 / Phase 1. Score in [0, 1.5] from
	// internal/supportscam. URL+SLD+title-based today; visible-DOM
	// text plugs in at Phase 2; OCR at Phase 3. Crossing the
	// thresholds in supportscam.go drives a policy rule that adds
	// SUPPORT_SCAM_LANGUAGE + the per-category reason codes to the
	// verdict. See supportscam.ThresholdWarn / ThresholdBlock /
	// ThresholdHardBlock for the meaning of each band.
	SupportScamScore        float64
	SupportScamCategories   []string // category names that fired (best-effort, for trace)

	// PaymentScamScore — Wave 3 / Phase 2. Score in [0, 1.5] from
	// internal/paymentscam. Sources: URL + SLD + title + visible-DOM
	// text. Hosts in brandgraph get a zero score inside the scorer.
	// Drives Stage PS in policy.Apply: PAYMENT_SCAM_LANGUAGE +
	// per-category reason codes when ThresholdWarn/Block/HardBlock
	// crossed.
	PaymentScamScore        float64
	PaymentScamCategories   []string

	// CryptoDrainerScore — Wave 3 / Phase 2. Score in [0, 1.5] from
	// internal/cryptodrainer. Sources: URL + SLD + title + visible-DOM
	// text + ScriptIndicators. Hosts in brandgraph get zero-score
	// inside the scorer.
	CryptoDrainerScore       float64
	CryptoDrainerCategories  []string

	// HomoglyphBrandMatch — true when Tier-1's homoglyphScore fired with
	// a strong match against a brand keyword (weight >= 0.85: exact match
	// after confusable normalization, e.g. g00gle → google, paypal-style
	// digit/Cyrillic substitution). Drives a near-hard rule in policy.Apply:
	// untrusted homoglyph hosts ISOLATE on sensitive pages and WARN on
	// generic pages. This signal MUST NOT be suppressed by trust score —
	// domain-age trust on g00gle.com is exactly the failure mode the doc
	// warns about ("popularity/age is not safety").
	HomoglyphBrandMatch bool
	// HomoglyphBrandName — short brand label for the matched keyword
	// (e.g. "google"). Surfaced to the block page so the user sees
	// "this domain impersonates Google."
	HomoglyphBrandName  string

	// Tier2Requested — true when the pipeline decided this URL needed a
	// sandbox render (Tier-2) for evidence. Goes hand-in-hand with
	// Tier2Available below: if Tier2Requested && !Tier2Available, the
	// engine WANTED page-content evidence but didn't get it (sandbox
	// down, sandbox timeout, render-cache miss + service unhealthy).
	//
	// This pair drives the health-gated degraded-mode behavior in
	// policy.Apply: sensitive pages on which Tier-2 was needed but
	// missing must NOT silently ALLOW — they ISOLATE with a
	// TIER2_DATA_UNAVAILABLE reason code. Closes the "uflix.to-class"
	// silent-fake-safety bug.
	Tier2Requested bool
	Tier2Available bool

	// ResolverDivergence — Phase E soft signal. True when the browser's
	// connection IP for this domain is publicly routable but is NOT in
	// the answer set our protective resolver saw at lookup time. Multi-
	// CDN/anycast sites flip this constantly, so it is advisory only and
	// always suppressed on highly-trusted hosts.
	//
	// The HARD divergence (browser hit a private IP for a public domain)
	// is PUBLIC_DOMAIN_PRIVATE_IP and is handled at Stage CI — it ignores
	// trust score and short-circuits BLOCK. This soft variant ignores
	// neither.
	ResolverDivergence       bool
	// ResolverDivergenceDetail — short human string for the report-page
	// drill-down ("browser hit 203.0.113.5, resolver saw 198.51.100.4").
	ResolverDivergenceDetail string
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

	// Mode — the user's protection mode from the extension Options page.
	// "normal" | "safe" | "family" | "strict" | "paranoid" | "ultra".
	//
	// ULTRA mode (Phase 5): inverts the default verdict. Where the other
	// modes ask "is there evidence of badness?", ultra asks "is there
	// proof of cleanliness?" — any URL not affirmatively cleared opens
	// in ISOLATE. Implemented at the end of Apply as Stage U.
	Mode string

	// CategoryBlocks — per-category enable flags from the extension's
	// mode/categories selector. When a feed hit's category is true here,
	// it's an auto-BLOCK; when false, the page is allowed even if it
	// matched a category feed.
	//
	// Keys: "adult" | "gambling" | "piracy" | "crack_keygen" |
	//       "malvertising" | "popunder"
	CategoryBlocks map[string]bool

	// VerificationAvailable: false when sandbox/visual-match were down,
	// which makes Stages B/C/D unknowable rather than absent.
	VerificationAvailable bool

	// TrustedIdentity — true when the host is in the curated Trusted Identity
	// Registry (top brands: google, microsoft, amazon, apple, paypal, banks
	// etc.). Suppresses fail-closed ISOLATE for sensitive pages and downgrades
	// noisy credential-sink rules that frequently false-positive on legit
	// login flows (GitHub login posts to analytics + captcha + auth, which
	// our hidden-mirror detector treats as suspicious).
	//
	// Phase C.3 transition: this is the legacy aggregate. New code should
	// consult the scope-specific fields below (TrustedForLogin etc.).
	// TrustedIdentity is kept as an alias for TrustedAnyScope so existing
	// soft-rule call sites continue to behave identically — Phase D
	// rewrites those rules to ask the right scope and this field goes away.
	TrustedIdentity bool

	// Phase C.3 — scope-aware trust. Populated by policymap.go from
	// brandgraph.Trust(host, scope). A host can be trusted for one scope
	// without being trusted for others — gstatic.com is trusted as a
	// script source but NOT as a login destination, so a credential form
	// rendered on a gstatic.com URL should NOT suppress credential-sink
	// rules. Today every soft rule still consults TrustedIdentity; Phase D
	// migrates them to the right scope below.

	// TrustedForLogin — host is a curated login destination
	// (accounts.google.com, login.live.com, github.com, appleid.apple.com).
	// Suppresses CREDENTIAL_SINK_HIDDEN_MIRROR and friends.
	TrustedForLogin bool
	// TrustedForPayment — host is a curated payment destination
	// (checkout.stripe.com, www.paypal.com, checkout.paypal.com).
	// Suppresses payment-sink-cross-origin warnings.
	TrustedForPayment bool
	// TrustedForOAuth — host is a curated OAuth redirect endpoint. Allows
	// unusual scope grants without unknown-clientID escalation.
	TrustedForOAuth bool
	// TrustedForScript — host is a curated script/CDN source (gstatic.com,
	// googleusercontent.com, googletagmanager.com). Suppresses
	// SCRIPT_ORIGIN_DRIFT but does NOT suppress credential or payment sinks.
	TrustedForScript bool
	// TrustedForCDN — host is a curated static-asset CDN. Suppresses
	// shared-hosting penalties for the static path without granting any
	// action-bearing trust.
	TrustedForCDN bool
	// TrustedForDocs — host is a curated documentation source. Allows
	// install-command publication without REQUIRE_APPROVAL escalation.
	TrustedForDocs bool
	// TrustedAnyScope — true if any of the scoped fields above is true OR
	// the host is in full-trust (a curated canonical brand domain). This
	// is the field TrustedIdentity is aliased from. Use this only when the
	// call site really doesn't care which scope — most checks should pick
	// a specific scope above.
	TrustedAnyScope bool

	// Phase D — positive trust score in [0.0, 1.0]. Aggregates domain age,
	// feed/vendor-DNS cleanliness, brand/org membership, HTTPS validity.
	// Populated by policymap.go from existing context + brandgraph signals.
	//
	// IMPORTANT: this score is for soft-rule suppression only. Hard rules
	// (vendor DNS consensus, feed-high hit, raw-IP binary drop, public-
	// domain-private-IP, YARA critical) must ignore it. A compromised
	// trusted brand still BLOCKs on hard evidence.
	//
	// Phase E rewrites the noisy soft rules to consult this. Today no
	// rule reads it — D.2 ships the wiring only.
	TrustScore        float64
	TrustContributors []TrustContributor
}

// Phase E — soft-rule weights.
//
// Each named soft rule contributes a per-fire risk delta plus its reason
// code. The accumulator promotes a verdict at end of the soft-rules block:
//
//   risk >= softWarnThreshold  → at-least WARN (if no prior verdict)
//   risk >= softBlockThreshold → at-least BLOCK on sensitive page classes
//
// Single-signal weights = softWarnThreshold (1.0) so any one fired soft
// rule preserves the pre-refactor WARN behavior — this keeps existing
// regression tests valid. Two corroborating soft signals push toward
// 2.0 and earn slightly higher confidence at mapping time.
//
// Hard rules (vendor-DNS consensus, feed-high, raw-IP-binary-drop,
// PUBLIC_DOMAIN_PRIVATE_IP, YARA critical, pre-submit credential capture,
// hidden mirror sink) MUST NOT route through this accumulator — they
// short-circuit BLOCK regardless of trust.
const (
	softWeightRandomHostname      = 1.0
	softWeightObfuscatedJS        = 1.0
	softWeightHiddenIframeXOrigin = 1.0
	softWeightSuspiciousDownload  = 1.0
	softWeightHiddenAnchors       = 1.0
	softWeightDNSDivergenceSoft   = 0.5 // single-side multi-CDN drift is half-weight on its own
	softWarnThreshold             = 1.0
)

// softAccum is the per-Apply soft-rule accumulator. fire() records both
// the risk delta and the reason code; the final mapping (toward end of
// Apply) reads risk to decide whether to promote ALLOW → WARN.
//
// Reason codes are appended eagerly to r.ReasonCodes (not buffered) so
// that report-page UI continues to surface every fired signal even when
// the threshold is not met — matching the legacy behavior.
type softAccum struct {
	risk float64
}

// fire records weight + reason code for a soft rule. Caller must already
// have checked IsHighlyTrusted (rules are responsible for their own
// gating so they can emit telemetry without the suppression branch).
func (s *softAccum) fire(r *Result, weight float64, code reasons.Code) {
	s.risk += weight
	r.ReasonCodes = append(r.ReasonCodes, string(code))
	r.trace("F.4", string(code), "fired", "soft signal", weight)
}

// suppressed records that a soft rule WOULD have fired but trust
// suppressed it. Visible in the decision trace so an operator can see
// exactly which rules trust score muted on this URL.
func (s *softAccum) suppressed(r *Result, code reasons.Code, why string) {
	r.trace("F.4", string(code), "suppressed", why, 0)
}

// trace appends one decision step. Cheap; called dozens of times per
// /v1/check by design — the trace is the user-visible debug payload.
func (r *Result) trace(stage, code, outcome, detail string, weight float64) {
	r.DecisionTrace = append(r.DecisionTrace, DecisionStep{
		Stage:   stage,
		Code:    code,
		Outcome: outcome,
		Detail:  detail,
		Weight:  weight,
	})
}

// HighTrustScoreThreshold is the trust-score floor at which soft rules
// stop firing on a non-trustreg domain. Tuned conservatively at 0.7 —
// requires multiple positive signals (e.g. 3+ year-old domain + clean
// feeds + clean vendor DNS) rather than a single one. Phase E.
//
// Hard rules ignore this threshold. A compromised trusted brand still
// BLOCKs on vendor-DNS consensus, feed-high hit, raw-IP-binary-drop,
// PUBLIC_DOMAIN_PRIVATE_IP, or YARA critical regardless of trust.
const HighTrustScoreThreshold = 0.70

// IsHighlyTrusted reports whether soft rules should be suppressed on this
// host. Returns true when either:
//
//   - the host is in brandgraph under any scope (curated trust), OR
//   - the aggregated trust score crosses HighTrustScoreThreshold.
//
// Used by HIDDEN_MALICIOUS_LINK, HIDDEN_IFRAME_CROSS_ORIGIN,
// OBFUSCATED_JS_DETECTED, RANDOM_HOSTNAME, SUSPICIOUS_DOWNLOAD_OFFERED.
// Hard rules MUST NOT call this — they fire independent of trust.
func (in Inputs) IsHighlyTrusted() bool {
	// TrustedIdentity is the documented legacy alias for TrustedAnyScope
	// (see Inputs.TrustedIdentity comment). Honor it here so callers that
	// have not yet migrated to scoped trust still get soft-rule suppression.
	if in.TrustedIdentity || in.TrustedAnyScope {
		return true
	}
	return in.TrustScore >= HighTrustScoreThreshold
}

// TrustContributor is one labeled weight that moved the trust score.
// Surfaced in the evidence UI so users can see *why* a score was high.
// Mirrors trustscore.Contributor — duplicated here to keep internal/policy
// independent of internal/trustscore at the type level.
type TrustContributor struct {
	Label  string
	Weight float64
}

// DecisionStep is one entry in the per-Apply decision trace. The trace is
// emitted on the /v1/check response, the structured `check` log line, and
// the livetail debug stream. Every meaningful "the engine considered X and
// decided Y" branch records a step here so an operator can read the trail
// end-to-end and verify the verdict is solid.
type DecisionStep struct {
	Stage   string  `json:"stage"`             // e.g. "CI", "0", "F.1", "F.4", "F4soft", "G"
	Code    string  `json:"code,omitempty"`    // reason code this step concerns, when applicable
	Outcome string  `json:"outcome"`           // "fired" | "suppressed" | "skip" | "pass" | "fail"
	Detail  string  `json:"detail,omitempty"`  // short human explanation
	Weight  float64 `json:"weight,omitempty"`  // soft-rule weight contribution (Phase E)
}

// Result is what gateway.go turns into the HTTP response.
type Result struct {
	Verdict     Verdict
	Confidence  float64
	ReasonCodes []string
	BlockReason string // human-readable summary for blocked.html

	// StageOutcome maps stage letter → "pass" | "fail" | "unknown" | "skip"
	// for analytics + the report-page drill-down. Coarse-grained; for full
	// per-rule decision evidence see DecisionTrace below.
	StageOutcome map[string]string

	// DecisionTrace — append-only log of every rule the engine evaluated:
	// hard-rule short-circuits, soft-rule fires, soft-rule suppressions on
	// trust score, the soft-mapping threshold result, and the final verdict
	// step. Order is the order in which rules were evaluated. Surfaced to
	// the user via the /v1/check response so the block-page can render
	// "here is exactly how we decided."
	DecisionTrace []DecisionStep

	// ClearanceChecks — per-gate pass/fail summary for Ultra mode (always
	// populated in Ultra; populated best-effort in other modes for the
	// block-page transparency grid). Keys are stable identifiers; values
	// are "pass" | "fail" | "warn" | "unknown".
	//
	// Gates: "feed", "vendor_dns", "domain_age", "hostname_shape",
	//        "visual", "identity", "behavior", "trust".
	ClearanceChecks map[string]string
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
	// Phase E — soft-rule scoring accumulator. Used by HIDDEN_MALICIOUS_LINK,
	// RANDOM_HOSTNAME (non-sensitive path), OBFUSCATED_JS_DETECTED,
	// HIDDEN_IFRAME_CROSS_ORIGIN, SUSPICIOUS_DOWNLOAD_OFFERED (non-sensitive
	// path), and DNS_DIVERGENCE_SOFT. Hard rules never touch this.
	var soft softAccum

	// --- Stage CI: connection identity (Phase B hard rule) ---
	//
	// If the browser actually connected to a private/loopback/CGNAT IP for
	// what we believe is a public domain, the user's DNS path is hijacked:
	// router compromise, hosts-file tampering, malicious LAN resolver, or
	// (less likely) DNS rebinding from an attacker page. Either way, no
	// signal downstream (vendor DNS, feeds, render, visual match, trust
	// score) is trustworthy on this connection — the bytes the browser
	// rendered did not come from the real origin.
	//
	// This MUST fire before Stage 0 / TrustedIdentity. A trusted-brand
	// domain pointed at 10.0.0.5 is a classic phish kit running on the
	// attacker's LAN box — being a trusted brand makes it MORE dangerous,
	// not less.
	if in.Context.BrowserRemoteIP != "" && in.Context.BrowserRemoteIPIsPrivate && isPublicDomain(in.Domain) {
		r.Verdict = Block
		r.Confidence = 0.97
		r.BlockReason = "This public domain resolved to a private IP (" + in.Context.BrowserRemoteIP + "). The DNS path appears to be hijacked."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.PublicDomainPrivateIP))
		r.StageOutcome["CI"] = "fail-public-domain-private-ip"
		r.trace("CI", string(reasons.PublicDomainPrivateIP), "fired",
			"public domain hit private IP "+in.Context.BrowserRemoteIP+" — DNS-path hijack", 0)
		r.trace("G", "", "fail", "verdict=BLOCK (hard rule, ignores trust)", 0)
		return r
	}
	r.trace("CI", "", "pass", "browser remote IP not private (or absent)", 0)

	// --- Stage 0: VendorDNS multi-provider consensus (highest-priority BLOCK) ---
	//
	// Eight independent protective-DNS providers (Cloudflare Family/Security,
	// Quad9, AdGuard Default/Family, OpenDNS, CleanBrowsing) all maintain
	// massive, continuously-updated threat lists. When ≥2 of them sinkhole
	// the same domain, the agreement is near-zero false-positive rate — it
	// means multiple independent security teams have confirmed the threat.
	//
	// Trusted-identity hosts are still checked first to handle the rare case
	// of a vendor false-positive on a real brand domain (e.g. a family-DNS
	// provider over-blocking a major brand's CDN). For non-trusted hosts,
	// consensus blocks short-circuit the entire pipeline.
	if in.Context.VendorDNSBlocked && !in.TrustedIdentity {
		r.Verdict = Block
		r.Confidence = 0.97
		blockedBy := joinUpTo(in.Context.VendorDNSBlockedBy, 4)
		r.BlockReason = "Domain is on the blocklist of multiple independent protective-DNS providers (" + blockedBy + ")."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.VendorDNSConsensusBlock))
		r.StageOutcome["0"] = "fail-vendordns-consensus"
		r.trace("0", string(reasons.VendorDNSConsensusBlock), "fired",
			"vendor-DNS consensus: "+blockedBy, 0)
		r.trace("G", "", "fail", "verdict=BLOCK (hard rule)", 0)
		return r
	}
	if in.Context.VendorDNSBlocked && in.TrustedIdentity {
		r.trace("0", string(reasons.VendorDNSConsensusBlock), "suppressed",
			"vendor DNS would block, but host is in trustreg — likely vendor over-block on a real brand", 0)
	} else {
		r.trace("0", "", "pass", "no vendor-DNS consensus block", 0)
	}

	// --- Stage IS: homoglyph / brand-impersonation hard rule ---
	//
	// Tier-1 emitted `homoglyph_match` with weight ≥0.85 — the SLD,
	// after confusable normalization, EQUALS a curated brand keyword
	// (g00gle → google, paypa1 → paypal, microsоft → microsoft via
	// Cyrillic 'о'). This is the strongest single-signal brand-
	// impersonation tell.
	//
	// HARD rule (ignores trust score):
	//   - sensitive page (login/payment/oauth/install) on an untrusted
	//     homoglyph host → BLOCK. The whole point of an impersonator
	//     is to capture credentials; ALLOWing it because the squat is
	//     5 years old is exactly the "age == safety" failure the
	//     architecture doc warns about.
	//   - generic page on a homoglyph host → WARN at minimum, so the
	//     user sees the impersonation flag before any click-through.
	//
	// Trustreg / brandgraph membership is the only escape: a host
	// that's actually in the curated brand registry (extremely rare —
	// would mean google.com itself somehow looks like a homoglyph of
	// google.com, which can't happen because the homoglyph check
	// already skips literal exact matches).
	//
	// Surfaced in the smoke corpus as the failing case
	// `homoglyph-google` (g00gle.com). Before this rule the signal was
	// emitted, lost because of a signal-name typo in codes.go, and
	// then suppressed by domain-age trust score even after the typo
	// fix. This rule closes the path end-to-end.
	if in.Context.HomoglyphBrandMatch && !in.TrustedIdentity {
		brand := in.Context.HomoglyphBrandName
		if brand == "" {
			brand = "a protected brand"
		}
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.HomoglyphOfProtectedBrand))
		if in.PageClass.IsSensitive() {
			r.Verdict = Block
			r.Confidence = 0.90
			r.BlockReason = "This domain impersonates " + brand +
				" (homoglyph substitution) on a sensitive page. Credentials entered here would go to the impersonator, not " + brand + "."
			r.StageOutcome["IS"] = "fail-homoglyph-on-sensitive"
			r.trace("IS", string(reasons.HomoglyphOfProtectedBrand), "fired",
				"homoglyph of "+brand+" on sensitive page → BLOCK (trust ignored)", 0.85)
			r.trace("G", "", "fail", "verdict=BLOCK (hard impersonation rule)", 0.90)
			return r
		}
		// Non-sensitive: still WARN so the user sees the impersonation
		// flag. Verdict can be promoted further by downstream rules.
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.75
		}
		r.BlockReason = "This domain impersonates " + brand +
			" (homoglyph substitution). Verify the spelling in the address bar before continuing."
		r.StageOutcome["IS"] = "warn-homoglyph"
		r.trace("IS", string(reasons.HomoglyphOfProtectedBrand), "fired",
			"homoglyph of "+brand+" → WARN (trust ignored)", 0.85)
	}

	// --- Stage SS: tech-support / fake-helpdesk scam scorer (Wave 3 Phase 1) ---
	//
	// Consumes ctx.SupportScamScore + SupportScamCategories produced by
	// internal/supportscam over URL + SLD + title (and later DOM text +
	// OCR). Three policy bands:
	//
	//   score >= 0.80 (HardBlock) → BLOCK regardless of page class.
	//     Composite scams (brand impersonation + remote-tool ask +
	//     gift-card demand) target everyone — there's no benign reading.
	//   score >= 0.50 (Block) → BLOCK on sensitive pages; WARN on
	//     generic. The host has multiple scam indicators but no smoking
	//     gun.
	//   score >= 0.30 (Warn) → WARN. Single-category signal that
	//     warrants surfacing to the user.
	//
	// Trust does NOT suppress this rule. Brand-impersonation already has
	// its own escape (host-in-brandgraph short-circuit inside the scorer)
	// so highly-trusted hosts that legitimately discuss support topics
	// don't fire. Adding trust-score suppression here would re-introduce
	// the "popularity is safety" failure the doc explicitly warns about.
	if in.Context.SupportScamScore >= 0.80 {
		r.Verdict = Block
		r.Confidence = 0.92
		r.BlockReason = "This page matches multiple tech-support-scam patterns " +
			"(brand impersonation, payment demand, remote-access tool, or " +
			"scareware language). Real support never demands gift cards or " +
			"asks you to install remote-control software."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.SupportScamLanguage))
		for _, c := range supportScamReasonCodesFor(in.Context.SupportScamCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["SS"] = "fail-hardblock"
		r.trace("SS", string(reasons.SupportScamLanguage), "fired",
			"composite tech-support-scam pattern → BLOCK", in.Context.SupportScamScore)
		r.trace("G", "", "fail", "verdict=BLOCK (composite support-scam, ignores trust)",
			0.92)
		return r
	}
	if in.Context.SupportScamScore >= 0.50 {
		if in.PageClass.IsSensitive() {
			r.Verdict = Block
			r.Confidence = 0.85
			r.BlockReason = "This page matches tech-support-scam patterns on a sensitive page class."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.SupportScamLanguage))
			for _, c := range supportScamReasonCodesFor(in.Context.SupportScamCategories) {
				r.ReasonCodes = append(r.ReasonCodes, string(c))
			}
			r.StageOutcome["SS"] = "fail-sensitive"
			r.trace("SS", string(reasons.SupportScamLanguage), "fired",
				"support-scam patterns on sensitive page → BLOCK", in.Context.SupportScamScore)
			r.trace("G", "", "fail", "verdict=BLOCK", 0.85)
			return r
		}
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.70
		}
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.SupportScamLanguage))
		for _, c := range supportScamReasonCodesFor(in.Context.SupportScamCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["SS"] = "warn-block-threshold"
		r.trace("SS", string(reasons.SupportScamLanguage), "fired",
			"support-scam patterns → WARN (generic page)", in.Context.SupportScamScore)
	} else if in.Context.SupportScamScore >= 0.30 {
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.60
		}
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.SupportScamLanguage))
		for _, c := range supportScamReasonCodesFor(in.Context.SupportScamCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["SS"] = "warn-threshold"
		r.trace("SS", string(reasons.SupportScamLanguage), "fired",
			"support-scam patterns → WARN", in.Context.SupportScamScore)
	}

	// --- Stage PS: payment-scam / money-fraud scorer (Wave 3 Phase 2) ---
	//
	// Consumes ctx.PaymentScamScore from internal/paymentscam. Same
	// three-band shape as Stage SS:
	//
	//   score >= 0.80 (HardBlock) → BLOCK regardless of page class
	//     (composite scams target everyone)
	//   score >= 0.50 (Block)     → BLOCK on sensitive; WARN on generic
	//   score >= 0.30 (Warn)      → WARN
	//
	// The scorer already short-circuits to zero on brandgraph-trusted
	// hosts so Wikipedia / news / IRS.gov discussing these topics
	// doesn't fire. Trust score does NOT additionally suppress here —
	// the brandgraph escape is the only safe valve.
	if in.Context.PaymentScamScore >= 0.80 {
		r.Verdict = Block
		r.Confidence = 0.92
		r.BlockReason = "This page matches multiple payment-scam patterns " +
			"(payment-method demand combined with refund / lottery / urgent " +
			"pretext language). No legitimate business or agency demands gift " +
			"cards or wire transfers."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.PaymentScamLanguage))
		for _, c := range paymentScamReasonCodesFor(in.Context.PaymentScamCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["PS"] = "fail-hardblock"
		r.trace("PS", string(reasons.PaymentScamLanguage), "fired",
			"composite payment-scam pattern → BLOCK", in.Context.PaymentScamScore)
		r.trace("G", "", "fail", "verdict=BLOCK (payment scam, ignores trust)", 0.92)
		return r
	}
	if in.Context.PaymentScamScore >= 0.50 {
		if in.PageClass.IsSensitive() {
			r.Verdict = Block
			r.Confidence = 0.85
			r.BlockReason = "This page matches payment-scam patterns on a sensitive page class."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.PaymentScamLanguage))
			for _, c := range paymentScamReasonCodesFor(in.Context.PaymentScamCategories) {
				r.ReasonCodes = append(r.ReasonCodes, string(c))
			}
			r.StageOutcome["PS"] = "fail-sensitive"
			r.trace("PS", string(reasons.PaymentScamLanguage), "fired",
				"payment-scam patterns on sensitive page → BLOCK", in.Context.PaymentScamScore)
			r.trace("G", "", "fail", "verdict=BLOCK", 0.85)
			return r
		}
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.70
		}
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.PaymentScamLanguage))
		for _, c := range paymentScamReasonCodesFor(in.Context.PaymentScamCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["PS"] = "warn-block-threshold"
		r.trace("PS", string(reasons.PaymentScamLanguage), "fired",
			"payment-scam patterns → WARN", in.Context.PaymentScamScore)
	} else if in.Context.PaymentScamScore >= 0.30 {
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.60
		}
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.PaymentScamLanguage))
		for _, c := range paymentScamReasonCodesFor(in.Context.PaymentScamCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["PS"] = "warn-threshold"
		r.trace("PS", string(reasons.PaymentScamLanguage), "fired",
			"payment-scam patterns → WARN", in.Context.PaymentScamScore)
	}

	// --- Stage CD: crypto-drainer / wallet-scam scorer (Wave 3 Phase 2) ---
	//
	// Consumes ctx.CryptoDrainerScore from internal/cryptodrainer.
	// Same three-band shape as Stages SS / PS. HardBlock floor is
	// LOWER here (0.70 vs 0.80) because a wallet-drainer signed
	// transaction is essentially irreversible — a false-positive ALLOW
	// can cost the user their entire wallet. The scorer's brandgraph
	// short-circuit keeps real DeFi dApps (uniswap.org, opensea.io,
	// metamask.io) at zero score.
	if in.Context.CryptoDrainerScore >= 0.70 {
		r.Verdict = Block
		r.Confidence = 0.94
		r.BlockReason = "This page matches multiple wallet-drainer patterns. " +
			"Signing a transaction here can empty your wallet in one click. " +
			"Real DeFi flows live on the project's own canonical domain."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.CryptoDrainerPattern))
		for _, c := range cryptoDrainerReasonCodesFor(in.Context.CryptoDrainerCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["CD"] = "fail-hardblock"
		r.trace("CD", string(reasons.CryptoDrainerPattern), "fired",
			"composite wallet-drainer pattern → BLOCK", in.Context.CryptoDrainerScore)
		r.trace("G", "", "fail", "verdict=BLOCK (drainer pattern, irreversible)", 0.94)
		return r
	}
	if in.Context.CryptoDrainerScore >= 0.45 {
		if in.PageClass.IsSensitive() {
			r.Verdict = Block
			r.Confidence = 0.88
			r.BlockReason = "This page matches wallet-drainer patterns on a sensitive page class."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.CryptoDrainerPattern))
			for _, c := range cryptoDrainerReasonCodesFor(in.Context.CryptoDrainerCategories) {
				r.ReasonCodes = append(r.ReasonCodes, string(c))
			}
			r.StageOutcome["CD"] = "fail-sensitive"
			r.trace("CD", string(reasons.CryptoDrainerPattern), "fired",
				"drainer patterns on sensitive page → BLOCK", in.Context.CryptoDrainerScore)
			r.trace("G", "", "fail", "verdict=BLOCK", 0.88)
			return r
		}
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.72
		}
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.CryptoDrainerPattern))
		for _, c := range cryptoDrainerReasonCodesFor(in.Context.CryptoDrainerCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["CD"] = "warn-block-threshold"
		r.trace("CD", string(reasons.CryptoDrainerPattern), "fired",
			"drainer patterns → WARN", in.Context.CryptoDrainerScore)
	} else if in.Context.CryptoDrainerScore >= 0.30 {
		if r.Verdict == Allow {
			r.Verdict = Warn
			r.Confidence = 0.62
		}
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.CryptoDrainerPattern))
		for _, c := range cryptoDrainerReasonCodesFor(in.Context.CryptoDrainerCategories) {
			r.ReasonCodes = append(r.ReasonCodes, string(c))
		}
		r.StageOutcome["CD"] = "warn-threshold"
		r.trace("CD", string(reasons.CryptoDrainerPattern), "fired",
			"drainer patterns → WARN", in.Context.CryptoDrainerScore)
	}

	// --- Stage F.0: category-feed BLOCK + content-vs-security split ---
	//
	// Categories come in two flavors:
	//
	//   SECURITY (always blocks):
	//     "malware" | "phishing" | "c2" | "" (default — pre-category-feed entries)
	//
	//   CONTENT (mode-gated):
	//     "adult" | "gambling" | "piracy" | "crack_keygen" | "malvertising"
	//
	// Content categories only block when the user has them ON in mode/
	// categories. Security categories always block (the standard feed-hit
	// path). This lets a user run "Normal" mode and visit adult content,
	// while still being protected from URLhaus malware on the same feed-
	// lookup table.
	if len(in.Context.FeedCategories) > 0 {
		hasContentOnly := true
		anyContentEnabled := false
		for _, cat := range in.Context.FeedCategories {
			if cat == "" || !isContentCategory(cat) {
				// Empty = security feed row (URLhaus, OpenPhish, etc.) — these
				// rows have no category label. Non-content labels are likewise
				// security-class. Either way the hit is NOT purely content;
				// don't strip the feed signal.
				hasContentOnly = false
				continue
			}
			if in.CategoryBlocks != nil && in.CategoryBlocks[cat] {
				anyContentEnabled = true
				r.Verdict = Block
				r.Confidence = 0.95
				r.BlockReason = "Blocked by your " + cat + "-category filter."
				r.ReasonCodes = append(r.ReasonCodes, "CATEGORY_BLOCK_"+strings.ToUpper(cat))
				r.StageOutcome["F"] = "category-block:" + cat
				return r
			}
		}
		// If every matched feed row was a CONTENT category and the user has
		// none enabled, treat as no-feed-hit so the F.1 high-confidence rule
		// doesn't fire on (e.g.) StevenBlack adult entries when the user
		// has opted to allow adult content.
		if hasContentOnly && !anyContentEnabled {
			in.Context.FeedHit = false
			in.Context.FeedHighSources = nil
			in.Context.FeedMediumSources = nil
			in.Context.FeedSources = nil
		}
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
		//
		// Fresh-domain promotion: a single noisy-feed hit on a domain
		// registered <30 days ago is qualitatively different from the same
		// hit on a 5-year-old domain. Real phishing campaigns burn through
		// fresh domains; established sites stay flagged for known reasons.
		// Promote WARN→BLOCK when both signals agree.
		if in.Context.DomainAgeKnown && in.Context.DomainAgeDays < 30 {
			r.Verdict = Block
			r.Confidence = 0.85
			r.BlockReason = "URL flagged by community feed (" +
				in.Context.FeedMediumSources[0] +
				") and the domain was registered in the last 30 days."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.ExternalFeedHit))
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.FreshDomain))
			r.StageOutcome["F"] = "fail-feed-single-medium+fresh-domain"
			return r
		}
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
	// EXCEPTIONS:
	//   - trusted-identity hosts (github.com/login, accounts.google.com etc.)
	//     routinely POST to multiple endpoints — analytics, captcha, auth —
	//     which trips our hidden-mirror and multi-destination detectors.
	//   - non-credential page classes (Download, DeveloperToolInstallLure)
	//     have download links + install commands that point to the brand's
	//     own CDN (signal.org/download → updates.signal.org/...). The
	//     cross-origin sink detector treats that as "credentials going
	//     elsewhere", producing false positives. Use IsCredentialPage()
	//     which only matches Login/Password/MFA/OAuth/Payment/Crypto/Invoice.
	if in.PageClass.IsCredentialPage() && !in.TrustedIdentity {
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
	// CORROBORATION GATE — when CLIP returns a high-confidence match but
	// the brand's keyword does NOT appear in the URL or page title, that's
	// suspicious of a degenerate-embedding misfire (page rendered as a
	// blank Cloudflare challenge, error page, etc.) — NOT a real replica
	// claim. We DOWNGRADE the verdict in that case rather than skipping
	// the rule entirely so unknown-brand-on-sensitive-page still ISOLATEs.
	//
	// Trusted-identity hosts skip the whole rule (handled separately below).
	if in.Replica.IsHighMatch && !in.Identity.Bound && !in.TrustedIdentity {
		if in.Identity.Unknown {
			// Replica high + identity unknown. WITH brand-name in URL/title →
			// real impersonation tell (ISOLATE/WARN). WITHOUT corroboration →
			// likely CLIP misfire on a degenerate render (porn.com→Trezor,
			// piratebayproxy→Snapchat, jevhcksi→Discord class). Skip the
			// replica-driven action entirely; downstream rules (suspicious
			// host, raw-IP, behavior) can still fire.
			if !in.Replica.BrandNameInURL {
				// Fall through silently. Tier-1 suspicious-host signals
				// upstream may still WARN/ISOLATE; if not, ALLOW is the
				// honest outcome.
				return r
			}
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
		// Identity is explicitly false. WITH brand-name corroboration in the
		// URL/title → BLOCK at high confidence (real impersonation: the
		// attacker visually copied the brand AND named the URL after it).
		//
		// WITHOUT corroboration → IGNORE. The visual match is almost
		// certainly a CLIP misfire on a degenerate render (porn.com→Trezor,
		// piratebayproxy→Snapchat, login.tailscale.com→Reddit class). Acting
		// on it ISOLATEd legitimate sites whose minimal login UIs happen to
		// embed close to some seeded brand. The brandgraph "identity not
		// bound" is also degenerate here: of course Tailscale's domain isn't
		// bound to Reddit — they're unrelated brands. Mismatch is the
		// *expected* state for any URL where the visual hit was wrong.
		//
		// Real phishing always names the brand in the URL or title — that's
		// the whole point of impersonation. The corroboration gate is what
		// distinguishes "this is engineered to fool the user" from "CLIP got
		// confused by a generic login layout". Downstream rules (feed hits,
		// fresh domain, suspicious host, raw-IP, behavior) can still BLOCK
		// or ISOLATE this URL for *their own* reasons; we just don't let
		// the uncorroborated visual match be one of those reasons.
		if in.Replica.BrandNameInURL {
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
			r.Verdict = Block
			r.Confidence = 0.9
			r.BlockReason = "Page visually replicates " + in.Replica.Brand +
				" AND the URL/title references " + in.Replica.Brand +
				", but the hosting does not match " + in.Replica.Brand + "'s real infrastructure."
			r.StageOutcome["B+C"] = "fail-corroborated"
			return r
		}
		// Uncorroborated → fall through silently. Downstream rules can
		// still fire on their own merits.
		r.StageOutcome["B+C"] = "uncorroborated-suppressed"
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
	// CLIP scores in 0.70-0.85 are inherently ambiguous: they fire on real
	// phishing AND on generic minimal-form login pages that happen to embed
	// close to some seeded brand (login.tailscale.com → Reddit at 0.848 is
	// the canonical false-positive). Without brand-name corroboration in
	// the URL or page title, treating a weak match as suspicious has too
	// many FPs to be useful — the visual model is too noisy at this band.
	//
	// Therefore: weak-match action requires BrandNameInURL=true. With it,
	// the page is engineered to look like the brand AND named after the
	// brand, on a host the brand doesn't own → confidently suspicious.
	// Without it, suppress and let downstream rules speak.
	//
	// Trusted-identity hosts are also protected: a weak match to the real
	// PayPal page from inside paypal.com must never WARN.
	if in.Replica.IsWeakMatch && !in.TrustedIdentity && !in.Identity.Bound &&
		in.Replica.BrandNameInURL {
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.VisualReplicaHigh))
		if in.PageClass.IsSensitive() {
			r.Verdict = Isolate
			r.Confidence = 0.6
			r.BlockReason = "Page resembles " + in.Replica.Brand +
				" and the URL/title references " + in.Replica.Brand +
				" but the hosting doesn't match. Opening in isolation."
			r.StageOutcome["B+C"] = "weak-sensitive-corroborated"
			return r
		}
		r.Verdict = Warn
		r.Confidence = 0.6
		r.BlockReason = "Page resembles " + in.Replica.Brand +
			" and the URL/title references " + in.Replica.Brand +
			" but the hosting doesn't match. Proceed with caution."
		r.StageOutcome["B+C"] = "weak-untrusted-corroborated"
		return r
	}
	if in.Replica.IsWeakMatch && !in.TrustedIdentity && !in.Replica.BrandNameInURL {
		// CLIP weak match without corroboration — suppress.
		r.StageOutcome["B+C"] = "weak-uncorroborated-suppressed"
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

	// --- Suspicious hostname (DGA / random-host) on untrusted infrastructure ---
	//
	// jevhcksi.org-class case: hostname looks random AND host is not trusted
	// AND cert is fresh. Each signal alone is weak; together they're a
	// strong "this is a short-lived attack host" pattern.
	//
	// Skipped for trusted-identity hosts (some real brands have weird
	// internal hostnames). Skipped when the page successfully renders to
	// a known visual brand match — visual override beats lexical guess.
	if in.Context.SuspiciousHostnameSignals && !in.IsHighlyTrusted() && in.Replica.Brand == "" {
		// Domain-age modifier: a 5-year-old domain with a weird-looking name
		// is far less suspicious than a 3-day-old one. The fp-bench class
		// "legitimate small-business site with terse SLD" was generating
		// false ISOLATEs; the age gate filters them out.
		isOldDomain := in.Context.DomainAgeKnown && in.Context.DomainAgeDays >= 730
		isFreshDomain := in.Context.DomainAgeKnown && in.Context.DomainAgeDays < 30

		// Promote stronger when the page is sensitive (login / payment /
		// install-command etc.) — that's where the attacker payoff is.
		if in.PageClass.IsSensitive() {
			if isOldDomain {
				// Old + sensitive + weird name → WARN (not ISOLATE).
				r.Verdict = Warn
				r.Confidence = 0.55
				r.BlockReason = "Hostname looks randomly generated, but the domain has been registered for years. Treating as advisory."
				r.ReasonCodes = append(r.ReasonCodes, string(reasons.RandomHostname))
				r.StageOutcome["F"] = "suspicious-host-sensitive-old"
				return r
			}
			if isFreshDomain {
				// Fresh + sensitive + weird name → BLOCK (high-confidence
				// "burner phishing host" pattern).
				r.Verdict = Block
				r.Confidence = 0.85
				r.BlockReason = "Sensitive page on a random-looking host registered in the last 30 days — high-risk burner-domain pattern."
				r.ReasonCodes = append(r.ReasonCodes, string(reasons.RandomHostname))
				r.ReasonCodes = append(r.ReasonCodes, string(reasons.FreshDomain))
				r.StageOutcome["F"] = "fail-suspicious-host-fresh-sensitive"
				return r
			}
			r.Verdict = Isolate
			r.Confidence = 0.7
			r.BlockReason = "Sensitive page on a random-looking host with no known reputation. Opening in isolation."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.RandomHostname))
			r.StageOutcome["F"] = "suspicious-host-sensitive"
			return r
		}
		// Non-sensitive page.
		if isOldDomain {
			// Old + weird name + non-sensitive → no action; downstream
			// rules can still surface other issues.
			r.StageOutcome["F"] = "suspicious-host-old-suppressed"
		} else {
			// Phase E: route the soft non-sensitive path through the
			// accumulator. BlockReason is preserved so the report-page UI
			// still surfaces the human detail; the actual ALLOW→WARN flip
			// is decided by the soft mapping after all signals are in.
			soft.fire(&r, softWeightRandomHostname, reasons.RandomHostname)
			r.BlockReason = "Hostname looks randomly generated. " + in.Context.SuspiciousHostnameDetail
			r.StageOutcome["F"] = "suspicious-host"
		}
		// Don't return — let deeper rules (visual, sink, etc.) escalate if needed.
	}

	// --- Fresh-domain + sensitive-page rule ---
	//
	// Independent of any other signal: a domain registered in the last 7 days
	// hosting a login/payment/oauth/admin page is a very high-risk pattern.
	// Legitimate brands almost never launch new domains for sensitive flows
	// without significant trust ceremony (cert chain, brand mention, ASN
	// affinity). Default to ISOLATE; let downstream identity-binding rules
	// upgrade to ALLOW when the host is trusted.
	if in.Context.DomainAgeKnown && in.Context.DomainAgeDays < 7 &&
		in.PageClass.IsSensitive() && !in.TrustedIdentity {
		r.Verdict = Isolate
		r.Confidence = 0.75
		r.BlockReason = "Sensitive page on a domain registered in the last 7 days. Opening in isolation as a precaution."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.FreshDomain))
		r.StageOutcome["F"] = "fresh-domain-sensitive"
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
	//
	// EXCEPTION: operator-configured trusted hosts. Self-hosted apps on
	// known IPs (e.g. internal egress proxies, dev VPSs) are flagged as
	// trusted via XGG_LOCAL_TRUSTED_HOSTS. Skip the raw-IP block for
	// those — the same env var already protects them from other
	// fail-closed rules via in.TrustedIdentity.
	if in.Context.RawIPHost && !in.TrustedIdentity {
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

	// --- Health-gated degraded mode (DT companion §23.1) ---
	//
	// Tier-2 was requested but the sandbox didn't return evidence. Treat
	// missing evidence as MISSING PROOF, not as PASS. On sensitive pages
	// the engine must NOT silently ALLOW: ISOLATE so the user makes the
	// call. On non-sensitive pages we still surface the gap in the trace
	// so the operator can see why downstream F.4 rules didn't fire.
	//
	// This is the structural fix for the silent-fake-safety bug class
	// uflix.to surfaced: the engine returned ALLOW because no F.4 rule
	// had data to fire on, even though page-content was supposed to be
	// the primary signal source.
	//
	// Hard rules (CI / Stage 0 / fresh-domain / raw-IP / vendor-DNS
	// consensus) already short-circuited above and DO NOT depend on
	// sandbox — those still work without Tier-2.
	if in.Context.Tier2Requested && !in.Context.Tier2Available {
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.Tier2DataUnavailable))
		if in.PageClass.IsSensitive() && !in.IsHighlyTrusted() {
			r.Verdict = Isolate
			r.Confidence = 0.6
			r.BlockReason = "Sensitive page (login/payment/OAuth/install) could not be deep-scanned. Opening in isolation as a safety default."
			r.StageOutcome["H"] = "isolate-tier2-missing-on-sensitive"
			r.trace("H", string(reasons.Tier2DataUnavailable), "fail",
				"sandbox unavailable on sensitive page → ISOLATE (missing proof, not clean)", 0)
		} else {
			r.StageOutcome["H"] = "tier2-missing-noted"
			r.trace("H", string(reasons.Tier2DataUnavailable), "suppressed",
				"sandbox unavailable; downstream F.4 rules will not fire on this URL", 0)
		}
	} else if in.Context.Tier2Requested {
		r.trace("H", "", "pass", "tier-2 sandbox evidence present", 0)
	}

	// --- Stage F.4: deep DOM evidence (Phase 6) ---
	//
	// Hidden malicious anchors, obfuscated JS, clickjack overlays, cross-
	// origin hidden iframes — extracted by sandbox-render's DOM inventory.
	// Second-order signals: each alone is suspicious but legitimate sites
	// occasionally have them. Only the highest-severity combinations block.

	if in.Context.HasClickjackOverlay && !in.TrustedIdentity {
		if in.PageClass.IsSensitive() {
			r.Verdict = Isolate
			r.Confidence = 0.8
			r.BlockReason = "Page has a full-viewport transparent overlay that captures clicks — classic clickjack pattern on a sensitive page."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.OverlayClickjack))
			r.StageOutcome["F4"] = "fail-clickjack"
			return r
		}
		r.Verdict = Warn
		r.Confidence = 0.7
		r.BlockReason = "Page has a full-viewport transparent overlay that captures clicks. Proceed with caution."
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.OverlayClickjack))
		r.StageOutcome["F4"] = "warn-clickjack"
		// Don't return — let downstream upgrade if needed.
	}

	// Obfuscated-JS rule: high-entropy alone matches every modern webpack /
	// Vite / esbuild bundle, so we exclude it from the count unless paired
	// with a HIGH-signal indicator. Real malware obfuscation pairs
	// high-entropy with eval/Function-constructor/atob-chains/document-write.
	{
		strong := 0 // count "smoking gun" indicators
		hasEntropy := false
		for _, ind := range in.Context.ObfuscatedJSIndicators {
			switch ind {
			case "eval", "function_constructor", "atob_chain",
				"document_write", "base64_blob":
				strong++
			case "high_entropy":
				hasEntropy = true
			}
		}
		// Trigger when:
		//   - 2+ strong indicators (clear obfuscation pattern), OR
		//   - 1 strong + high-entropy (entropy corroborates a strong signal)
		fire := strong >= 2 || (strong >= 1 && hasEntropy)
		switch {
		case fire && !in.IsHighlyTrusted():
			soft.fire(&r, softWeightObfuscatedJS, reasons.ObfuscatedJSDetected)
			r.StageOutcome["F4"] = "warn-obfuscated-js"
		case fire && in.IsHighlyTrusted():
			soft.suppressed(&r, reasons.ObfuscatedJSDetected,
				"obfuscated JS indicators present but host is highly trusted")
		}
	}

	// Wave 3 tuning — require >= 3 hidden cross-origin iframes before
	// firing. Major content sites (BBC, NYT, Wikipedia) embed 1-2 for
	// analytics (Google Analytics + Tag Manager); real credential-mirror
	// phishing kits typically embed 3+ (form mirror + tracker + beacon).
	// The threshold-of-3 is the natural gap between the two populations
	// in the smoke corpus measurement.
	const HiddenIframeFireThreshold = 3
	switch {
	case in.Context.HiddenCrossOriginIframeCount >= HiddenIframeFireThreshold && !in.IsHighlyTrusted():
		soft.fire(&r, softWeightHiddenIframeXOrigin, reasons.HiddenIframeCrossOrigin)
		r.StageOutcome["F4"] = "warn-hidden-iframe"
	case in.Context.HiddenCrossOriginIframeCount >= HiddenIframeFireThreshold && in.IsHighlyTrusted():
		soft.suppressed(&r, reasons.HiddenIframeCrossOrigin,
			"3+ hidden cross-origin iframes present but host is highly trusted")
	}

	if in.Context.RiskyDownloadCount > 0 && !in.IsHighlyTrusted() {
		sensitive := in.PageClass.IsSensitive()
		devPage := in.PageClass == pageclass.Download ||
			in.PageClass == pageclass.DeveloperToolInstallLure ||
			in.Context.OfficialInstallMatch
		switch {
		case sensitive && !devPage:
			// Login/payment/oauth page offering a download → very suspicious.
			r.Verdict = Block
			r.Confidence = 0.88
			r.BlockReason = "Sensitive page (login/payment/OAuth) offers an executable or installer download — high-risk pattern."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.SuspiciousDownloadOffered))
			r.StageOutcome["F4"] = "fail-download-on-sensitive"
			return r
		case !devPage:
			soft.fire(&r, softWeightSuspiciousDownload, reasons.SuspiciousDownloadOffered)
			r.StageOutcome["F4"] = "warn-download-non-dev"
		}
	} else if in.Context.RiskyDownloadCount > 0 && in.IsHighlyTrusted() {
		soft.suppressed(&r, reasons.SuspiciousDownloadOffered,
			"risky download links present but host is highly trusted")
		// devPage + OfficialInstallMatch already gates ALLOW elsewhere; no action.
	}

	// Hidden anchors count alone is advisory; per-link feed cross-reference
	// would be needed for a high-confidence block (deferred to a future pass).
	//
	// Wave 3 tuning — raised from 8 to 60. Measurement on the smoke
	// corpus showed major content sites pack 80-200 hidden anchors
	// (off-screen menus, accordion footers, lazy-loaded link sections):
	//
	//	BBC.com homepage           89
	//	Wikipedia article          176
	//	NYT homepage                0  (different page structure)
	//	signal.org/download       ~6  (the original tuning anchor)
	//
	// Real attacker link farms typically have 5-30 hidden anchors.
	// The 100 threshold sits comfortably above BBC's 89 (the failing
	// smoke-corpus class) and Mozilla's similar shape. Wikipedia's
	// 176 still fires, but Wikipedia articles aren't in the corpus
	// wrapper-benign targets. The original 8 was too aggressive once
	// sandbox-render became operational across major content sites
	// (Wave 1 onward).
	const HiddenAnchorsFireThreshold = 100
	switch {
	case in.Context.HiddenSuspiciousCount >= HiddenAnchorsFireThreshold && !in.IsHighlyTrusted():
		soft.fire(&r, softWeightHiddenAnchors, reasons.HiddenMaliciousLink)
		r.StageOutcome["F4"] = "warn-hidden-anchors"
	case in.Context.HiddenSuspiciousCount >= HiddenAnchorsFireThreshold && in.IsHighlyTrusted():
		soft.suppressed(&r, reasons.HiddenMaliciousLink,
			"many hidden cross-origin anchors but host is highly trusted")
	}

	// --- DNS_DIVERGENCE_SOFT (Phase E) ---
	//
	// Browser connected to a publicly-routable IP the resolver did not see
	// in the answer set. On its own this is a weak signal — multi-CDN and
	// split-horizon DNS create benign divergence — so it carries half-
	// weight and is suppressed on highly-trusted hosts. Paired with any
	// other soft signal it crosses the WARN threshold; alone it does not.
	//
	// The HARD divergence case (browser → private IP for public domain)
	// is PUBLIC_DOMAIN_PRIVATE_IP at Stage CI, which ignores trust and
	// short-circuits BLOCK far above this point.
	switch {
	case in.Context.ResolverDivergence && !in.IsHighlyTrusted():
		soft.fire(&r, softWeightDNSDivergenceSoft, reasons.DNSDivergenceSoft)
		r.StageOutcome["F4"] = "soft-dns-divergence"
	case in.Context.ResolverDivergence && in.IsHighlyTrusted():
		soft.suppressed(&r, reasons.DNSDivergenceSoft,
			"DNS divergence (multi-CDN drift) but host is highly trusted")
	}

	// --- Phase E soft-rule mapping ---
	//
	// Promote ALLOW → WARN once accumulated soft-rule risk crosses the
	// threshold. Hard rules above already short-circuited with their own
	// verdicts; we never demote here. Confidence scales mildly with the
	// number of corroborating signals so multi-signal pages report higher
	// confidence than single-signal ones, without ever crossing into the
	// confidence range reserved for hard evidence (>=0.75).
	if r.Verdict == Allow && soft.risk >= softWarnThreshold {
		r.Verdict = Warn
		r.Confidence = 0.55
		if soft.risk >= 2.0 {
			r.Confidence = 0.65
		}
		r.StageOutcome["F4soft"] = "warn-soft-accum"
		r.trace("F4soft", "", "fired",
			"accumulated soft risk crossed warn threshold", soft.risk)
	} else if soft.risk > 0 {
		// Some soft signals fired but didn't cross the threshold (e.g. a
		// half-weight DNS divergence alone). Record explicitly so the
		// operator can see the engine considered them.
		r.trace("F4soft", "", "pass",
			"soft signals fired but under warn threshold", soft.risk)
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

	// --- Trust-score summary in the trace ---
	// One row per call, regardless of verdict. Gives the operator a
	// single line they can scan to see "the engine considered this host
	// trust-X, that's why the soft rules were/were-not suppressed."
	switch {
	case in.TrustedAnyScope || in.TrustedIdentity:
		r.trace("trust", "", "pass",
			"host is in brandgraph/trustreg — soft rules suppressed", 0)
	case in.TrustScore >= HighTrustScoreThreshold:
		r.trace("trust", "", "pass",
			"trust score crossed soft-suppression threshold", in.TrustScore)
	default:
		r.trace("trust", "", "skip",
			"host not highly trusted; soft rules eligible to fire", in.TrustScore)
	}

	// --- Final verdict step — always last in the trace ---
	r.trace("G", "", string(r.Verdict),
		"final verdict", r.Confidence)

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

	// --- Stage U: ULTRA mode clearance gate ---
	//
	// Ultra inverts the default. Every gate must affirmatively PASS for an
	// ALLOW; the moment any gate is uncertain or fails, the URL opens in
	// ISOLATE. This is the "guilty until proven innocent" model intended
	// for executives, journalists, IR analysts, and personal high-security
	// browsing where one-shot phishing is unacceptable.
	//
	// The previous rules can BLOCK or ISOLATE on positive evidence; Stage U
	// upgrades ALLOWs to ISOLATE when the URL hasn't earned full clearance.
	// We always populate ClearanceChecks (for the block-page transparency
	// grid) but only flip the verdict when Mode == "ultra".
	r.ClearanceChecks = computeClearanceChecks(in)
	if strings.EqualFold(in.Mode, "ultra") && r.Verdict == Allow {
		if !hasFullClearance(r.ClearanceChecks, in) {
			r.Verdict = Isolate
			r.Confidence = 0.7
			r.BlockReason = "Ultra mode: this page hasn't earned full clearance. Opening in isolation."
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.UltraNotCleared))
			r.StageOutcome["U"] = "ultra-not-cleared"
		} else {
			r.ReasonCodes = append(r.ReasonCodes, string(reasons.UltraCleared))
			r.StageOutcome["U"] = "ultra-cleared"
		}
	}

	return r
}

// computeClearanceChecks — per-gate pass/warn/fail/unknown for the
// transparency grid the block page renders. Always called; even in
// non-Ultra modes the user gets to see what passed.
func computeClearanceChecks(in Inputs) map[string]string {
	checks := map[string]string{}

	// Threat-intel feeds
	switch {
	case len(in.Context.FeedHighSources) > 0:
		checks["feed"] = "fail"
	case len(in.Context.FeedMediumSources) >= 2:
		checks["feed"] = "fail"
	case len(in.Context.FeedMediumSources) == 1:
		checks["feed"] = "warn"
	default:
		checks["feed"] = "pass"
	}

	// Vendor-DNS consensus
	switch {
	case in.Context.VendorDNSBlocked:
		checks["vendor_dns"] = "fail"
	case in.Context.VendorDNSSingleHit:
		checks["vendor_dns"] = "warn"
	default:
		checks["vendor_dns"] = "pass"
	}

	// Domain age
	switch {
	case !in.Context.DomainAgeKnown:
		checks["domain_age"] = "unknown"
	case in.Context.DomainAgeDays < 30:
		checks["domain_age"] = "fail"
	case in.Context.DomainAgeDays < 180:
		checks["domain_age"] = "warn"
	default:
		checks["domain_age"] = "pass"
	}

	// Hostname shape
	switch {
	case in.Context.RawIPBinaryDrop:
		checks["hostname_shape"] = "fail"
	case in.Context.RawIPHost:
		checks["hostname_shape"] = "fail"
	case in.Context.SuspiciousHostnameSignals:
		checks["hostname_shape"] = "warn"
	default:
		checks["hostname_shape"] = "pass"
	}

	// Visual / replica
	switch {
	case in.Replica.IsHighMatch && !in.Identity.Bound && in.Replica.BrandNameInURL:
		checks["visual"] = "fail"
	case in.Replica.IsHighMatch && in.Identity.Bound:
		checks["visual"] = "pass" // matches the brand AND hosted by it
	case in.Replica.IsWeakMatch && !in.Identity.Bound:
		checks["visual"] = "warn"
	default:
		checks["visual"] = "pass"
	}

	// Identity binding
	switch {
	case in.Identity.MismatchDomain || in.Identity.MismatchASN ||
		in.Identity.MismatchCert || in.Identity.MismatchScriptOrigin:
		checks["identity"] = "fail"
	case in.Identity.Bound:
		checks["identity"] = "pass"
	case in.Identity.Unknown:
		checks["identity"] = "unknown"
	default:
		checks["identity"] = "pass"
	}

	// Page behavior
	switch {
	case in.Context.BehaviorScareware:
		checks["behavior"] = "fail"
	case in.Context.BehaviorPopupStorm || in.Context.BehaviorClipboardHijack:
		checks["behavior"] = "warn"
	default:
		checks["behavior"] = "pass"
	}

	// Positive trust signal
	switch {
	case in.TrustedIdentity:
		checks["trust"] = "pass"
	case in.Context.OfficialInstallMatch:
		checks["trust"] = "pass"
	default:
		checks["trust"] = "unknown"
	}

	return checks
}

// hasFullClearance — Ultra-mode pass requires:
//   - feed gate must be "pass" (no medium-single advisory either)
//   - vendor_dns must be "pass"
//   - domain_age must be "pass" OR the host is in trustreg (trust=pass)
//   - hostname_shape must be "pass"
//   - visual must be "pass"
//   - identity must be "pass" OR trust=pass
//   - behavior must be "pass" OR no sandbox data (unknown is fine —
//     ultra forces sandbox elsewhere, but if sandbox failed we don't
//     fault the user for that)
//   - trust check is informational; it gates relaxations above but
//     doesn't independently require pass
//
// Any other state → not cleared → ISOLATE.
func hasFullClearance(c map[string]string, in Inputs) bool {
	trustPass := c["trust"] == "pass"
	if c["feed"] != "pass" {
		return false
	}
	if c["vendor_dns"] != "pass" {
		return false
	}
	if c["domain_age"] != "pass" && !trustPass {
		return false
	}
	if c["hostname_shape"] != "pass" {
		return false
	}
	if c["visual"] != "pass" {
		return false
	}
	if c["identity"] != "pass" && !trustPass {
		return false
	}
	if c["behavior"] == "fail" {
		return false
	}
	return true
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

// isContentCategory — true for category labels that are content filters
// (mode-gated), false for security categories (always block).
func isContentCategory(c string) bool {
	switch strings.ToLower(c) {
	case "adult", "gambling", "piracy", "crack_keygen", "malvertising", "popunder":
		return true
	}
	return false
}

// isPublicDomain reports whether a host looks like a public registrable
// domain (something that genuinely has DNS authority on the public internet),
// as opposed to a raw IP literal or a local-only / test-only namespace.
//
// Used by the PUBLIC_DOMAIN_PRIVATE_IP hard rule: that rule only makes
// sense when the user thinks they reached a public site. Hitting
// http://router.local from 192.168.1.1 is not a hijack — both sides are
// LAN. Hitting https://bank.example from 10.0.0.5 is a hijack.
//
// Rules:
//   - empty / unparseable → false (we can't decide; don't fire the hard rule)
//   - IP literal → false (raw-IP URLs are handled by RAW_IP_HOST, not here)
//   - no dot → false (single-label hostnames are LAN names)
//   - reserved/local TLDs (.local, .localhost, .internal, .test, .example,
//     .invalid, .home, .lan, .corp) → false
//   - everything else → true
func isPublicDomain(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return false
	}
	if !strings.Contains(h, ".") {
		return false
	}
	// Trim trailing dot from FQDN form.
	h = strings.TrimSuffix(h, ".")
	for _, tld := range localTLDs {
		if strings.HasSuffix(h, "."+tld) || h == tld {
			return false
		}
	}
	return true
}

var localTLDs = []string{
	"local", "localhost", "internal", "intranet",
	"test", "example", "invalid",
	"home", "lan", "corp", "private",
}

// supportScamReasonCodesFor maps the per-category names emitted by
// internal/supportscam.Score into reason codes the response surfaces.
// One-to-one mapping; unknown categories are skipped silently so a
// scorer addition without a code-update doesn't blow up the response.
func supportScamReasonCodesFor(cats []string) []reasons.Code {
	if len(cats) == 0 {
		return nil
	}
	var out []reasons.Code
	for _, c := range cats {
		switch c {
		case "scareware":
			out = append(out, reasons.FakeSecurityWarning)
		case "payment_demand":
			out = append(out, reasons.GiftCardPaymentDemand)
		case "remote_tool":
			out = append(out, reasons.RemoteToolLure)
		case "brand_impersonation":
			out = append(out, reasons.FakeTechSupportBrand)
		case "gov_impersonation":
			out = append(out, reasons.GovImpersonation)
		case "support_phone_lure":
			// Phone lure alone isn't a hard reason code; it composes
			// with the others via SupportScamLanguage. Skip to keep
			// the reason-code surface narrow.
		}
	}
	return out
}

// paymentScamReasonCodesFor maps internal/paymentscam category names
// to reason codes the response surfaces. One-to-one mapping; unknown
// categories are skipped so a scorer addition without a code update
// doesn't blow up the response.
func paymentScamReasonCodesFor(cats []string) []reasons.Code {
	if len(cats) == 0 {
		return nil
	}
	var out []reasons.Code
	for _, c := range cats {
		switch c {
		case "gift_card_scam":
			out = append(out, reasons.GiftCardPaymentDemand)
		case "wire_fraud":
			out = append(out, reasons.WireFraudDemand)
		case "tax_refund_scam":
			out = append(out, reasons.TaxRefundScam)
		case "fake_invoice":
			out = append(out, reasons.FakeInvoicePhishing)
		case "lottery_scam":
			out = append(out, reasons.LotteryPrizeScam)
		case "romance_scam":
			out = append(out, reasons.RomanceScamMoneyRequest)
		case "charity_scam":
			out = append(out, reasons.CharityImpersonation)
		case "gov_impersonation":
			out = append(out, reasons.GovImpersonation)
		}
	}
	return out
}

// cryptoDrainerReasonCodesFor maps internal/cryptodrainer category
// names to reason codes. Same shape as supportscam / paymentscam.
func cryptoDrainerReasonCodesFor(cats []string) []reasons.Code {
	if len(cats) == 0 {
		return nil
	}
	var out []reasons.Code
	for _, c := range cats {
		switch c {
		case "airdrop_lure":
			out = append(out, reasons.AirdropClaimScam)
		case "revoke_permissions_lure":
			out = append(out, reasons.WalletRevokeLure)
		case "fake_mint_lure":
			out = append(out, reasons.NFTMintScam)
		case "wallet_connect_lure":
			out = append(out, reasons.CryptoDrainerPattern)
		case "drainer_wallet_method":
			out = append(out, reasons.WalletDrainerScript)
		case "fake_defi_brand":
			out = append(out, reasons.FakeDeFiBrand)
		}
	}
	return out
}
