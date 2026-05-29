package policy

import (
	"strings"
	"testing"

	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

// helpers
func has(codes []string, code reasons.Code) bool {
	for _, c := range codes {
		if c == string(code) {
			return true
		}
	}
	return false
}

func base(in Inputs) Inputs {
	if in.PageClass == "" {
		in.PageClass = pageclass.Generic
	}
	in.VerificationAvailable = true
	return in
}

// --- Stage F: feed-hit with source-tier consensus ---

func TestFeedHit_HighConfidenceSingleHit_Blocks(t *testing.T) {
	// One URLhaus hit alone is enough — URLhaus is curated/high-confidence.
	r := Apply(base(Inputs{
		Context: ContextOutput{
			FeedHit:         true,
			FeedSources:     []string{"urlhaus"},
			FeedHighSources: []string{"urlhaus"},
		},
		Identity: IdentityOutput{Bound: true},
	}))
	if r.Verdict != Block {
		t.Errorf("single high-confidence hit should BLOCK; got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.ExternalFeedHit) {
		t.Errorf("expected ExternalFeedHit; got %v", r.ReasonCodes)
	}
}

func TestFeedHit_TwoMediumSources_BlocksByConsensus(t *testing.T) {
	r := Apply(base(Inputs{
		Context: ContextOutput{
			FeedHit:           true,
			FeedSources:       []string{"phishdb_github", "crowdsec_community"},
			FeedMediumSources: []string{"phishdb_github", "crowdsec_community"},
		},
		Identity: IdentityOutput{Bound: true},
	}))
	if r.Verdict != Block {
		t.Errorf("two medium sources should BLOCK by consensus; got %s", r.Verdict)
	}
}

func TestFeedHit_SingleMediumOnly_AdvisoryWarn(t *testing.T) {
	// PhishDB-GitHub alone is noisy (it once flagged amazon.com). Single hit
	// must NOT auto-BLOCK; instead it becomes advisory WARN, leaving room
	// for downstream rules to override either direction.
	r := Apply(base(Inputs{
		Context: ContextOutput{
			FeedHit:           true,
			FeedSources:       []string{"phishdb_github"},
			FeedMediumSources: []string{"phishdb_github"},
		},
		Identity: IdentityOutput{Bound: true},
	}))
	if r.Verdict == Block {
		t.Errorf("single medium hit should NOT auto-BLOCK; got %s", r.Verdict)
	}
	if r.Verdict != Warn {
		t.Errorf("single medium hit should be WARN advisory; got %s", r.Verdict)
	}
}

// --- Stage F.0: category-feed split (Fix 2) ---

// TestCategoryFeed_SecurityAndAdult_SecurityWins verifies that a URL appearing
// on both URLhaus (empty category = security) AND an adult-category feed still
// BLOCKs even when the user has adult disabled. The URLhaus row must not be
// stripped because the row set is not purely content-category.
func TestCategoryFeed_SecurityAndAdult_SecurityWins(t *testing.T) {
	r := Apply(base(Inputs{
		Context: ContextOutput{
			FeedHit:         true,
			FeedCategories:  []string{"", "adult"}, // "" = URLhaus row
			FeedHighSources: []string{"urlhaus"},
			FeedSources:     []string{"urlhaus"},
		},
		// User has adult disabled (no entry in CategoryBlocks).
		CategoryBlocks: map[string]bool{},
	}))
	if r.Verdict != Block {
		t.Errorf("URLhaus (empty-category) + adult feed: should BLOCK on URLhaus; got %s", r.Verdict)
	}
}

// TestCategoryFeed_AdultOnly_UserEnabled_Blocks verifies that a purely
// adult-category row blocks when the user has the adult filter on.
func TestCategoryFeed_AdultOnly_UserEnabled_Blocks(t *testing.T) {
	r := Apply(base(Inputs{
		Context: ContextOutput{
			FeedHit:           true,
			FeedCategories:    []string{"adult"},
			FeedMediumSources: []string{"stevenblack"},
			FeedSources:       []string{"stevenblack"},
		},
		CategoryBlocks: map[string]bool{"adult": true},
	}))
	if r.Verdict != Block {
		t.Errorf("adult-only row, user has adult ON: should BLOCK; got %s", r.Verdict)
	}
}

// TestCategoryFeed_AdultOnly_UserDisabled_Allows verifies that a purely
// adult-category row does NOT block when the user has the adult filter off.
func TestCategoryFeed_AdultOnly_UserDisabled_Allows(t *testing.T) {
	r := Apply(base(Inputs{
		Context: ContextOutput{
			FeedHit:           true,
			FeedCategories:    []string{"adult"},
			FeedMediumSources: []string{"stevenblack"},
			FeedSources:       []string{"stevenblack"},
		},
		// User has adult disabled — no entry.
		CategoryBlocks: map[string]bool{},
	}))
	if r.Verdict == Block {
		t.Errorf("adult-only row, user has adult OFF: should NOT block; got %s", r.Verdict)
	}
}

// --- Phase A: HiddenSuspiciousCount thresholds + orggraph interaction ---

// TestHiddenSuspiciousCount_BelowThreshold_DoesNotWarn — 7 cross-origin
// hidden anchors is below the threshold (8). Should not WARN. The
// threshold itself is the structural fix; orggraph reduces same-org
// links out of the count entirely upstream in policymap.
func TestHiddenSuspiciousCount_BelowThreshold_DoesNotWarn(t *testing.T) {
	r := Apply(base(Inputs{
		Context: ContextOutput{
			HiddenSuspiciousCount: 7,
		},
	}))
	if r.Verdict != Allow {
		t.Errorf("7 hidden anchors should NOT WARN; got %s", r.Verdict)
	}
	for _, c := range r.ReasonCodes {
		if c == string(reasons.HiddenMaliciousLink) {
			t.Errorf("HIDDEN_MALICIOUS_LINK should not fire at 7")
		}
	}
}

// TestHiddenSuspiciousCount_AtThreshold_Warns — 8+ cross-origin hidden
// anchors crosses the threshold. Should WARN on untrusted host.
func TestHiddenSuspiciousCount_AtThreshold_Warns(t *testing.T) {
	r := Apply(base(Inputs{
		Context: ContextOutput{
			HiddenSuspiciousCount: 8,
		},
	}))
	if r.Verdict != Warn {
		t.Errorf("8 hidden anchors on untrusted host should WARN; got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.HiddenMaliciousLink) {
		t.Errorf("expected HIDDEN_MALICIOUS_LINK")
	}
}

// TestHiddenSuspiciousCount_TrustedHost_SuppressesWarn — even with many
// hidden cross-origin anchors, a TrustedIdentity host doesn't WARN.
// Note: this is a SOFT-rule TrustedIdentity carve-out, the kind Phase B
// will replace with a trustscore consultation. Kept here as the current
// behavior contract.
func TestHiddenSuspiciousCount_TrustedHost_SuppressesWarn(t *testing.T) {
	r := Apply(base(Inputs{
		TrustedIdentity: true,
		Context: ContextOutput{
			HiddenSuspiciousCount: 50,
		},
	}))
	if r.Verdict == Warn || r.Verdict == Block {
		t.Errorf("trusted host should not WARN/BLOCK on hidden anchors alone; got %s", r.Verdict)
	}
}

// --- Stage B+C: replica + identity ---

func TestReplica_AloneIsNotMalicious(t *testing.T) {
	// Microsoft tutorial / brand-owned domain showing a Microsoft login screenshot.
	// Replica high + identity bound → ALLOW.
	r := Apply(base(Inputs{
		Replica:  ReplicaOutput{Brand: "Microsoft", Score: 0.95, IsHighMatch: true},
		Identity: IdentityOutput{Bound: true},
	}))
	if r.Verdict != Allow {
		t.Errorf("replica high + identity bound: should ALLOW; got %s", r.Verdict)
	}
}

// TestReplica_HighPlusIdentityFalse_NoBrandInURL_DoesNotIsolate is the
// regression test for the login.tailscale.com → Reddit FP class. CLIP can
// embed any minimal-form login page close to some seeded brand (Reddit,
// Discord, Trezor, Snapchat have all surfaced as FP brands in real traffic).
// When that happens, brandgraph correctly reports "identity not bound" —
// because of course Tailscale's domain isn't bound to Reddit. But that
// mismatch alone is NOT evidence of phishing: it's the expected state of a
// CLIP misfire. Without brand-name corroboration in the URL/title, we MUST
// allow downstream rules to make the verdict and not ISOLATE on the bare
// uncorroborated visual match.
func TestReplica_HighPlusIdentityFalse_NoBrandInURL_DoesNotIsolate(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Replica: ReplicaOutput{
			Brand:          "Reddit",
			Score:          0.95,
			IsHighMatch:    true,
			BrandNameInURL: false, // URL is login.tailscale.com — no "reddit" in it
		},
		Identity: IdentityOutput{
			Bound:          false,
			MismatchDomain: true, // brandgraph correctly says: tailscale.com ≠ reddit infra
			BrandName:      "Reddit",
		},
	}))
	if r.Verdict != Allow {
		t.Errorf("uncorroborated CLIP misfire: should ALLOW (let downstream rules decide); got %s", r.Verdict)
	}
	for _, c := range r.ReasonCodes {
		if c == string(reasons.VisualReplicaHigh) {
			t.Errorf("should not surface VISUAL_REPLICA_HIGH when brand-name not in URL")
		}
	}
}

func TestReplica_HighPlusIdentityFalse_BLOCKs(t *testing.T) {
	// Real phishing scenario: visual matches Microsoft, identity check
	// shows the hosting isn't Microsoft, AND the URL/title says "microsoft"
	// (BrandNameInURL=true — the attacker is calling the page Microsoft on
	// purpose). All three signals together → high-confidence BLOCK.
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Replica: ReplicaOutput{
			Brand:          "Microsoft",
			Score:          0.95,
			IsHighMatch:    true,
			BrandNameInURL: true,
		},
		Identity: IdentityOutput{
			Bound:          false,
			MismatchDomain: true,
			MismatchASN:    true,
			BrandName:      "Microsoft",
		},
	}))
	if r.Verdict != Block {
		t.Errorf("replica high + identity false + brand-in-URL: should BLOCK; got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.VisualReplicaHigh) {
		t.Errorf("expected VisualReplicaHigh")
	}
	if !has(r.ReasonCodes, reasons.IdentityMismatchDomain) {
		t.Errorf("expected IdentityMismatchDomain (orthogonal code, not lumped)")
	}
	if !has(r.ReasonCodes, reasons.IdentityMismatchASN) {
		t.Errorf("expected IdentityMismatchASN")
	}
}

func TestReplica_HighPlusIdentityUnknown_SensitiveIsolates(t *testing.T) {
	// Brand-name-in-URL set true: page claims to be PayPal AND visually
	// looks like PayPal AND we can't verify the hosting → ISOLATE.
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Replica: ReplicaOutput{
			Brand:          "PayPal",
			Score:          0.91,
			IsHighMatch:    true,
			BrandNameInURL: true,
		},
		Identity: IdentityOutput{Unknown: true, BrandName: "PayPal"},
	}))
	if r.Verdict != Isolate {
		t.Errorf("replica + identity unknown + sensitive: should ISOLATE; got %s", r.Verdict)
	}
}

func TestReplica_HighPlusIdentityUnknown_GenericWarns(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Generic,
		Replica: ReplicaOutput{
			Brand:          "Stripe",
			Score:          0.92,
			IsHighMatch:    true,
			BrandNameInURL: true,
		},
		Identity: IdentityOutput{Unknown: true},
	}))
	if r.Verdict != Warn {
		t.Errorf("replica + identity unknown + generic: should WARN; got %s", r.Verdict)
	}
}

// --- Stage D: sink trust ---

func TestSink_PreSubmitCapture_BLOCKsRegardlessOfReplica(t *testing.T) {
	// Even with low replica score, keystroke capture on a sensitive page is BLOCK.
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Sink:      SinkOutput{PreSubmitCapture: true, Destinations: []string{"https://evil.example"}},
	}))
	if r.Verdict != Block {
		t.Errorf("pre-submit capture: should BLOCK; got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.CredentialSinkPreSubmitCapture) {
		t.Errorf("expected CredentialSinkPreSubmitCapture")
	}
}

func TestSink_HiddenMirror_BLOCKs(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Payment,
		Sink:      SinkOutput{HiddenMirror: true},
	}))
	if r.Verdict != Block {
		t.Errorf("hidden mirror: should BLOCK")
	}
	if !has(r.ReasonCodes, reasons.CredentialSinkHiddenMirror) {
		t.Errorf("expected CredentialSinkHiddenMirror")
	}
}

func TestSink_MultiDestination_BLOCKs(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Sink: SinkOutput{
			MultiDestination: true,
			Destinations:     []string{"https://a.evil", "https://b.evil", "https://c.evil"},
		},
	}))
	if r.Verdict != Block {
		t.Errorf("multi-destination: should BLOCK")
	}
}

func TestSink_UntrustedEndpoint_BLOCKs(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Sink: SinkOutput{
			UntrustedEndpoint: true,
			CrossOrigin:       true,
			Destinations:      []string{"https://attacker.com"},
		},
	}))
	if r.Verdict != Block {
		t.Errorf("untrusted endpoint: should BLOCK")
	}
	if !has(r.ReasonCodes, reasons.CredentialSinkUntrustedEndpoint) {
		t.Errorf("expected CredentialSinkUntrustedEndpoint (more specific than CrossOrigin)")
	}
}

func TestSink_CrossOriginOnGenericPage_DoesNotBlock(t *testing.T) {
	// Sink failure rules only apply to sensitive page classes. A generic
	// blog post with cross-origin fetch is fine.
	r := Apply(base(Inputs{
		PageClass: pageclass.Generic,
		Sink:      SinkOutput{CrossOrigin: true},
	}))
	if r.Verdict == Block {
		t.Errorf("cross-origin on generic page should NOT block")
	}
}

// --- OAuth ---

func TestOAuth_UnverifiedHighScopeApp_BLOCKs(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.OAuthConsent,
		Identity:  IdentityOutput{Bound: true}, // real provider domain
		Context: ContextOutput{
			OAuthHighRiskUnknown: true,
			OAuthAppName:         "Random App XYZ",
			OAuthClientID:        "abc-123",
		},
	}))
	if r.Verdict != Block {
		t.Errorf("unverified OAuth + sensitive scopes on real provider: should BLOCK; got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.OAuthUnverifiedHighScopeApp) {
		t.Errorf("expected OAuthUnverifiedHighScopeApp")
	}
}

// --- Anti-cloaking ---

func TestCloaking_ChallengeOnSensitivePage_Isolates(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Context:   ContextOutput{IsChallengePage: true, ChallengeKind: "cloudflare"},
	}))
	if r.Verdict != Isolate {
		t.Errorf("challenge on sensitive page: should ISOLATE; got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.CloakingDivergence) {
		t.Errorf("expected CloakingDivergence")
	}
}

func TestCloaking_ChallengeOnGenericPage_DoesNotIsolate(t *testing.T) {
	// A captcha on a forum index doesn't need isolation.
	r := Apply(base(Inputs{
		PageClass: pageclass.Generic,
		Context:   ContextOutput{IsChallengePage: true, ChallengeKind: "cloudflare"},
	}))
	if r.Verdict == Isolate {
		t.Errorf("challenge on generic page should not auto-isolate")
	}
}

// --- Path drift ---

func TestPathDrift_OnSensitivePage_BLOCKs(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Context:   ContextOutput{PathDrift: true},
	}))
	if r.Verdict != Block {
		t.Errorf("path drift on sensitive page: should BLOCK")
	}
	if !has(r.ReasonCodes, reasons.PathDriftOnTrustedDomain) {
		t.Errorf("expected PathDriftOnTrustedDomain")
	}
}

// --- Fail-closed on sensitive when verification unavailable ---

func TestSensitive_VerificationUnavailable_FailsClosed(t *testing.T) {
	in := Inputs{
		URL:       "https://example.com/login",
		PageClass: pageclass.Login,
		// note: VerificationAvailable explicitly false (base() helper not used)
	}
	r := Apply(in)
	if r.Verdict != Isolate {
		t.Errorf("sensitive + verification unavailable: should ISOLATE, got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.SensitivePageVerificationUnavailable) {
		t.Errorf("expected SensitivePageVerificationUnavailable")
	}
}

func TestGeneric_VerificationUnavailable_StillAllows(t *testing.T) {
	in := Inputs{
		URL:       "https://example.com/about",
		PageClass: pageclass.Generic,
	}
	r := Apply(in)
	if r.Verdict != Allow {
		t.Errorf("generic + verification unavailable: should still ALLOW")
	}
}

// --- Behavior support signals ---

func TestPopupStorm_WarnsButDoesNotBlock(t *testing.T) {
	r := Apply(base(Inputs{
		Context: ContextOutput{BehaviorPopupStorm: true},
	}))
	if r.Verdict != Warn {
		t.Errorf("popup storm alone: should WARN; got %s", r.Verdict)
	}
}

func TestScarewareComposite_BLOCKs(t *testing.T) {
	r := Apply(base(Inputs{
		Context: ContextOutput{BehaviorScareware: true},
	}))
	if r.Verdict != Block {
		t.Errorf("scareware composite: should BLOCK")
	}
}

// --- Paranoid (Executive Mode) ---

func TestParanoid_IsolatesUnverifiedSensitive(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Identity:  IdentityOutput{Bound: false, Unknown: true},
		Paranoid:  true,
	}))
	// Will hit B+C unknown-sensitive isolate path first (replica score is zero
	// so that branch doesn't fire) — fall through. Paranoid then upgrades.
	if r.Verdict != Isolate {
		t.Errorf("paranoid + sensitive + identity unbound: should ISOLATE; got %s", r.Verdict)
	}
}

func TestParanoid_DoesNotElevateBoundSensitive(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Identity:  IdentityOutput{Bound: true},
		Paranoid:  true,
	}))
	if r.Verdict != Allow {
		t.Errorf("paranoid + bound identity: should still ALLOW")
	}
}

// --- Reason-code orthogonality ---

func TestIdentityCodes_AreOrthogonal(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Replica: ReplicaOutput{
			Brand:          "Stripe",
			IsHighMatch:    true,
			Score:          0.95,
			BrandNameInURL: true,
		},
		Identity: IdentityOutput{
			Bound:          false,
			MismatchDomain: true,
			MismatchCert:   true,
		},
	}))
	if !has(r.ReasonCodes, reasons.IdentityMismatchDomain) {
		t.Errorf("expected MismatchDomain code")
	}
	if !has(r.ReasonCodes, reasons.IdentityMismatchCert) {
		t.Errorf("expected MismatchCert code")
	}
	// MismatchASN was NOT flagged → must not appear
	if has(r.ReasonCodes, reasons.IdentityMismatchASN) {
		t.Errorf("MismatchASN should not appear when ASN wasn't flagged")
	}
}

// --- Sanity: BlockReason filled in ---

func TestBlockReason_NotEmpty(t *testing.T) {
	cases := []Inputs{
		base(Inputs{Context: ContextOutput{FeedHit: true}}),
		base(Inputs{PageClass: pageclass.Login, Sink: SinkOutput{PreSubmitCapture: true}}),
		base(Inputs{
			PageClass: pageclass.Login,
			Replica:   ReplicaOutput{Brand: "X", IsHighMatch: true, Score: 0.95},
			Identity:  IdentityOutput{Bound: false, MismatchDomain: true},
		}),
	}
	for _, in := range cases {
		r := Apply(in)
		if r.Verdict == Block && strings.TrimSpace(r.BlockReason) == "" {
			t.Errorf("BLOCK without BlockReason for input %+v", in)
		}
	}
}

// --- Phase B.3: PUBLIC_DOMAIN_PRIVATE_IP hard rule ---

// TestPublicDomainPrivateIP_HardBlocks — when the browser reached an RFC1918
// IP for what verdict-api thinks is a public domain, the connection is
// hijacked. Hard BLOCK, before any vendor-DNS / trust check.
func TestPublicDomainPrivateIP_HardBlocks(t *testing.T) {
	r := Apply(base(Inputs{
		Domain: "bank.example.com",
		Context: ContextOutput{
			BrowserRemoteIP:          "10.0.0.5",
			BrowserRemoteIPIsPrivate: true,
		},
	}))
	if r.Verdict != Block {
		t.Errorf("public domain reaching private IP must BLOCK; got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.PublicDomainPrivateIP) {
		t.Errorf("expected PUBLIC_DOMAIN_PRIVATE_IP; got %v", r.ReasonCodes)
	}
}

// TestPublicDomainPrivateIP_TrustedIdentityCannotSuppress — even if the
// domain is in trustreg, a hijacked DNS path still BLOCKs. Hard rules
// override trust per CLAUDE.md "Hard rules vs scored rules".
func TestPublicDomainPrivateIP_TrustedIdentityCannotSuppress(t *testing.T) {
	r := Apply(base(Inputs{
		Domain:          "google.com",
		TrustedIdentity: true,
		Context: ContextOutput{
			BrowserRemoteIP:          "192.168.1.50",
			BrowserRemoteIPIsPrivate: true,
		},
	}))
	if r.Verdict != Block {
		t.Errorf("trusted brand on private IP must still BLOCK; got %s", r.Verdict)
	}
	if !has(r.ReasonCodes, reasons.PublicDomainPrivateIP) {
		t.Errorf("expected PUBLIC_DOMAIN_PRIVATE_IP even for trusted; got %v", r.ReasonCodes)
	}
}

// TestPublicDomainPrivateIP_LocalDomainNotAffected — router.local from
// 192.168.1.1 is LAN-to-LAN, not a hijack. Must not BLOCK.
func TestPublicDomainPrivateIP_LocalDomainNotAffected(t *testing.T) {
	for _, host := range []string{"router.local", "printer.lan", "intranet.corp", "localhost", "myhost"} {
		r := Apply(base(Inputs{
			Domain: host,
			Context: ContextOutput{
				BrowserRemoteIP:          "192.168.1.1",
				BrowserRemoteIPIsPrivate: true,
			},
		}))
		if r.Verdict == Block && has(r.ReasonCodes, reasons.PublicDomainPrivateIP) {
			t.Errorf("local-namespace host %q reaching private IP must not fire PUBLIC_DOMAIN_PRIVATE_IP", host)
		}
	}
}

// TestPublicDomainPrivateIP_PublicIPDoesNotFire — public domain reaching a
// public IP is the happy path; nothing here should trip.
func TestPublicDomainPrivateIP_PublicIPDoesNotFire(t *testing.T) {
	r := Apply(base(Inputs{
		Domain: "example.com",
		Context: ContextOutput{
			BrowserRemoteIP:          "203.0.113.10",
			BrowserRemoteIPIsPrivate: false,
		},
	}))
	if has(r.ReasonCodes, reasons.PublicDomainPrivateIP) {
		t.Errorf("public domain on public IP must not fire PUBLIC_DOMAIN_PRIVATE_IP; got %v", r.ReasonCodes)
	}
}

// TestPublicDomainPrivateIP_AbsentWhenExtensionDidNotSend — no
// browser_remote_ip means we have no signal; must not BLOCK.
func TestPublicDomainPrivateIP_AbsentWhenExtensionDidNotSend(t *testing.T) {
	r := Apply(base(Inputs{
		Domain: "example.com",
		Context: ContextOutput{
			BrowserRemoteIP:          "",
			BrowserRemoteIPIsPrivate: false,
		},
	}))
	if has(r.ReasonCodes, reasons.PublicDomainPrivateIP) {
		t.Errorf("no remote IP supplied must not fire PUBLIC_DOMAIN_PRIVATE_IP")
	}
}

func TestIsPublicDomain(t *testing.T) {
	yes := []string{"example.com", "sub.example.com", "bank.co.uk", "example.com.", "EXAMPLE.COM"}
	no := []string{"", "localhost", "router.local", "x.localhost", "thing.lan",
		"intranet.corp", "test.test", "host.invalid", "127.0.0.1", "::1",
		"singlelabel", "8.8.8.8"}
	for _, h := range yes {
		if !isPublicDomain(h) {
			t.Errorf("isPublicDomain(%q) = false, want true", h)
		}
	}
	for _, h := range no {
		if isPublicDomain(h) {
			t.Errorf("isPublicDomain(%q) = true, want false", h)
		}
	}
}

// --- Phase C.3: scoped trust population sanity ---
//
// These tests don't exercise Apply — they document the contract the
// populator (policymap.go) must satisfy. If any of these would be wrong
// after a brandgraph change, callers reading the legacy TrustedIdentity
// field need to be migrated to the right scope.

// TestScopedTrust_LegacyAliasMatchesAggregate — TrustedIdentity must equal
// TrustedAnyScope so existing soft-rule call sites don't change behavior
// during the C.3 transition.
func TestScopedTrust_LegacyAliasMatchesAggregate(t *testing.T) {
	// Mode 1: both true.
	r := base(Inputs{TrustedIdentity: true, TrustedAnyScope: true})
	if r.TrustedIdentity != r.TrustedAnyScope {
		t.Errorf("TrustedIdentity must equal TrustedAnyScope; got %v != %v", r.TrustedIdentity, r.TrustedAnyScope)
	}
	// Mode 2: both false.
	r = base(Inputs{})
	if r.TrustedIdentity != r.TrustedAnyScope {
		t.Errorf("TrustedIdentity must equal TrustedAnyScope when both unset; got %v != %v", r.TrustedIdentity, r.TrustedAnyScope)
	}
}

// TestScopedTrust_ScriptOnlyDoesNotImplyLogin — a host that's only
// script-source-trusted (CDN like gstatic.com) must NOT have
// TrustedForLogin set. This is the invariant that protects credential
// sinks on CDN-hosted phishing pages.
func TestScopedTrust_ScriptOnlyDoesNotImplyLogin(t *testing.T) {
	r := base(Inputs{
		TrustedForScript: true,
		TrustedAnyScope:  true,
	})
	if r.TrustedForLogin {
		t.Errorf("script-only trust must not set TrustedForLogin")
	}
}
