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

func TestReplica_HighPlusIdentityFalse_BLOCKs(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Replica:   ReplicaOutput{Brand: "Microsoft", Score: 0.95, IsHighMatch: true},
		Identity: IdentityOutput{
			Bound:          false,
			MismatchDomain: true,
			MismatchASN:    true,
			BrandName:      "Microsoft",
		},
	}))
	if r.Verdict != Block {
		t.Errorf("replica high + identity false: should BLOCK; got %s", r.Verdict)
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
	r := Apply(base(Inputs{
		PageClass: pageclass.Login,
		Replica:   ReplicaOutput{Brand: "PayPal", Score: 0.91, IsHighMatch: true},
		Identity:  IdentityOutput{Unknown: true, BrandName: "PayPal"},
	}))
	if r.Verdict != Isolate {
		t.Errorf("replica + identity unknown + sensitive: should ISOLATE; got %s", r.Verdict)
	}
}

func TestReplica_HighPlusIdentityUnknown_GenericWarns(t *testing.T) {
	r := Apply(base(Inputs{
		PageClass: pageclass.Generic,
		Replica:   ReplicaOutput{Brand: "Stripe", Score: 0.92, IsHighMatch: true},
		Identity:  IdentityOutput{Unknown: true},
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
		Replica:   ReplicaOutput{Brand: "Stripe", IsHighMatch: true, Score: 0.95},
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
