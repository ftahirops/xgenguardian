package policy

import (
	"reflect"
	"testing"

	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

// --- Diff plumbing ---

func TestShadow_NilCandidate_NoDiff(t *testing.T) {
	in := base(Inputs{
		Context: ContextOutput{HasCrossOriginIframe: true, HiddenCrossOriginIframeCount: 3},
	})
	prod, diff := RunShadow(in, nil)
	if prod.Verdict != Warn {
		t.Errorf("production should WARN on hidden iframe; got %s", prod.Verdict)
	}
	if !diff.IsClean() {
		t.Errorf("nil candidate must yield a clean diff; got kind=%s", diff.Kind())
	}
	if diff.ProductionLatencyNs <= 0 {
		t.Errorf("production latency should be measured even with nil candidate")
	}
}

func TestShadow_IdentityCandidate_Clean(t *testing.T) {
	in := base(Inputs{
		Context: ContextOutput{HiddenSuspiciousCount: 12},
	})
	_, diff := RunShadow(in, Apply)
	if !diff.IsClean() {
		t.Errorf("identity candidate must yield clean diff; got %+v", diff)
	}
	if diff.Kind() != "clean" {
		t.Errorf("Kind() should be clean; got %s", diff.Kind())
	}
}

// --- VerdictChanged detection ---

func TestShadow_VerdictChanged_Detected(t *testing.T) {
	in := base(Inputs{
		Context: ContextOutput{HasCrossOriginIframe: true, HiddenCrossOriginIframeCount: 3},
	})
	// Candidate forces ISOLATE — production would WARN on a hidden iframe.
	candidate := func(Inputs) Result {
		return Result{Verdict: Isolate, ReasonCodes: []string{string(reasons.HiddenIframeCrossOrigin)}}
	}
	_, diff := RunShadow(in, candidate)
	if !diff.VerdictChanged {
		t.Fatalf("expected VerdictChanged; got %+v", diff)
	}
	if diff.ProductionVerdict != Warn || diff.CandidateVerdict != Isolate {
		t.Errorf("verdict fields wrong: prod=%s cand=%s", diff.ProductionVerdict, diff.CandidateVerdict)
	}
	if diff.Kind() != "verdict_changed" {
		t.Errorf("Kind() = %s; want verdict_changed", diff.Kind())
	}
}

// --- Reason-code add/remove detection ---

func TestShadow_ReasonsAdded_Detected(t *testing.T) {
	in := base(Inputs{})
	// Production returns ALLOW with no codes.
	// Candidate returns ALLOW but with two extra codes.
	candidate := func(in Inputs) Result {
		r := Apply(in)
		r.ReasonCodes = append(r.ReasonCodes, string(reasons.RandomHostname), string(reasons.HiddenMaliciousLink))
		return r
	}
	_, diff := RunShadow(in, candidate)
	if diff.VerdictChanged {
		t.Fatalf("verdict should not change")
	}
	want := []string{"HIDDEN_MALICIOUS_LINK", "RANDOM_HOSTNAME"}
	if !reflect.DeepEqual(diff.ReasonsAdded, want) {
		t.Errorf("ReasonsAdded = %v; want %v", diff.ReasonsAdded, want)
	}
	if len(diff.ReasonsRemoved) != 0 {
		t.Errorf("ReasonsRemoved should be empty; got %v", diff.ReasonsRemoved)
	}
	if diff.Kind() != "reasons_added" {
		t.Errorf("Kind() = %s; want reasons_added", diff.Kind())
	}
}

func TestShadow_ReasonsRemoved_Detected(t *testing.T) {
	in := base(Inputs{
		Context: ContextOutput{HasCrossOriginIframe: true, HiddenCrossOriginIframeCount: 3},
	})
	// Candidate quiets the hidden-iframe reason while preserving the verdict.
	candidate := func(in Inputs) Result {
		return Result{Verdict: Warn, ReasonCodes: []string{}}
	}
	_, diff := RunShadow(in, candidate)
	if !reflect.DeepEqual(diff.ReasonsRemoved, []string{"HIDDEN_IFRAME_CROSS_ORIGIN"}) {
		t.Errorf("ReasonsRemoved = %v; want [HIDDEN_IFRAME_CROSS_ORIGIN]", diff.ReasonsRemoved)
	}
	if diff.Kind() != "reasons_removed" {
		t.Errorf("Kind() = %s; want reasons_removed", diff.Kind())
	}
}

// --- VerdictChanged takes precedence in Kind() ---

func TestShadow_Kind_VerdictChangedTrumpsReasons(t *testing.T) {
	in := base(Inputs{
		Context: ContextOutput{HasCrossOriginIframe: true, HiddenCrossOriginIframeCount: 3},
	})
	candidate := func(in Inputs) Result {
		// Different verdict AND different reasons — verdict_changed wins.
		return Result{Verdict: Block, ReasonCodes: []string{"NEW_CODE_X"}}
	}
	_, diff := RunShadow(in, candidate)
	if diff.Kind() != "verdict_changed" {
		t.Errorf("verdict_changed must take precedence; got %s", diff.Kind())
	}
}

// --- Confidence drift is reported but does NOT mark Diff dirty ---

func TestShadow_ConfidenceDrift_DoesNotMarkDirty(t *testing.T) {
	in := base(Inputs{
		Context: ContextOutput{HasCrossOriginIframe: true, HiddenCrossOriginIframeCount: 3},
	})
	candidate := func(in Inputs) Result {
		r := Apply(in)
		r.Confidence += 0.10 // candidate is more confident
		return r
	}
	_, diff := RunShadow(in, candidate)
	if !diff.IsClean() {
		t.Errorf("confidence drift alone must not dirty the diff; got %+v", diff)
	}
	if diff.ConfidenceDelta <= 0 {
		t.Errorf("ConfidenceDelta should be positive; got %f", diff.ConfidenceDelta)
	}
}

// --- Production result is what RunShadow returns even when candidate disagrees ---

func TestShadow_CandidateMustNotLeakIntoUserResult(t *testing.T) {
	in := base(Inputs{
		PageClass: pageclass.Login,
		Context:   ContextOutput{HasCrossOriginIframe: true, HiddenCrossOriginIframeCount: 3},
	})
	candidate := func(Inputs) Result {
		// Candidate wants to ISOLATE the user — must NOT happen.
		return Result{Verdict: Isolate}
	}
	prod, diff := RunShadow(in, candidate)
	if prod.Verdict == Isolate {
		t.Fatalf("candidate verdict leaked into user-facing result")
	}
	if !diff.VerdictChanged {
		t.Errorf("expected VerdictChanged to be flagged for review")
	}
}

// --- Both engines are measured ---

func TestShadow_BothLatenciesCaptured(t *testing.T) {
	in := base(Inputs{})
	_, diff := RunShadow(in, Apply)
	if diff.ProductionLatencyNs <= 0 {
		t.Errorf("ProductionLatencyNs not captured")
	}
	if diff.CandidateLatencyNs <= 0 {
		t.Errorf("CandidateLatencyNs not captured")
	}
}
