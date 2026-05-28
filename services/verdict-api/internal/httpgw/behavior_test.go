package httpgw

import (
	"testing"

	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

func TestBehaviorSignals_Nil(t *testing.T) {
	sigs, codes := behaviorSignals(nil)
	if len(sigs) != 0 || len(codes) != 0 {
		t.Errorf("nil input should yield zero signals/codes")
	}
}

func TestBehaviorSignals_PopupStorm(t *testing.T) {
	_, codes := behaviorSignals(map[string]int{"popup_open": 5})
	if !contains(codes, string(reasons.PopupStormDetected)) {
		t.Errorf("popup_open=5 should trigger PopupStormDetected; got %v", codes)
	}
}

func TestBehaviorSignals_PopupBelowThreshold(t *testing.T) {
	_, codes := behaviorSignals(map[string]int{"popup_open": 2})
	if contains(codes, string(reasons.PopupStormDetected)) {
		t.Errorf("popup_open=2 should NOT trigger PopupStormDetected; got %v", codes)
	}
}

func TestBehaviorSignals_AlertLoopComposite(t *testing.T) {
	// alert + confirm combined must hit ≥2 for the alert-loop signal.
	_, codes := behaviorSignals(map[string]int{"alert": 1, "confirm": 1})
	if !contains(codes, string(reasons.AlertLoopDetected)) {
		t.Errorf("alert+confirm should trigger AlertLoopDetected; got %v", codes)
	}
}

func TestBehaviorSignals_FullscreenTrap(t *testing.T) {
	_, codes := behaviorSignals(map[string]int{"fullscreen_req": 1})
	if !contains(codes, string(reasons.FullscreenTrapDetected)) {
		t.Errorf("fullscreen_req=1 should trigger FullscreenTrapDetected; got %v", codes)
	}
}

func TestBehaviorSignals_ScarewareComposite(t *testing.T) {
	// Three or more abuse classes → FAKE_SUPPORT_SCAREWARE.
	_, codes := behaviorSignals(map[string]int{
		"popup_open":      4,
		"alert":           3,
		"fullscreen_req":  1,
	})
	if !contains(codes, string(reasons.FakeSupportScareware)) {
		t.Errorf("3+ abuse classes should fire scareware composite; got %v", codes)
	}
	// And the individual reasons should still be there.
	for _, want := range []string{
		string(reasons.PopupStormDetected),
		string(reasons.AlertLoopDetected),
		string(reasons.FullscreenTrapDetected),
	} {
		if !contains(codes, want) {
			t.Errorf("expected %s in codes, got %v", want, codes)
		}
	}
}

func TestBehaviorSignals_NotEnoughForScareware(t *testing.T) {
	// Two abuse classes → individual reasons fire, but no composite.
	_, codes := behaviorSignals(map[string]int{
		"popup_open": 4,
		"alert":      3,
	})
	if contains(codes, string(reasons.FakeSupportScareware)) {
		t.Errorf("2 abuse classes should NOT fire scareware composite; got %v", codes)
	}
}

func TestBehaviorSignals_AllCodesMapped(t *testing.T) {
	// Sanity: every signal name we emit has a mapping in signalToCode.
	sigs, _ := behaviorSignals(map[string]int{
		"popup_open":      5,
		"alert":           3,
		"fullscreen_req":  1,
		"beforeunload":    1,
		"clipboard_write": 1,
		"auto_download":   1,
	})
	for _, s := range sigs {
		if _, ok := signalToCode[s.Name]; !ok {
			t.Errorf("signal %q has no entry in signalToCode", s.Name)
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
