// behavior.go — converts sandbox-render's behavioural counters
// (window.__xgg_behavior) into fusion signals + canonical reason codes.
//
// Thresholds are conservative: legitimate pages do open new windows and
// trigger fullscreen requests on user gesture. We only fire when the count
// is high enough to be unambiguous (e.g. ≥3 popup_open calls without user
// interaction). The composite FAKE_SUPPORT_SCAREWARE reason trips when at
// least three of the individual signals fire on one page — the textbook
// tech-support-scam fingerprint.

package httpgw

import (
	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

// behaviorSignals reads `behavior` (counter map from window.__xgg_behavior)
// and returns:
//   - the list of fusion signals to add (each carries the weight that
//     should contribute to the verdict),
//   - the list of canonical reason codes to attach to the response.
//
// behavior is nil-safe.
func behaviorSignals(behavior map[string]int) ([]fusion.Signal, []string) {
	var sigs []fusion.Signal
	var codes []string

	if behavior == nil {
		return sigs, codes
	}

	// Track how many of the high-signal abuse classes fired on this page.
	// 3+ → FAKE_SUPPORT_SCAREWARE composite (high confidence tech-support scam).
	tripped := 0

	if behavior["popup_open"] >= 3 {
		sigs = append(sigs, fusion.Signal{
			Name: "behavior_popup_storm", Weight: 0.55,
			Detail: itoaInt(behavior["popup_open"]) + " window.open calls without user interaction",
		})
		codes = append(codes, string(reasons.PopupStormDetected))
		tripped++
	}

	if behavior["alert"]+behavior["confirm"]+behavior["prompt"] >= 2 {
		sigs = append(sigs, fusion.Signal{
			Name: "behavior_alert_loop", Weight: 0.5,
			Detail: "repeated alert/confirm/prompt dialog calls",
		})
		codes = append(codes, string(reasons.AlertLoopDetected))
		tripped++
	}

	if behavior["fullscreen_req"] >= 1 {
		sigs = append(sigs, fusion.Signal{
			Name: "behavior_fullscreen_trap", Weight: 0.4,
			Detail: "page requested fullscreen without a user gesture",
		})
		codes = append(codes, string(reasons.FullscreenTrapDetected))
		tripped++
	}

	if behavior["beforeunload"] >= 1 {
		sigs = append(sigs, fusion.Signal{
			Name: "behavior_beforeunload", Weight: 0.25,
			Detail: "beforeunload handler registered to block navigation",
		})
		codes = append(codes, string(reasons.BeforeUnloadAbuse))
	}

	if behavior["clipboard_write"] >= 1 {
		sigs = append(sigs, fusion.Signal{
			Name: "behavior_clipboard_hijack", Weight: 0.45,
			Detail: "page wrote to clipboard without user gesture",
		})
		codes = append(codes, string(reasons.ClipboardHijackAttempt))
		tripped++
	}

	if behavior["auto_download"] >= 1 {
		sigs = append(sigs, fusion.Signal{
			Name: "behavior_auto_download", Weight: 0.55,
			Detail: "download triggered with no user click",
		})
		codes = append(codes, string(reasons.AutoDownloadTrigger))
		tripped++
	}

	// Composite scareware detection. Three or more of the individual
	// abuse classes on one page → tech-support scam fingerprint.
	if tripped >= 3 {
		sigs = append(sigs, fusion.Signal{
			Name: "behavior_scareware_composite", Weight: 0.6,
			Detail: itoaInt(tripped) + " concurrent abuse classes",
		})
		codes = append(codes, string(reasons.FakeSupportScareware))
	}

	return sigs, codes
}

// itoaInt — local int→string conversion (fusion already has one but it's
// keyed off a different package; cheap to inline).
func itoaInt(n int) string {
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
