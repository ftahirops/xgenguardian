// decision_matrix.go — explicit "Reputation can clear browsing; only proof
// can clear sensitive action" decision layer.
//
// Architectural principle (the carved-in-stone rule):
//
//   External reputation feeds (URLhaus, OpenPhish, vendor DNS) can answer
//   the question "is this URL already known bad?" They CANNOT answer:
//
//       "Is this page authorized to ask THIS user for THIS action right now?"
//
// That action-aware question is what XGG's deep tests (visual brand match,
// credential-sink analysis, shell-command analysis, OAuth client check,
// phone-number extraction, popup-behavior counters) are designed to answer.
//
// So:
//   - All-feeds-clean is permission to allow READ-ONLY browsing.
//   - It is NOT permission to allow login / payment / OAuth / install-command
//     / download on an untrusted host.
//   - Sensitive actions on unverified hosts MUST be cleared by local proof
//     (trusted-identity binding + sink verification + (where applicable)
//     official install/template match).
//
// This file holds the matrix as a typed data table (no chained ifs) so the
// rule is auditable, testable, and easy to extend with new action types.
//
// The matrix runs LAST inside Apply(). It does NOT replace Stages A-F. It
// codifies the residual decision after all stages have voted:
//
//     ExternalEvidence + XGGEvidence + Action  →  Verdict
//
// Specifically, after Stage F (feed lookup + OAuth + behavior + shell-command),
// Apply() consults this matrix when no earlier rule has already returned.

package policy

// Action — what the user is about to do on the page. Maps from PageClass +
// observed-DOM hints. The matrix decides differently per action because
// allowing read-only browsing on an unknown shared-host page is fine; allowing
// login/payment/OAuth on the same page is NOT.
type Action int

const (
	ActionRead           Action = iota // generic browsing — lowest sensitivity
	ActionLogin                        // password field present / login class
	ActionPayment                      // payment/checkout fields
	ActionOAuthConsent                 // OAuth /authorize page
	ActionDownload                     // direct download / install binary
	ActionInstallCommand               // dev-tool docs page with shell command for paste
	ActionSupport                      // tech-support-like page with phone/contact
)

// ExternalEvidence — verdict from threat-intel feeds + reputation services.
// Note: "ExternalClean" doesn't mean "safe" — it means "no third party
// flagged it yet." That's a positive signal, not a permission slip.
type ExternalEvidence struct {
	// FeedHigh — at least one high-confidence feed (URLhaus, OpenPhish,
	// Web Risk, curated IOC) flagged this URL.
	FeedHigh bool
	// FeedMediumCount — number of distinct medium-confidence feeds that
	// flagged the URL. ≥2 = consensus block.
	FeedMediumCount int
	// AllVendorsClean — every consulted source (feeds + DNS providers if
	// integrated) reported no problem. Reduces risk but does not clear
	// sensitive actions on its own.
	AllVendorsClean bool
}

// XGGEvidence — verdict from local action-aware analysis. This is the
// proof that external reputation cannot provide.
type XGGEvidence struct {
	// TrustedIdentity — host is in the curated Trusted Identity Registry
	// (and/or the brand-relationship graph once it lands).
	TrustedIdentity bool
	// OfficialInstallMatch — page is on a registered vendor host AND
	// shows a command that matches one of that vendor's canonical
	// install templates AND any URLs in the command target the vendor's
	// canonical hosts.
	OfficialInstallMatch bool
	// CredentialSinkClean — when the page has a login/payment form, the
	// form submits to a trusted destination (no hidden mirror, no
	// pre-submit capture, no multi-destination cross-origin POST).
	// True only after the sandbox actually verified it.
	CredentialSinkClean bool
	// SinkVerificationAvailable — the sandbox rendered the page
	// successfully enough to inspect the sink. When false, we don't know
	// whether the sink is clean or dirty — fail-closed on sensitive actions.
	SinkVerificationAvailable bool
	// ReplicaIdentityMismatch — visual brand match found a brand but
	// the host is NOT in that brand's canonical-domain list.
	ReplicaIdentityMismatch bool
	// MaliciousCommand — shellcmd hard-fail pattern fired and was NOT
	// vetted by an installreg template (i.e. it's not the vendor's
	// canonical command).
	MaliciousCommand bool
	// SuspiciousCommand — 2+ soft-signal shellcmd patterns fired on an
	// untrusted host.
	SuspiciousCommand bool
}

// MatrixDecision — outcome from Decide(). Verdict is the recommendation;
// Reason is a stable string the policy emits as the StageOutcome["G"]
// for analyst drill-down.
type MatrixDecision struct {
	Verdict Verdict
	Reason  string
}

// Decide — runs the explicit table-driven decision. Returns the recommended
// verdict for the (external, xgg, action) triple. Callers are responsible
// for mapping this to the final policy.Result and merging reason codes.
//
// The rules are written from MOST-SPECIFIC to MOST-GENERAL. The first
// matching row wins. Each rule is named so failing tests point at exactly
// which row blocked / cleared the request.
func Decide(ext ExternalEvidence, xgg XGGEvidence, action Action) MatrixDecision {

	// === HARD BLOCKS (any action, any context) ===
	if ext.FeedHigh {
		return MatrixDecision{Block, "high-feed-hit"}
	}
	if ext.FeedMediumCount >= 2 {
		return MatrixDecision{Block, "medium-feed-consensus"}
	}
	if xgg.MaliciousCommand {
		return MatrixDecision{Block, "malicious-command-pattern"}
	}
	// Visual brand impersonation on a non-canonical host is a hard block
	// regardless of action: even read-only browsing of a phishing clone
	// confirms the page exists to the victim.
	if xgg.ReplicaIdentityMismatch {
		return MatrixDecision{Block, "replica-identity-mismatch"}
	}

	// === SENSITIVE-ACTION GATES ===
	// "Reputation can clear browsing; only proof can clear sensitive action."
	// For login / payment / OAuth / install-command / support, all-vendors-
	// clean by itself is NOT enough — we require positive XGG proof.
	switch action {
	case ActionLogin, ActionPayment, ActionOAuthConsent:
		// Trusted-identity host is the strongest single positive signal.
		if xgg.TrustedIdentity {
			// Even on a trusted host, if the sink is dirty (e.g. compromised
			// page mirroring credentials to an attacker), still block.
			if xgg.SinkVerificationAvailable && !xgg.CredentialSinkClean {
				return MatrixDecision{Block, "trusted-host-dirty-sink"}
			}
			return MatrixDecision{Allow, "trusted-host-clean-sink"}
		}
		// Untrusted host. We MUST have sink verification AND it must be clean.
		if !xgg.SinkVerificationAvailable {
			return MatrixDecision{Isolate, "sensitive-untrusted-sink-unknown"}
		}
		if !xgg.CredentialSinkClean {
			return MatrixDecision{Block, "untrusted-host-dirty-sink"}
		}
		// Verified clean sink on untrusted host. Don't blanket-allow; the
		// page might still be a fresh phishing kit that hasn't tripped a
		// sink rule yet. WARN — user gets to decide, with evidence.
		return MatrixDecision{Warn, "untrusted-host-clean-sink-warn"}

	case ActionInstallCommand:
		// Install command pages: positive match against the official install
		// registry is the proof; without it, an untrusted host is suspicious.
		if xgg.OfficialInstallMatch {
			return MatrixDecision{Allow, "official-install-match"}
		}
		if xgg.SuspiciousCommand {
			return MatrixDecision{Warn, "suspicious-install-command"}
		}
		if xgg.TrustedIdentity {
			return MatrixDecision{Allow, "trusted-host-install-page"}
		}
		// Untrusted host showing an install command without a vendor-template
		// match — could be a legit third-party blog OR a phishing-class lure.
		// Warn rather than ISOLATE so the user can see + verify the command.
		return MatrixDecision{Warn, "untrusted-host-unknown-install-command"}

	case ActionDownload:
		// Trusted host download = ALLOW. Untrusted = WARN (sandbox + YARA
		// would have flagged it already; we get here only when those passed).
		if xgg.TrustedIdentity {
			return MatrixDecision{Allow, "trusted-host-download"}
		}
		return MatrixDecision{Warn, "untrusted-host-download"}

	case ActionSupport:
		// Support-class pages with no phone-mismatch / fake-chat signals
		// fall here. Trusted host = ALLOW; untrusted = WARN until phone-
		// number extraction (P2 build) lands.
		if xgg.TrustedIdentity {
			return MatrixDecision{Allow, "trusted-support-page"}
		}
		return MatrixDecision{Warn, "untrusted-support-page"}
	}

	// === READ-ONLY BROWSING ===
	// All-vendors-clean + read-only is the canonical "no problem found" path.
	// Single medium-feed hit is advisory: WARN but don't block.
	if ext.FeedMediumCount == 1 {
		return MatrixDecision{Warn, "single-medium-feed-advisory"}
	}
	return MatrixDecision{Allow, "browsing-allowed"}
}

// ActionFromPageClass — maps the page-class classifier output to the
// matrix's Action enum. Keeps the matrix's input space small and stable
// even as new PageClass values are added.
func ActionFromPageClass(c interface{ IsSensitive() bool }, raw string) Action {
	switch raw {
	case "login", "password-step", "mfa":
		return ActionLogin
	case "payment":
		return ActionPayment
	case "oauth-consent":
		return ActionOAuthConsent
	case "download":
		return ActionDownload
	case "developer-tool-install-lure":
		return ActionInstallCommand
	case "support-scareware":
		return ActionSupport
	}
	return ActionRead
}
