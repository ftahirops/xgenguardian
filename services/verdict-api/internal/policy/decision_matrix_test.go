package policy

import "testing"

// Tests are written as one-row-per-cell so a failure says exactly which
// matrix row regressed. Keep matching the table order in decision_matrix.go.

func TestMatrix_HighFeedHit_Blocks_AnyAction(t *testing.T) {
	for _, a := range []Action{
		ActionRead, ActionLogin, ActionPayment, ActionOAuthConsent,
		ActionDownload, ActionInstallCommand, ActionSupport,
	} {
		d := Decide(ExternalEvidence{FeedHigh: true}, XGGEvidence{}, a)
		if d.Verdict != Block || d.Reason != "high-feed-hit" {
			t.Errorf("action=%v: want BLOCK/high-feed-hit; got %v/%s", a, d.Verdict, d.Reason)
		}
	}
}

func TestMatrix_TwoMediumFeeds_Blocks(t *testing.T) {
	d := Decide(ExternalEvidence{FeedMediumCount: 2}, XGGEvidence{}, ActionRead)
	if d.Verdict != Block || d.Reason != "medium-feed-consensus" {
		t.Errorf("want BLOCK/medium-feed-consensus; got %v/%s", d.Verdict, d.Reason)
	}
}

func TestMatrix_MaliciousCommand_Blocks_Always(t *testing.T) {
	d := Decide(ExternalEvidence{AllVendorsClean: true}, XGGEvidence{MaliciousCommand: true}, ActionInstallCommand)
	if d.Verdict != Block {
		t.Errorf("malicious command should BLOCK regardless of feed-clean; got %v", d.Verdict)
	}
}

func TestMatrix_ReplicaMismatch_Blocks_EvenForReadOnly(t *testing.T) {
	d := Decide(ExternalEvidence{AllVendorsClean: true}, XGGEvidence{ReplicaIdentityMismatch: true}, ActionRead)
	if d.Verdict != Block {
		t.Errorf("visual replica on untrusted host should BLOCK; got %v", d.Verdict)
	}
}

// === The architecture-defining tests: reputation clean ≠ sensitive-action clean ===

func TestMatrix_AllVendorsClean_LoginOnUntrusted_NotAllow(t *testing.T) {
	d := Decide(
		ExternalEvidence{AllVendorsClean: true},
		XGGEvidence{TrustedIdentity: false, SinkVerificationAvailable: false},
		ActionLogin,
	)
	if d.Verdict == Allow {
		t.Errorf("all-vendors-clean must NOT allow login on untrusted host; got %v", d.Verdict)
	}
	if d.Verdict != Isolate {
		t.Errorf("expected ISOLATE for unknown sink; got %v/%s", d.Verdict, d.Reason)
	}
}

func TestMatrix_AllVendorsClean_PaymentOnUntrusted_CleanSink_Warn(t *testing.T) {
	d := Decide(
		ExternalEvidence{AllVendorsClean: true},
		XGGEvidence{
			TrustedIdentity:           false,
			SinkVerificationAvailable: true,
			CredentialSinkClean:       true,
		},
		ActionPayment,
	)
	if d.Verdict != Warn {
		t.Errorf("untrusted host + clean sink + payment = WARN; got %v/%s", d.Verdict, d.Reason)
	}
}

func TestMatrix_TrustedIdentity_DirtySink_BlocksEvenOnTrustedHost(t *testing.T) {
	d := Decide(
		ExternalEvidence{AllVendorsClean: true},
		XGGEvidence{
			TrustedIdentity:           true,
			SinkVerificationAvailable: true,
			CredentialSinkClean:       false,
		},
		ActionLogin,
	)
	if d.Verdict != Block {
		t.Errorf("trusted host + dirty sink should still BLOCK (compromised page); got %v", d.Verdict)
	}
}

func TestMatrix_TrustedIdentity_CleanSink_Allows(t *testing.T) {
	d := Decide(
		ExternalEvidence{AllVendorsClean: true},
		XGGEvidence{
			TrustedIdentity:           true,
			SinkVerificationAvailable: true,
			CredentialSinkClean:       true,
		},
		ActionLogin,
	)
	if d.Verdict != Allow {
		t.Errorf("trusted host + clean sink = ALLOW; got %v", d.Verdict)
	}
}

// === Install command flows ===

func TestMatrix_OfficialInstallMatch_AllowsOnAnyHost(t *testing.T) {
	d := Decide(
		ExternalEvidence{AllVendorsClean: true},
		XGGEvidence{OfficialInstallMatch: true},
		ActionInstallCommand,
	)
	if d.Verdict != Allow {
		t.Errorf("official install match = ALLOW; got %v", d.Verdict)
	}
}

func TestMatrix_UntrustedInstallCommandBlog_WarnsNotBlocks(t *testing.T) {
	// dev.to / Medium / Substack publishing the official Anthropic install
	// command — host isn't in trustreg, command isn't in installreg's
	// allowed-host list. Should WARN (analyst can verify) not BLOCK.
	d := Decide(
		ExternalEvidence{AllVendorsClean: true},
		XGGEvidence{},
		ActionInstallCommand,
	)
	if d.Verdict != Warn {
		t.Errorf("untrusted-host install blog = WARN; got %v/%s", d.Verdict, d.Reason)
	}
}

func TestMatrix_SuspiciousCommand_OnUntrusted_Warns(t *testing.T) {
	d := Decide(
		ExternalEvidence{AllVendorsClean: true},
		XGGEvidence{SuspiciousCommand: true},
		ActionInstallCommand,
	)
	if d.Verdict != Warn {
		t.Errorf("suspicious command on untrusted = WARN; got %v", d.Verdict)
	}
}

// === Read-only browsing baselines ===

func TestMatrix_NoSignals_AllowsReadOnly(t *testing.T) {
	d := Decide(ExternalEvidence{AllVendorsClean: true}, XGGEvidence{}, ActionRead)
	if d.Verdict != Allow {
		t.Errorf("clean external + read-only = ALLOW; got %v", d.Verdict)
	}
}

func TestMatrix_SingleMediumFeed_OnReadOnly_AdvisoryWarn(t *testing.T) {
	d := Decide(ExternalEvidence{FeedMediumCount: 1}, XGGEvidence{}, ActionRead)
	if d.Verdict != Warn {
		t.Errorf("single medium feed + read-only = advisory WARN; got %v/%s", d.Verdict, d.Reason)
	}
}
