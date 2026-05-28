// pipeline_legacy.go — pre-staged-policy decision path.
//
// This is the exact decision logic that lived inline in runPipelineWithTier
// before Package 7 (the staged-policy cutover). Kept behind the
// USE_LEGACY_POLICY env flag as a panic button during the migration.
// Remove once the new policy engine has been live in production for a
// release cycle.
package httpgw

import (
	"time"

	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/oauthreg"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
	"github.com/xgenguardian/services/verdict-api/internal/strictness"
)

// legacyDecision reproduces the old fusion-then-strictness flow exactly.
// Returns the same 7-tuple the new path produces so callers don't branch.
//
// Don't add new logic here. Add to internal/policy/policy.go.
func legacyDecision(
	req checkRequest,
	in fusion.Inputs,
	outOrig fusion.Output,
	render *renderResponse,
	feedSources []string,
	oauthDec *oauthreg.Decision,
) (verdict string, codes []string, blockReason string, strictnessApplied bool, confidence float64, pageClass string, grade string) {
	out := outOrig

	isChallenge := render != nil && render.IsChallengePage
	if isChallenge && out.Verdict == "CLEAN" {
		out.Verdict = "ISOLATE"
		out.Reason = "Bot-protection challenge prevented a full scan — opening in isolation."
		out.Signals = append(out.Signals, fusion.Signal{
			Name:   "bot_protection_challenge",
			Weight: 0,
			Detail: render.ChallengeKind,
		})
	}

	if oauthDec != nil && !oauthDec.Known && oauthDec.SuspiciousScopes {
		out.Verdict = "BLOCK"
		out.Reason = "OAuth consent for an unverified app requesting sensitive permissions."
		out.Signals = append(out.Signals, fusion.Signal{
			Name:   "oauth_unknown_client",
			Weight: 0.6,
			Detail: oauthDec.Provider + " client_id=" + oauthDec.ClientID,
		})
	}

	codes = codesFromFusion(out)
	if isChallenge {
		codes = append(codes, string(reasons.CloakingDivergence))
	}
	if len(feedSources) > 0 {
		codes = append(codes, string(reasons.ExternalFeedHit))
	}

	if render != nil && len(render.YaraMatches) > 0 {
		yaraCodes := codesFromYaraMatches(render.YaraMatches)
		seen := map[string]struct{}{}
		for _, c := range codes {
			seen[c] = struct{}{}
		}
		hasSpecific := false
		for _, c := range yaraCodes {
			if c != string(reasons.YaraSignatureMatch) {
				hasSpecific = true
				break
			}
		}
		if hasSpecific {
			pruned := make([]string, 0, len(codes))
			for _, c := range codes {
				if c == string(reasons.YaraSignatureMatch) {
					continue
				}
				pruned = append(pruned, c)
			}
			codes = pruned
			seen = map[string]struct{}{}
			for _, c := range codes {
				seen[c] = struct{}{}
			}
		}
		for _, c := range yaraCodes {
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			codes = append(codes, c)
		}
	}

	pageClass = pageClassOf(req.URL)
	grade = chooseGrade(out.Verdict, out.Confidence)
	strictResult := strictness.Apply(strictness.Inputs{
		RawVerdict: strictness.Verdict(out.Verdict),
		Grade:      strictness.Grade(grade),
		PageClass:  pageClass,
	}, strictness.Policy{
		Paranoid: req.Paranoid,
		Now:      time.Now(),
	})
	verdict = string(strictResult.Verdict)
	strictnessApplied = strictResult.StrictnessApplied
	confidence = out.Confidence
	blockReason = out.Reason
	if strictnessApplied {
		codes = append(codes, string(reasons.BlockedByStrictnessPolicy))
	}
	return
}
