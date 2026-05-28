// codes.go — mapping from fusion.Signal.Name (lowercase tokens emitted by
// the fusion engine) to canonical reasons.Code. Keeping the mapping local to
// the gateway means fusion stays a pure scorer; the gateway is the layer
// that talks to the outside world and owns the public taxonomy.
//
// New fusion signal names MUST be added here as new detectors land, or
// blocked.html will fall back to the ad-hoc signal name with no human
// description.

package httpgw

import (
	"strings"

	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

// signalToCode maps the lowercase fusion signal name to a canonical reason.
// Returning empty Code means "no canonical mapping" — caller should keep
// the raw signal in evidence.signals for analysts but not surface it as a
// user-visible reason.
var signalToCode = map[string]reasons.Code{
	"blocklist_hit":           reasons.ExternalFeedHit,
	"visual_brand_match":      reasons.BrandClaimDomainMismatch,
	"visual_brand_match_weak": reasons.FaviconBrandMismatch,
	"identity_mismatch":       reasons.BrandClaimDomainMismatch,
	"favicon_brand_match":     reasons.FaviconBrandMismatch,
	"cred_form_cross_origin":  reasons.FormPostsToUnrelatedDomain,
	"risky_downloads":         reasons.RiskyDownloadLinked,
	"domain_age":              reasons.DomainAgeUnderThreshold,
	"gsb_unsafe":              reasons.GoogleWebRiskUnsafe,
	"vt_positives":            reasons.VirusTotalPositive,
	"homoglyph":               reasons.HomoglyphOfProtectedBrand,
	"levenshtein":             reasons.HomoglyphOfProtectedBrand,
	"combosquat":              reasons.HomoglyphOfProtectedBrand,
	"cert_age":                reasons.CertDriftOnTrustedPage,
	"lexical_credential_path": reasons.LoginFormOnUnapprovedDomain,

	// Behavioural-abuse signals (Phase 2 §5.2).
	"behavior_popup_storm":         reasons.PopupStormDetected,
	"behavior_alert_loop":          reasons.AlertLoopDetected,
	"behavior_fullscreen_trap":     reasons.FullscreenTrapDetected,
	"behavior_beforeunload":        reasons.BeforeUnloadAbuse,
	"behavior_clipboard_hijack":    reasons.ClipboardHijackAttempt,
	"behavior_auto_download":       reasons.AutoDownloadTrigger,
	"behavior_scareware_composite": reasons.FakeSupportScareware,

	// DGA classifier (this pipeline-push).
	"dga_classifier_hit": reasons.DGAClassifierHit,

	// Direct-download URL — Chromium can't render, fallback signal.
	"direct_download_url": reasons.RiskyDownloadLinked,

	// Raw-IP host signals — commodity malware / Mirai-style botnet drops.
	"raw_ip_host":         reasons.RawIPHost,
	"raw_ip_binary_drop":  reasons.MalwareRawIPBinaryDrop,

	// OAuth client_id reputation (§16.4).
	"oauth_unknown_client": reasons.OAuthUnknownClientID,
}

// codesFromFusion produces the deduplicated reason-code list for an output.
// Order preserved from the fusion signal order so the first/strongest signal
// surfaces first in the UI.
//
// YARA-sourced signals (prefix "yara_") fall back to YARA_SIGNATURE_MATCH
// when fusion-pipeline can't see the rule-declared reason_code. The
// caller (pipeline.go) is responsible for splicing in the per-rule
// reason_code where it has access to the renderResponse.
func codesFromFusion(out fusion.Output) []string {
	seen := map[string]struct{}{}
	codes := make([]string, 0, len(out.Signals))
	for _, s := range out.Signals {
		var code string
		if c, ok := signalToCode[s.Name]; ok {
			code = string(c)
		} else if strings.HasPrefix(s.Name, "yara_") {
			code = string(reasons.YaraSignatureMatch)
		} else {
			continue
		}
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
	}
	return codes
}

// codesFromYaraMatches converts the rule-declared reason_code on each YARA
// match into the canonical reason set. Falls back to YARA_SIGNATURE_MATCH
// if the rule didn't declare one or declared an unknown code.
//
// Called by pipeline.go *after* codesFromFusion so per-rule reasons override
// the generic YARA_SIGNATURE_MATCH for the same finding.
func codesFromYaraMatches(matches []yaraMatch) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		code := m.ReasonCode
		if code == "" || !reasons.IsKnown(reasons.Code(code)) {
			code = string(reasons.YaraSignatureMatch)
		}
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	return out
}
