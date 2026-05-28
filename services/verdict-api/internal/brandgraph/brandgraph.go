// Package brandgraph — action-scoped brand-relationship graph.
//
// Successor to internal/trustreg, which stores flat hostname lists per brand.
// brandgraph replaces those with (brand, host_pattern, scope) edges so trust
// can be scoped to the action: `cdn.example.com` trusted as a script source
// is NOT also trusted as a login destination.
//
// State of this package (2026-05-28): SCAFFOLD only. The schema is in
// migration 0009; this file defines the public API and stub implementations
// against the trustreg data so existing call sites keep working during the
// migration. Real Postgres-backed loading + automated brand-discovery
// (CT log harvest, dnstwist, official-website crawl) lands in follow-up
// sessions.
//
// Plan to wire in (next sessions):
//   1. Backfill brand_hosts from trustreg's hardcoded entries (manual source).
//   2. Switch internal/policy + httpgw lookups from trustreg.IsTrusted(host)
//      to brandgraph.Trust(host, scope).
//   3. Add brand-discovery cron: CT log monitor → host candidates →
//      manual-review queue → promote to brand_hosts with source='ct-log'.
//   4. Remove trustreg's flat registry; keep only the env-loaded local entries.
package brandgraph

import "strings"

// Scope — action-context for trust evaluation. New scopes can be added but
// the schema's CHECK constraint also has to grow.
type Scope string

const (
	ScopeFullTrust     Scope = "full-trust"      // canonical brand domain — trusted for all actions
	ScopeLogin         Scope = "login"           // trusted as a destination for auth flows
	ScopePayment       Scope = "payment"         // trusted as a payment-form destination
	ScopeOAuthRedirect Scope = "oauth-redirect"  // trusted as an OAuth callback target
	ScopeScriptSource  Scope = "script-source"   // CDN script delivery — NOT a login sink
	ScopeCDN           Scope = "cdn"             // static asset delivery
	ScopeDocs          Scope = "docs"            // documentation hosts (install commands OK)
	ScopeSupport       Scope = "support"         // support/contact pages
	ScopeApp           Scope = "app"             // user-facing app dashboard
	ScopeAPI           Scope = "api"             // API gateway
)

// Match — result of a lookup. Brand is empty when no edge matches.
type Match struct {
	Brand      string
	Scope      Scope
	Confidence string // "high" | "medium" | "low"
}

// Trust reports whether `host` is trusted FOR `scope`. This is the load-
// bearing function call sites use to decide if an action should be allowed
// without further proof.
//
// Match semantics:
//   - full-trust edge matches every scope query
//   - any other edge matches only the requested scope
//   - host_pattern can be exact or `*.suffix.example`
//
// When a Postgres-backed Store has been wired via SetStore(), Trust()
// consults that. Otherwise it falls back to the in-process stub maps
// below (kept for tests and for the first-boot path before brands have
// been seeded).
func Trust(host string, scope Scope) Match {
	if s := liveStore(); s != nil {
		if m := s.trust(host, scope); m.Brand != "" {
			return m
		}
	}
	h := normalize(host)
	if h == "" {
		return Match{}
	}
	if m, ok := stubLookup[h]; ok {
		// full-trust matches any scope
		if m.Scope == ScopeFullTrust {
			return m
		}
		if m.Scope == scope {
			return m
		}
	}
	for suffix, m := range stubSuffixLookup {
		if strings.HasSuffix(h, suffix) {
			if m.Scope == ScopeFullTrust || m.Scope == scope {
				return m
			}
		}
	}
	return Match{}
}

// IsAnyTrust — convenience for callers that just want "is this host known
// to belong to any brand under any scope?" Used during the transition so
// existing trustreg.IsTrusted(host) call sites can switch with one-line
// edits while we work out scope semantics per call site.
func IsAnyTrust(host string) bool {
	if s := liveStore(); s != nil && s.isAnyTrust(host) {
		return true
	}
	h := normalize(host)
	if h == "" {
		return false
	}
	if _, ok := stubLookup[h]; ok {
		return true
	}
	for suffix := range stubSuffixLookup {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// BrandFor — returns the canonical brand name for any-scope match. Useful
// for log lines and report-page rendering. Empty when no edge matches.
func BrandFor(host string) string {
	if s := liveStore(); s != nil {
		if b := s.brandFor(host); b != "" {
			return b
		}
	}
	h := normalize(host)
	if m, ok := stubLookup[h]; ok {
		return m.Brand
	}
	for suffix, m := range stubSuffixLookup {
		if strings.HasSuffix(h, suffix) {
			return m.Brand
		}
	}
	return ""
}

func normalize(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// stubLookup — minimal in-process seed, used until the Postgres-backed
// loader lands. Mirrors the most-common trustreg entries so policy can
// already call brandgraph.Trust(host, scope) and get the right answer for
// the major brands. Full backfill (75+ brands × multiple scopes) lands
// in the migration follow-up.
//
// Entries here are the canonical brand-domain mappings only. Action-
// scoped edges (CDN, OAuth-redirect, script-source) live in the migration.
var stubLookup = map[string]Match{
	// Anthropic / Claude
	"anthropic.com":         {"anthropic", ScopeFullTrust, "high"},
	"claude.ai":             {"anthropic", ScopeFullTrust, "high"},
	"claude.com":            {"anthropic", ScopeFullTrust, "high"},
	"docs.anthropic.com":    {"anthropic", ScopeDocs, "high"},
	"docs.claude.com":       {"anthropic", ScopeDocs, "high"},
	"platform.claude.com":   {"anthropic", ScopeApp, "high"},
	"console.anthropic.com": {"anthropic", ScopeApp, "high"},
	"console.claude.com":    {"anthropic", ScopeApp, "high"},

	// Google login
	"accounts.google.com": {"google", ScopeLogin, "high"},
	"google.com":          {"google", ScopeFullTrust, "high"},
	"www.google.com":      {"google", ScopeFullTrust, "high"},

	// Microsoft
	"login.microsoftonline.com": {"microsoft", ScopeLogin, "high"},
	"login.live.com":            {"microsoft", ScopeLogin, "high"},
	"microsoft.com":             {"microsoft", ScopeFullTrust, "high"},

	// Apple
	"appleid.apple.com": {"apple", ScopeLogin, "high"},
	"apple.com":         {"apple", ScopeFullTrust, "high"},

	// PayPal
	"paypal.com":         {"paypal", ScopeFullTrust, "high"},
	"www.paypal.com":     {"paypal", ScopeFullTrust, "high"},
	"checkout.paypal.com": {"paypal", ScopePayment, "high"},
}

// stubSuffixLookup — suffix patterns (with the leading dot stripped on
// match). Only narrow, brand-owned suffixes; broad ones like .google.com
// belong in the migrated full-graph because that suffix includes
// sites.google.com (shared hosting, scope = none).
var stubSuffixLookup = map[string]Match{
	".anthropic.com":          {"anthropic", ScopeFullTrust, "high"},
	".claude.com":             {"anthropic", ScopeFullTrust, "high"},
	".claude.ai":              {"anthropic", ScopeFullTrust, "high"},
	".gstatic.com":            {"google", ScopeScriptSource, "high"}, // SCRIPT only, not login
	".googleusercontent.com":  {"google", ScopeCDN, "high"},          // shared CDN, not login
	".googletagmanager.com":   {"google", ScopeScriptSource, "high"},
	".googlevideo.com":        {"google", ScopeCDN, "high"},
}
