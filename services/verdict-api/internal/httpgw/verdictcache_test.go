package httpgw

import (
	"context"
	"testing"
	"time"

	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
)

// TestCacheKeyDeterminism verifies that cacheKeyForURL produces a stable,
// deterministic key for the same URL. Scheme and host are case-folded; path
// case is preserved so that /Login and /login are distinct cache entries.
func TestCacheKeyDeterminism(t *testing.T) {
	url := "https://example.com/login"

	key1 := cacheKeyForURL("verdict:", url)
	key2 := cacheKeyForURL("verdict:", url)
	// Scheme and host uppercased, path lowercased — should equal key1 because
	// only scheme+host differ and those are folded.
	key3SchemeHostUpper := cacheKeyForURL("verdict:", "HTTPS://EXAMPLE.COM/login")
	// Path case differs: /LOGIN vs /login — must NOT equal key1.
	key3PathUpper := cacheKeyForURL("verdict:", "HTTPS://EXAMPLE.COM/LOGIN")
	key4 := cacheKeyForURL("verdict:", "  https://example.com/login  ")

	if key1 != key2 {
		t.Errorf("non-deterministic: key1=%s key2=%s", key1, key2)
	}
	// Scheme+host case folding: same path → same key.
	if key1 != key3SchemeHostUpper {
		t.Errorf("scheme/host case mismatch: key1=%s key3=%s (expected equal)", key1, key3SchemeHostUpper)
	}
	// Path is case-sensitive: /LOGIN ≠ /login → different keys.
	if key1 == key3PathUpper {
		t.Errorf("path case was incorrectly folded: key1=%s key3PathUpper=%s (expected different)", key1, key3PathUpper)
	}
	if key1 != key4 {
		t.Errorf("whitespace mismatch: key1=%s key4=%s (expected equal)", key1, key4)
	}

	// Different URLs must produce different keys.
	other := cacheKeyForURL("verdict:", "https://other.example.com/")
	if key1 == other {
		t.Error("distinct URLs produced the same cache key")
	}

	// Prefix isolation: "verdict:" and "render:" for the same URL must differ.
	renderKey := cacheKeyForURL("render:", url)
	if key1 == renderKey {
		t.Error("different prefixes produced the same cache key")
	}
}

// TestVerdictTTL verifies the TTL mapping for each verdict type.
func TestVerdictTTL(t *testing.T) {
	cases := []struct {
		verdict string
		want    time.Duration
	}{
		{"ALLOW", 6 * time.Hour},
		{"allow", 6 * time.Hour}, // case-insensitive
		{"WARN", 30 * time.Minute},
		{"BLOCK", 24 * time.Hour},
		{"ISOLATE", 1 * time.Hour},
		{"CLEAN", 6 * time.Hour},
		{"UNKNOWN", 15 * time.Minute},
		{"", 15 * time.Minute},
	}
	for _, tc := range cases {
		got := verdictTTL(tc.verdict)
		if got != tc.want {
			t.Errorf("verdictTTL(%q) = %v, want %v", tc.verdict, got, tc.want)
		}
	}
}

// TestSensitivePageClassNeverCache verifies that isSensitivePageClass returns
// true for URLs that must never be served from cache.
func TestSensitivePageClassNeverCache(t *testing.T) {
	sensitive := []string{
		"https://bank.example.com/login",
		"https://bank.example.com/signin",
		"https://bank.example.com/password/reset",
		"https://accounts.example.com/oauth/authorize",
		"https://accounts.example.com/consent",
		"https://store.example.com/payment",
		"https://store.example.com/checkout",
		"https://exchange.example.com/withdraw",
		"https://bank.example.com/mfa",
		"https://bank.example.com/2fa",
	}
	for _, u := range sensitive {
		if !isSensitivePageClass(u) {
			t.Errorf("expected isSensitivePageClass(%q) = true, got false", u)
		}
	}
}

// TestNonSensitivePageClassAllowsCache verifies that non-sensitive URLs are
// eligible for caching.
func TestNonSensitivePageClassAllowsCache(t *testing.T) {
	nonSensitive := []string{
		"https://news.example.com/article/123",
		"https://example.com/",
		"https://docs.example.com/api",
		"https://blog.example.com/post/hello-world",
	}
	for _, u := range nonSensitive {
		if isSensitivePageClass(u) {
			t.Errorf("expected isSensitivePageClass(%q) = false (non-sensitive), got true", u)
		}
	}
}

// TestGetVerdictCacheSkipsParanoid verifies paranoid mode bypasses cache.
func TestGetVerdictCacheSkipsParanoid(t *testing.T) {
	// Nil rdb ensures no Redis I/O; function must return nil for paranoid.
	got := getVerdictCache(context.Background(), nil, "https://example.com/", true, "")
	if got != nil {
		t.Error("expected nil for paranoid=true with nil rdb, got non-nil")
	}
}

// TestGetVerdictCacheSkipsSensitive verifies sensitive page classes bypass cache.
func TestGetVerdictCacheSkipsSensitive(t *testing.T) {
	got := getVerdictCache(context.Background(), nil, "https://bank.example.com/login", false, "")
	if got != nil {
		t.Error("expected nil for login URL with nil rdb, got non-nil")
	}
}

// TestSetVerdictCacheNoOpOnNilRdb ensures setVerdictCache is a no-op when rdb is nil.
func TestSetVerdictCacheNoOpOnNilRdb(t *testing.T) {
	// Should not panic.
	setVerdictCache(nil, "https://example.com/", false, "", checkResponse{
		Verdict:   "ALLOW",
		ScannedAt: time.Now().UTC(),
	})
}

// TestNormalizeURL verifies normalization rules: scheme and host are
// lowercased, but path/query/fragment case is preserved so that
// /Malware.exe and /malware.exe remain distinct cache keys.
func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// Scheme+host folded; path case preserved.
		{"https://EXAMPLE.COM/Path", "https://example.com/Path"},
		// Whitespace trimmed; no path → empty path preserved.
		{"  https://Example.com  ", "https://example.com"},
		// Trailing slash kept.
		{"https://example.com/", "https://example.com/"},
		// Path with mixed case preserved as-is.
		{"https://cdn.example.com/Malware.exe", "https://cdn.example.com/Malware.exe"},
	}
	for _, tc := range cases {
		got := normalizeURL(tc.input)
		if got != tc.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestPageclassConstants verifies the pageclass constants we gate on haven't
// changed their string values (regression guard).
func TestPageclassConstants(t *testing.T) {
	if pageclass.Login != "login" {
		t.Errorf("pageclass.Login changed: %s", pageclass.Login)
	}
	if pageclass.Payment != "payment" {
		t.Errorf("pageclass.Payment changed: %s", pageclass.Payment)
	}
	if pageclass.OAuthConsent != "oauth-consent" {
		t.Errorf("pageclass.OAuthConsent changed: %s", pageclass.OAuthConsent)
	}
	if pageclass.MFA != "mfa" {
		t.Errorf("pageclass.MFA changed: %s", pageclass.MFA)
	}
}

// TestRenderCacheTTL verifies the render TTL selection.
func TestRenderCacheTTL(t *testing.T) {
	// Clean render → 4h
	clean := &renderResponse{}
	if got := renderCacheTTL(clean); got != 4*time.Hour {
		t.Errorf("clean render TTL = %v, want 4h", got)
	}

	// YARA match → 30m
	withYara := &renderResponse{
		YaraMatches: []yaraMatch{{Rule: "malware_dropper", Severity: "high"}},
	}
	if got := renderCacheTTL(withYara); got != 30*time.Minute {
		t.Errorf("yara render TTL = %v, want 30m", got)
	}

	// Risky download → 30m
	withDL := &renderResponse{
		Downloads: []downloadFinding{{URL: "http://evil.example.com/x.exe", Risky: true}},
	}
	if got := renderCacheTTL(withDL); got != 30*time.Minute {
		t.Errorf("risky download render TTL = %v, want 30m", got)
	}

	// nil → 30m
	if got := renderCacheTTL(nil); got != 30*time.Minute {
		t.Errorf("nil render TTL = %v, want 30m", got)
	}
}
