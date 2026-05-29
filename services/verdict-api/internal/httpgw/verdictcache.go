// verdictcache.go — Redis-backed verdict and render result caches.
//
// Cache 1 (verdict cache): caches the full checkResponse for a normalized URL.
//   Key:  "verdict:" + sha256hex(normalizeURL(url))
//   TTL:  per-verdict (ALLOW=6h, WARN=30m, BLOCK=24h, ISOLATE=1h, CLEAN=6h, default=15m)
//   Skip: paranoid mode, sensitive page classes (Login, Payment, OAuth, Admin/MFA/etc.)
//
// Cache 2 (render cache): caches the sandbox renderResponse for a normalized URL.
//   Key:  "render:" + sha256hex(normalizeURL(url))
//   Also: "render:domain:" + sha256hex(domain) for non-sensitive paths.
//   TTL:  4h for clean/ALLOW results, 30m when threats were detected.
//   Skip: IsChallengePage=true
package httpgw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/metrics"
	"github.com/xgenguardian/services/verdict-api/internal/pageclass"
)

// verdictTTL returns the Redis TTL for a given verdict string.
func verdictTTL(verdict string) time.Duration {
	switch strings.ToUpper(verdict) {
	case "ALLOW":
		return 6 * time.Hour
	case "WARN":
		return 30 * time.Minute
	case "BLOCK":
		return 24 * time.Hour
	case "ISOLATE":
		return 1 * time.Hour
	case "CLEAN":
		return 6 * time.Hour
	default:
		return 15 * time.Minute
	}
}

// normalizeURL returns a trimmed URL with scheme and host lowercased, but with
// the path, query string, and fragment preserved as-is. Only lowercasing the
// scheme+host ensures that case-sensitive paths (e.g. /Malware.exe vs
// /malware.exe) produce distinct cache keys.
func normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL) // fallback for unparseable URLs
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// cacheKeyForURL returns the sha256-hex cache key for a normalized URL.
func cacheKeyForURL(prefix, rawURL string) string {
	normalized := normalizeURL(rawURL)
	h := sha256.Sum256([]byte(normalized))
	return prefix + hex.EncodeToString(h[:])
}

// isSensitivePageClass returns true for page classes that must never be cached.
// We never cache Login, Payment, OAuth, MFA, PasswordStep, or Admin-equivalent
// classes — these pages must always be re-verified.
func isSensitivePageClass(rawURL string) bool {
	cls := pageclass.FromURL(rawURL)
	switch cls {
	case pageclass.Login, pageclass.PasswordStep, pageclass.MFA,
		pageclass.OAuthConsent, pageclass.Payment, pageclass.CryptoWithdrawal:
		return true
	}
	return false
}

// isNonSensitivePath returns true when the URL path is NOT login/payment/oauth.
// Used for domain-level render cache lookups.
func isNonSensitivePath(rawURL string) bool {
	return !isSensitivePageClass(rawURL)
}

// getVerdictCache checks Redis for a cached checkResponse. Returns nil if not
// found, on any error, or when the request should skip caching (paranoid, sensitive class).
// ctx is the request context; if it is cancelled (e.g. client disconnects or
// the request deadline fires) the Redis GET is aborted rather than hanging.
func getVerdictCache(ctx context.Context, rdb *redis.Client, rawURL string, paranoid bool, mode string) *checkResponse {
	if rdb == nil {
		return nil
	}
	if paranoid {
		return nil
	}
	// Ultra mode never reads cache — every check goes through the full
	// clearance gate (Phase 5). Cache pollution between modes is the
	// other reason: a Safe-mode ALLOW for example.com shouldn't be
	// served to an Ultra-mode caller that needs a per-gate clearance.
	if strings.EqualFold(mode, "ultra") {
		return nil
	}
	if isSensitivePageClass(rawURL) {
		return nil
	}

	key := cacheKeyForURL("verdict:", rawURL)
	val, err := rdb.Get(ctx, key).Bytes()
	if err != nil {
		// redis.Nil = cache miss; other errors = fail-open
		if err != redis.Nil {
			metrics.RedisErrorsTotal.WithLabelValues("GET").Inc()
		}
		return nil
	}

	var resp checkResponse
	if err := json.Unmarshal(val, &resp); err != nil {
		log.Warn().Err(err).Str("key", key).Msg("verdictcache: unmarshal failed")
		return nil
	}
	// Mark as cached; ScannedAt retains the original scan time so callers can
	// compute "last scanned X ago".
	resp.Cached = true
	return &resp
}

// setVerdictCache writes a checkResponse to Redis with the appropriate TTL.
// Silently skips when conditions for caching are not met.
func setVerdictCache(rdb *redis.Client, rawURL string, paranoid bool, mode string, resp checkResponse) {
	if rdb == nil {
		return
	}
	// Paranoid mode produces ISOLATE/BLOCK results based on stricter rules.
	// We write BLOCK/ISOLATE/WARN to the cache (every future user benefits
	// from a paranoid-mode detection) but skip writing paranoid-ALLOW
	// (the ALLOW depended on paranoid-mode policy and shouldn't bleed into
	// normal-mode reads).
	if paranoid && (resp.Verdict == "ALLOW" || resp.Verdict == "CLEAN") {
		return
	}
	// Ultra mode: same logic — write BLOCK/ISOLATE/WARN so other users
	// benefit, but never write Ultra-ALLOW (it depended on the full
	// clearance gate which is mode-specific).
	if strings.EqualFold(mode, "ultra") && (resp.Verdict == "ALLOW" || resp.Verdict == "CLEAN") {
		return
	}
	if isSensitivePageClass(rawURL) {
		return
	}

	ttl := verdictTTL(resp.Verdict)
	key := cacheKeyForURL("verdict:", rawURL)
	ctx := context.Background()

	data, err := json.Marshal(resp)
	if err != nil {
		log.Warn().Err(err).Str("url", rawURL).Msg("verdictcache: marshal failed")
		return
	}
	if err := rdb.Set(ctx, key, data, ttl).Err(); err != nil {
		log.Warn().Err(err).Str("key", key).Msg("verdictcache: set failed")
		metrics.RedisErrorsTotal.WithLabelValues("SET").Inc()
	}
}

// renderCacheTTL returns the TTL for a render result based on whether threats
// were detected in the render.
func renderCacheTTL(r *renderResponse) time.Duration {
	if r == nil {
		return 30 * time.Minute
	}
	// If YARA matches or risky downloads present, use shorter TTL.
	if len(r.YaraMatches) > 0 {
		return 30 * time.Minute
	}
	n, _ := riskyDownloads(r.Downloads)
	if n > 0 {
		return 30 * time.Minute
	}
	return 4 * time.Hour
}

// getRenderCache checks Redis for a cached renderResponse. Checks URL-level
// first, then domain-level (only for non-sensitive paths).
// ctx is the request context so Redis GETs are bounded by the request deadline.
func getRenderCache(ctx context.Context, rdb *redis.Client, rawURL, domain string) *renderResponse {
	if rdb == nil {
		return nil
	}

	// URL-level lookup.
	urlKey := cacheKeyForURL("render:", rawURL)
	if val, err := rdb.Get(ctx, urlKey).Bytes(); err == nil {
		var r renderResponse
		if err := json.Unmarshal(val, &r); err == nil {
			return &r
		}
		log.Warn().Err(err).Str("key", urlKey).Msg("rendercache: unmarshal failed")
	}

	// Domain-level lookup (only when path is not sensitive).
	if isNonSensitivePath(rawURL) && domain != "" {
		domKey := cacheKeyForURL("render:domain:", domain)
		if val, err := rdb.Get(ctx, domKey).Bytes(); err == nil {
			var r renderResponse
			if err := json.Unmarshal(val, &r); err == nil {
				return &r
			}
			log.Warn().Err(err).Str("key", domKey).Msg("rendercache: domain unmarshal failed")
		}
	}

	return nil
}

// setRenderCache stores a renderResponse in Redis at URL and domain keys.
// Never caches challenge pages.
func setRenderCache(rdb *redis.Client, rawURL, domain string, r *renderResponse) {
	if rdb == nil || r == nil {
		return
	}
	if r.IsChallengePage {
		return
	}

	ttl := renderCacheTTL(r)
	ctx := context.Background()

	data, err := json.Marshal(r)
	if err != nil {
		log.Warn().Err(err).Str("url", rawURL).Msg("rendercache: marshal failed")
		return
	}

	// URL-level key.
	urlKey := cacheKeyForURL("render:", rawURL)
	if err := rdb.Set(ctx, urlKey, data, ttl).Err(); err != nil {
		log.Warn().Err(err).Str("key", urlKey).Msg("rendercache: url set failed")
		metrics.RedisErrorsTotal.WithLabelValues("SET").Inc()
	}

	// Domain-level key (only for non-sensitive paths).
	if isNonSensitivePath(rawURL) && domain != "" {
		domKey := cacheKeyForURL("render:domain:", domain)
		if err := rdb.Set(ctx, domKey, data, ttl).Err(); err != nil {
			log.Warn().Err(err).Str("key", domKey).Msg("rendercache: domain set failed")
			metrics.RedisErrorsTotal.WithLabelValues("SET").Inc()
		}
	}
}
