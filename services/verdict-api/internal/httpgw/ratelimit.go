// ratelimit.go — per-ClientID and per-source-IP sliding-window rate limiting
// for the public /v1/check and /v1/command-check endpoints.
//
// Limits (configurable via env):
//   RATE_LIMIT_PER_CLIENT_RPM  default 60   requests/minute per client_id
//   RATE_LIMIT_PER_IP_RPM      default 600  requests/minute per source IP
//
// Implementation: Redis INCR + EXPIRE on a per-minute bucket key.
//   Key: "rl:{kind}:{identity}:{YYYY-MM-DDTHH:MM}" (minute granularity)
//
// Skip rate limiting when s.Rdb == nil (dev/test mode).
// On limit exceeded: HTTP 429 with Retry-After: 60 header.
//
// Body-peek pattern: the handler reads the full body, extracts client_id, then
// restores the body as a fresh io.NopCloser so downstream JSON decoding works
// unchanged.
package httpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xgenguardian/services/verdict-api/internal/metrics"
)

// rateLimitPerClientRPM returns the configured per-client-id limit.
func rateLimitPerClientRPM() int {
	if v := goGetenv("RATE_LIMIT_PER_CLIENT_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 60
}

// rateLimitPerIPRPM returns the configured per-IP limit.
func rateLimitPerIPRPM() int {
	if v := goGetenv("RATE_LIMIT_PER_IP_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 600
}

// sourceIP extracts the first hop from X-Forwarded-For, or falls back to
// RemoteAddr. Only the IP portion is returned (port stripped).
func sourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For: client, proxy1, proxy2 — take the leftmost (client).
		if i := strings.Index(xff, ","); i > 0 {
			xff = strings.TrimSpace(xff[:i])
		} else {
			xff = strings.TrimSpace(xff)
		}
		if xff != "" {
			return xff
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// rlBucketKey returns the Redis key for a rate-limit bucket at the current
// minute. Using wall-clock minute as the bucket means the window is at most
// 2 minutes wide across a boundary — acceptable for our use case.
func rlBucketKey(kind, identity string) string {
	minute := time.Now().UTC().Format("2006-01-02T15:04")
	return fmt.Sprintf("rl:%s:%s:%s", kind, identity, minute)
}

// checkRateLimit increments the counter for key and returns true when the
// caller is within the limit, false when it is exceeded.
func (s *Server) checkRateLimit(ctx context.Context, key string, limit int) bool {
	// Pipeline INCR + EXPIRE so we never leave orphan keys even when EXPIRE
	// is missed due to a crash. TTL is 2 minutes (one bucket + one full minute
	// of overlap) to allow the counter to expire naturally.
	pipe := s.Rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 2*time.Minute)
	if _, err := pipe.Exec(ctx); err != nil {
		// Redis failure: fail-open (don't block legitimate traffic on Redis outage).
		return true
	}
	return incr.Val() <= int64(limit)
}

// rateLimitMiddleware wraps a handler with per-client-id and per-IP rate
// limiting backed by Redis. When s.Rdb is nil (dev mode) the middleware is a
// no-op pass-through.
func (s *Server) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Rdb == nil {
			next(w, r)
			return
		}

		// Peek at the body to extract client_id, then restore it.
		buf, err := io.ReadAll(io.LimitReader(r.Body, 64*1024)) // 64 KB should be way more than the JSON payload
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(buf))

		// Extract client_id without a full parse (fall back to "unknown").
		clientID := "unknown"
		var peek struct {
			ClientID string `json:"client_id"`
		}
		if json.Unmarshal(buf, &peek) == nil && peek.ClientID != "" {
			clientID = peek.ClientID
		}

		ctx := r.Context()
		ip := sourceIP(r)

		// Per-client-id check.
		clientKey := rlBucketKey("cid", clientID)
		if !s.checkRateLimit(ctx, clientKey, rateLimitPerClientRPM()) {
			metrics.RateLimitHitTotal.WithLabelValues("client").Inc()
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"rate limit exceeded","retry_after":60}`, http.StatusTooManyRequests)
			return
		}

		// Per-source-IP check.
		ipKey := rlBucketKey("ip", ip)
		if !s.checkRateLimit(ctx, ipKey, rateLimitPerIPRPM()) {
			metrics.RateLimitHitTotal.WithLabelValues("ip").Inc()
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"rate limit exceeded","retry_after":60}`, http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}
