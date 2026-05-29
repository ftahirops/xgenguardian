// Package internalauth provides shared-secret middleware and outbound-request
// helpers for inter-service authentication (Architecture Audit Finding #3).
//
// All inter-service receivers call Middleware to validate the X-Internal-Token
// header. All inter-service senders call AddToken to attach it.
//
// Token is read from XGG_INTERNAL_TOKEN at startup. When the env var is empty
// the middleware runs in dev mode: it allows every request but logs a warning
// on every call so operators notice the gap.
package internalauth

import (
	"crypto/subtle"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Header is the request header name carrying the shared secret.
const Header = "X-Internal-Token"

var (
	tokenOnce  sync.Once
	tokenBytes []byte // nil means "dev mode — no token set"

	// devWarnLastNs is the last Unix-nanosecond a dev-mode warning was logged.
	// Rate-limits to one warning per minute so it stays visible without flooding.
	devWarnLastNs atomic.Int64
)

func loadToken() {
	tokenOnce.Do(func() {
		v := os.Getenv("XGG_INTERNAL_TOKEN")
		if v == "" {
			log.Warn().Msg("internalauth: XGG_INTERNAL_TOKEN is not set — inter-service auth DISABLED (dev mode)")
			tokenBytes = nil
		} else {
			tokenBytes = []byte(v)
		}
	})
}

// Middleware returns an HTTP middleware that validates X-Internal-Token on
// every request that is NOT a healthz probe.
//
// Behaviour:
//   - XGG_INTERNAL_TOKEN unset → allow all, log a rate-limited warning.
//   - XGG_INTERNAL_TOKEN set, header matches (constant-time) → allow.
//   - XGG_INTERNAL_TOKEN set, header absent or wrong → 401 Unauthorized.
func Middleware(next http.Handler) http.Handler {
	loadToken()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Operational probes are always allowed, no credentials needed.
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		if tokenBytes == nil {
			// Dev mode: emit at most one warning per minute.
			now := time.Now().UnixNano()
			last := devWarnLastNs.Load()
			if now-last > int64(time.Minute) && devWarnLastNs.CompareAndSwap(last, now) {
				log.Warn().Str("path", r.URL.Path).
					Msg("internalauth: XGG_INTERNAL_TOKEN unset — request allowed in dev mode")
			}
			next.ServeHTTP(w, r)
			return
		}

		got := r.Header.Get(Header)
		if subtle.ConstantTimeCompare([]byte(got), tokenBytes) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AddToken attaches the shared-secret header to an outbound request.
// Call this before every inter-service HTTP call.
func AddToken(req *http.Request) {
	loadToken()
	if tokenBytes != nil {
		req.Header.Set(Header, string(tokenBytes))
	}
}
