// coalesce.go — request coalescing for sandbox renders.
//
// Problem: N concurrent /v1/check requests for the same URL would each
// fire a separate sandbox render, multiplying load on the (already
// expensive) Chromium pool by N. fp-bench at concurrency=20 would
// trigger 20 simultaneous renders of the same flaky phishing URL,
// hitting the sandbox semaphore's 429 cap.
//
// Fix: maintain an in-flight map keyed by normalized URL. The FIRST
// request to arrive runs the sandbox call; subsequent requests for the
// same URL block on the same result channel and receive the shared
// (*renderResponse, error). Followers don't even touch the sandbox.
//
// TTL — entries are dropped after 60s regardless of completion so a
// wedged sandbox call can't permanently block new requests for the same
// URL. The follow-ups will trigger a fresh render after the TTL expires.
//
// This is the standard singleflight pattern (golang.org/x/sync/singleflight)
// but we implement it inline to control the TTL semantics and to fit
// directly on the *Server receiver.

package httpgw

import (
	"context"
	"strings"
	"sync"
	"time"
)

// coalesceTTL — maximum time a single inflight entry can block followers.
// If the underlying sandbox call hasn't completed by this point, we treat
// the entry as wedged and let the next caller spawn a fresh render.
const coalesceTTL = 60 * time.Second

type inflightCall struct {
	done       chan struct{}
	resp       *renderResponse
	err        error
	startedAt  time.Time
}

type coalescer struct {
	mu      sync.Mutex
	calls   map[string]*inflightCall
}

func newCoalescer() *coalescer {
	return &coalescer{calls: map[string]*inflightCall{}}
}

// normalizeURLForCoalesce — coalesce key. Lowercases scheme+host, trims
// trailing slash on the path. We deliberately keep query strings AND
// fragments because some phishing kits use distinct query params per
// victim (so they're not really "the same URL" to scan).
func normalizeURLForCoalesce(rawurl string) string {
	s := rawurl
	if i := strings.Index(s, "://"); i > 0 {
		// lowercase scheme + host, keep path/query case-sensitive
		j := strings.IndexAny(s[i+3:], "/?#")
		if j < 0 {
			return strings.ToLower(s)
		}
		head := strings.ToLower(s[:i+3+j])
		tail := s[i+3+j:]
		// trim a trailing slash on a path with no query/fragment.
		// covers both "https://x/" -> "https://x" and "https://x/foo/" -> "https://x/foo".
		if !strings.ContainsAny(tail, "?#") && len(tail) >= 1 && tail[len(tail)-1] == '/' {
			tail = tail[:len(tail)-1]
		}
		return head + tail
	}
	return strings.ToLower(s)
}

// do — runs fn at most once per (key, ttl-window). Concurrent callers
// with the same key block on the first call's completion and receive
// the same result.
//
// fn is called inside the lock-free section, so it can be slow without
// holding up other unrelated keys.
func (c *coalescer) do(
	ctx context.Context,
	key string,
	fn func() (*renderResponse, error),
) (*renderResponse, error) {
	c.mu.Lock()
	if call, ok := c.calls[key]; ok {
		// Existing in-flight call. Treat as wedged if past TTL — drop it
		// and start a fresh one. (Wedged sandbox = noisy bug; we want
		// the system to recover, not stall behind it.)
		if time.Since(call.startedAt) < coalesceTTL {
			c.mu.Unlock()
			// Wait for the leader OR caller's ctx to expire.
			select {
			case <-call.done:
				return call.resp, call.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		// Past TTL: drop the wedged entry, fall through to leader.
		delete(c.calls, key)
	}
	call := &inflightCall{done: make(chan struct{}), startedAt: time.Now()}
	c.calls[key] = call
	c.mu.Unlock()

	// Leader path — run fn and broadcast result.
	call.resp, call.err = fn()
	close(call.done)

	c.mu.Lock()
	// Only remove if we're still the registered call for this key (a
	// later request past TTL could have replaced us — unlikely but safe).
	if c.calls[key] == call {
		delete(c.calls, key)
	}
	c.mu.Unlock()
	return call.resp, call.err
}
