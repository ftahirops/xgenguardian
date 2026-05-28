package httpgw

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoalescer_DedupsConcurrentCallsSameKey(t *testing.T) {
	c := newCoalescer()
	var calls int32

	// Slow leader: blocks for 100ms so followers definitely pile up.
	work := func() (*renderResponse, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(100 * time.Millisecond)
		return &renderResponse{Title: "the-result"}, nil
	}

	var wg sync.WaitGroup
	const N = 20
	results := make([]*renderResponse, N)
	for i := 0; i < N; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := c.do(context.Background(), "same-key", work)
			results[i] = r
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected 1 underlying call, got %d", got)
	}
	for i, r := range results {
		if r == nil || r.Title != "the-result" {
			t.Errorf("caller %d got %v, expected the-result", i, r)
		}
	}
}

func TestCoalescer_DistinctKeysIndependent(t *testing.T) {
	c := newCoalescer()
	var calls int32

	work := func() (*renderResponse, error) {
		atomic.AddInt32(&calls, 1)
		return &renderResponse{}, nil
	}
	c.do(context.Background(), "key-a", work)
	c.do(context.Background(), "key-b", work)
	c.do(context.Background(), "key-c", work)
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 distinct calls, got %d", got)
	}
}

func TestCoalescer_CancelDoesntKillLeader(t *testing.T) {
	c := newCoalescer()
	var ranToCompletion int32

	leaderCtx, leaderCancel := context.WithCancel(context.Background())
	followerCtx, followerCancel := context.WithCancel(context.Background())
	defer leaderCancel()

	leaderStarted := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = c.do(leaderCtx, "shared", func() (*renderResponse, error) {
			close(leaderStarted)
			time.Sleep(80 * time.Millisecond)
			atomic.StoreInt32(&ranToCompletion, 1)
			return &renderResponse{}, nil
		})
	}()
	<-leaderStarted

	// Follower starts, then cancels its own ctx. Leader must keep going.
	wg.Add(1)
	followerErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := c.do(followerCtx, "shared", func() (*renderResponse, error) {
			t.Errorf("follower should not run work fn")
			return nil, nil
		})
		followerErr <- err
	}()

	time.Sleep(10 * time.Millisecond)
	followerCancel()

	if err := <-followerErr; err == nil {
		t.Errorf("follower should have gotten ctx.Err()")
	}

	wg.Wait()
	if atomic.LoadInt32(&ranToCompletion) != 1 {
		t.Errorf("leader was killed by follower cancellation")
	}
}

func TestNormalizeURLForCoalesce(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM/Path":        "https://example.com/Path",
		"https://example.com/":            "https://example.com",
		"https://example.com/path?q=1":    "https://example.com/path?q=1",
		"http://example.com":              "http://example.com",
	}
	for in, want := range cases {
		got := normalizeURLForCoalesce(in)
		if got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
