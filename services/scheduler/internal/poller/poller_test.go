package poller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xgenguardian/services/scheduler/internal/drift"
)

type fakeDispatch struct {
	mu   sync.Mutex
	jobs []Job
}

func (f *fakeDispatch) Enqueue(_ context.Context, j Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, j)
	return nil
}

func (f *fakeDispatch) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.jobs)
}

func TestInitialTier(t *testing.T) {
	cases := map[string]drift.Tier{
		"A+": drift.TierLight,
		"A":  drift.TierLight,
		"B":  drift.TierMedium,
		"C":  drift.TierMedium,
		"D":  drift.TierDeep,
		"F":  drift.TierDeep,
		"F+": drift.TierDeep,
		"":   drift.TierDeep, // unknown → deep
	}
	for g, want := range cases {
		if got := initialTier(g); got != want {
			t.Errorf("initialTier(%q) = %s, want %s", g, got, want)
		}
	}
}

func TestRateLimit(t *testing.T) {
	p := New(nil, &fakeDispatch{}).WithRateLimit(50 * time.Millisecond)
	if p.rateLimited("example.com") {
		t.Errorf("first lookup should not be rate-limited")
	}
	p.markSeen("example.com")
	if !p.rateLimited("example.com") {
		t.Errorf("second immediate lookup should be rate-limited")
	}
	time.Sleep(60 * time.Millisecond)
	if p.rateLimited("example.com") {
		t.Errorf("after window expiry should not be rate-limited")
	}
}

func TestRateLimit_EmptyDomain(t *testing.T) {
	p := New(nil, &fakeDispatch{})
	if p.rateLimited("") {
		t.Errorf("empty domain should never rate-limit")
	}
	p.markSeen("") // should be a no-op
	if p.rateLimited("") {
		t.Errorf("still no rate-limit after empty markSeen")
	}
}
