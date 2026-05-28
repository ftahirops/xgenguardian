// Package poller drives the trust-registry revalidation loop
// (UNIFIED-PLAN.md §6, §4.3, §4.4).
//
//	Every interval:
//	  1. Select up to `batch` URLs with next_rescan_at <= NOW() ordered by
//	     priority (grade × age).
//	  2. Apply per-domain rate limit (max 1 / domain / 30s).
//	  3. Enqueue a revalidation job at the tier dictated by the grade.
//
// The actual scan execution lives in verdict-api + sandbox-render. The
// scheduler is the conductor; it does not call Playwright or render itself.
package poller

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/scheduler/internal/drift"
)

// Job is a single revalidation work item handed off to the verdict-api
// scan dispatcher (over an internal queue or HTTP POST — left to the wiring).
type Job struct {
	URL       string
	URLHash   []byte
	Domain    string
	Grade     string
	PageClass string
	Tier      drift.Tier
	Reason    string // "ttl_expired" | "drift:cert,form" | "manual"
}

// Dispatcher abstracts whatever consumes Jobs. In production this is an
// HTTP client posting to verdict-api/scan or a Redis stream producer.
type Dispatcher interface {
	Enqueue(ctx context.Context, j Job) error
}

// Poller wraps the loop state.
type Poller struct {
	pg         *pgxpool.Pool
	dispatch   Dispatcher
	batch      int
	interval   time.Duration
	rateLimit  time.Duration // per-domain min interval between scans

	mu        sync.Mutex
	lastByDom map[string]time.Time
}

// New builds a Poller. Sensible defaults: batch 100, interval 30s,
// per-domain rate limit 30s.
func New(pg *pgxpool.Pool, dispatch Dispatcher) *Poller {
	return &Poller{
		pg:        pg,
		dispatch:  dispatch,
		batch:     100,
		interval:  30 * time.Second,
		rateLimit: 30 * time.Second,
		lastByDom: map[string]time.Time{},
	}
}

// WithBatch configures the per-tick row limit.
func (p *Poller) WithBatch(n int) *Poller { p.batch = n; return p }

// WithInterval configures the tick rate.
func (p *Poller) WithInterval(d time.Duration) *Poller { p.interval = d; return p }

// WithRateLimit configures the per-domain throttle.
func (p *Poller) WithRateLimit(d time.Duration) *Poller { p.rateLimit = d; return p }

// Run blocks until ctx is done. One sweep at startup, then on each tick.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	p.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.tick(ctx)
		}
	}
}

func (p *Poller) tick(ctx context.Context) {
	rows, err := p.pg.Query(ctx, `
		SELECT u.url_hash, u.url, u.domain, COALESCE(u.grade, ''), COALESCE(u.page_class, 'generic')
		FROM urls u
		WHERE u.next_rescan_at IS NOT NULL
		  AND u.next_rescan_at <= NOW()
		ORDER BY
		  CASE u.grade
		    WHEN 'D' THEN 0
		    WHEN 'C' THEN 1
		    WHEN 'B' THEN 2
		    WHEN 'F' THEN 3
		    WHEN 'A' THEN 4
		    WHEN 'A+' THEN 5
		    ELSE 6
		  END,
		  u.next_rescan_at
		LIMIT $1
	`, p.batch)
	if err != nil {
		log.Warn().Err(err).Msg("poller query")
		return
	}
	defer rows.Close()

	dispatched := 0
	skipped := 0
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.URLHash, &j.URL, &j.Domain, &j.Grade, &j.PageClass); err != nil {
			log.Warn().Err(err).Msg("poller scan")
			continue
		}
		if p.rateLimited(j.Domain) {
			skipped++
			continue
		}
		j.Tier = initialTier(j.Grade)
		j.Reason = "ttl_expired"
		if err := p.dispatch.Enqueue(ctx, j); err != nil {
			log.Warn().Err(err).Str("url", j.URL).Msg("dispatch")
			continue
		}
		p.markSeen(j.Domain)
		dispatched++
	}
	if dispatched > 0 || skipped > 0 {
		log.Info().Int("dispatched", dispatched).Int("rate_limited", skipped).Msg("poller tick")
	}
}

func (p *Poller) rateLimited(domain string) bool {
	if domain == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	last, ok := p.lastByDom[domain]
	if !ok {
		return false
	}
	return time.Since(last) < p.rateLimit
}

func (p *Poller) markSeen(domain string) {
	if domain == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastByDom[domain] = time.Now()
	// Cheap GC: drop entries older than 2× rate limit.
	if len(p.lastByDom) > 10000 {
		cutoff := time.Now().Add(-2 * p.rateLimit)
		for k, v := range p.lastByDom {
			if v.Before(cutoff) {
				delete(p.lastByDom, k)
			}
		}
	}
}

// initialTier picks the starting revalidation tier for a TTL-driven scan.
// Drift detection inside verdict-api may force a tier-up afterwards.
//
//	A+ / A : light  — strong history, only fingerprint-diff needed.
//	B / C  : medium — HTML-lite fetch.
//	D / F+ : deep   — already suspicious; do the full thing.
func initialTier(grade string) drift.Tier {
	switch grade {
	case "A+", "A":
		return drift.TierLight
	case "B", "C":
		return drift.TierMedium
	}
	return drift.TierDeep
}
