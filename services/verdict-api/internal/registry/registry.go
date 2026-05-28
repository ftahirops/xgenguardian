// Package registry — in-memory brand registry hydrator.
//
// Loads canonical_domains, legitimate_asns, legitimate_issuers, and keywords
// from the `brands` Postgres table at startup, then refreshes every 5 minutes.
// fusion.Score() needs these fields populated to evaluate the identity-mismatch
// rule (§27 #13). Without this hydrator every page looks like impersonation
// because canonical-domain lists are empty.
//
// Lookups are case-insensitive on brand_name; the matcher tolerates the
// short keyword form ("paypal") that visual-match returns.
package registry

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

type Brand struct {
	Name              string
	CanonicalDomains  []string
	LegitimateASNs    []int
	LegitimateIssuers []string
	Keywords          []string
}

type Cache struct {
	pg      *pgxpool.Pool
	mu      sync.RWMutex
	byName  map[string]*Brand // lower-cased brand_name
	byToken map[string]*Brand // lower-cased keyword OR canonical SLD
	loaded  time.Time
}

func New(pg *pgxpool.Pool) *Cache {
	return &Cache{pg: pg, byName: map[string]*Brand{}, byToken: map[string]*Brand{}}
}

// Start begins the periodic refresh loop. Returns after the first successful
// load so callers can rely on a populated cache.
func (c *Cache) Start(ctx context.Context, interval time.Duration) error {
	if err := c.refresh(ctx); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.refresh(ctx); err != nil {
					log.Warn().Err(err).Msg("registry refresh failed")
				}
			}
		}
	}()
	return nil
}

func (c *Cache) refresh(ctx context.Context) error {
	rows, err := c.pg.Query(ctx, `
		SELECT brand_name, canonical_domains, legitimate_asns,
		       legitimate_issuers, keywords
		FROM brands
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	byName := map[string]*Brand{}
	byToken := map[string]*Brand{}

	for rows.Next() {
		b := &Brand{}
		var asns []int32
		if err := rows.Scan(&b.Name, &b.CanonicalDomains, &asns, &b.LegitimateIssuers, &b.Keywords); err != nil {
			log.Warn().Err(err).Msg("brand row scan")
			continue
		}
		for _, a := range asns {
			b.LegitimateASNs = append(b.LegitimateASNs, int(a))
		}
		byName[strings.ToLower(b.Name)] = b

		// Index by keyword and by SLD of each canonical domain.
		for _, k := range b.Keywords {
			byToken[strings.ToLower(strings.TrimSpace(k))] = b
		}
		for _, d := range b.CanonicalDomains {
			byToken[sld(d)] = b
		}
	}

	c.mu.Lock()
	c.byName = byName
	c.byToken = byToken
	c.loaded = time.Now()
	c.mu.Unlock()

	log.Info().Int("brands", len(byName)).Msg("brand registry hydrated")
	return nil
}

// Lookup resolves an arbitrary visual-match brand label (which may be a
// brand_name like "PayPal" or a keyword like "paypal" or a domain SLD like
// "paypal") to the full Brand record. Returns nil if not found.
func (c *Cache) Lookup(token string) *Brand {
	if token == "" {
		return nil
	}
	key := strings.ToLower(strings.TrimSpace(token))
	c.mu.RLock()
	defer c.mu.RUnlock()
	if b, ok := c.byName[key]; ok {
		return b
	}
	if b, ok := c.byToken[key]; ok {
		return b
	}
	// Try the SLD form too (callers sometimes pass full domains).
	if b, ok := c.byToken[sld(key)]; ok {
		return b
	}
	return nil
}

// AllKeywords returns every brand keyword + canonical SLD for use by
// homoglyph / CT-monitor / Tier-1 string matchers. Returns a fresh copy.
func (c *Cache) AllKeywords() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.byToken))
	seen := map[string]struct{}{}
	for k := range c.byToken {
		if len(k) < 4 {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// LoadedAt — for /healthz reporting.
func (c *Cache) LoadedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded
}

// sld — return the second-level domain portion: "www.paypal.com" → "paypal".
// Cheap heuristic, good enough for matching.
func sld(domain string) string {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return d
	}
	return parts[len(parts)-2]
}
