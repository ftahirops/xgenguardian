// store.go — Postgres-backed cache for brand_hosts.
//
// Loads the full brand_hosts table at startup into in-process maps and
// refreshes periodically (Refresh()). Same Trust(host, scope) public API
// as the stub in brandgraph.go.
//
// Two cache shapes for fast lookup:
//
//   exactHosts:   "login.microsoftonline.com" -> []Match (multiple scopes possible)
//   suffixHosts:  "*.googleusercontent.com"   -> []Match (also scope-keyed)
//
// Multiple matches per host are possible because the same host can be
// trusted at multiple scopes (e.g. a host trusted as both login + app).
// Trust() returns the first match whose scope satisfies the request.

package brandgraph

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store — Postgres-backed brandgraph cache.
type Store struct {
	pg         *pgxpool.Pool
	mu         sync.RWMutex
	exact      map[string][]Match
	suffix     map[string][]Match
	loadedAt   time.Time
	loadErrors int
}

// NewStore creates a store and performs an initial load. If the load fails,
// Trust()/IsAnyTrust() fall back to the stub maps in brandgraph.go.
func NewStore(ctx context.Context, pg *pgxpool.Pool) (*Store, error) {
	s := &Store{
		pg:     pg,
		exact:  map[string][]Match{},
		suffix: map[string][]Match{},
	}
	if err := s.Refresh(ctx); err != nil {
		return s, err
	}
	return s, nil
}

// Refresh reloads brand_hosts from Postgres. Safe to call concurrently with
// Trust() lookups — only swaps the maps under write lock.
func (s *Store) Refresh(ctx context.Context) error {
	rows, err := s.pg.Query(ctx, `
		SELECT b.brand_name, bh.host_pattern, bh.scope, bh.confidence
		FROM brand_hosts bh
		JOIN brands b ON b.brand_id = bh.brand_id
	`)
	if err != nil {
		s.mu.Lock()
		s.loadErrors++
		s.mu.Unlock()
		return err
	}
	defer rows.Close()

	nextExact := map[string][]Match{}
	nextSuffix := map[string][]Match{}
	for rows.Next() {
		var brand, pattern, scope, conf string
		if err := rows.Scan(&brand, &pattern, &scope, &conf); err != nil {
			continue
		}
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		m := Match{Brand: strings.ToLower(brand), Scope: Scope(scope), Confidence: conf}
		if strings.HasPrefix(pattern, "*.") {
			// suffix pattern — key by the trailing portion w/o the asterisk dot.
			sfx := strings.TrimPrefix(pattern, "*.")
			nextSuffix[sfx] = append(nextSuffix[sfx], m)
		} else {
			nextExact[pattern] = append(nextExact[pattern], m)
		}
	}

	s.mu.Lock()
	s.exact = nextExact
	s.suffix = nextSuffix
	s.loadedAt = time.Now()
	s.mu.Unlock()
	return nil
}

// LoadedAt — time of last successful refresh. For healthz/debug output.
func (s *Store) LoadedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadedAt
}

// Stats — for diagnostics endpoint.
func (s *Store) Stats() (exactHosts, suffixPatterns int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.exact), len(s.suffix)
}

// trustOnStore — used by package-level Trust() when a global store is set.
func (s *Store) trust(host string, scope Scope) Match {
	h := normalize(host)
	if h == "" {
		return Match{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Exact match first.
	if matches, ok := s.exact[h]; ok {
		for _, m := range matches {
			if m.Scope == ScopeFullTrust || m.Scope == scope {
				return m
			}
		}
	}
	// Suffix patterns: walk from longest to shortest (so .docs.example.com
	// wins over .example.com). Simple linear scan — table is small (hundreds
	// of entries) so this is fine; if it grows past 10k, replace with trie.
	for sfx, matches := range s.suffix {
		if strings.HasSuffix(h, sfx) {
			for _, m := range matches {
				if m.Scope == ScopeFullTrust || m.Scope == scope {
					return m
				}
			}
		}
	}
	return Match{}
}

func (s *Store) isAnyTrust(host string) bool {
	h := normalize(host)
	if h == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.exact[h]; ok {
		return true
	}
	for sfx := range s.suffix {
		if strings.HasSuffix(h, sfx) {
			return true
		}
	}
	return false
}

func (s *Store) brandFor(host string) string {
	h := normalize(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ms, ok := s.exact[h]; ok && len(ms) > 0 {
		return ms[0].Brand
	}
	for sfx, ms := range s.suffix {
		if strings.HasSuffix(h, sfx) && len(ms) > 0 {
			return ms[0].Brand
		}
	}
	return ""
}

// --- package-level store wiring ---
//
// SetStore wires a Postgres-backed Store as the live source for the
// package-level Trust / IsAnyTrust / BrandFor helpers. Callers (verdict-api
// main) instantiate the Store at startup and call SetStore so policy code
// keeps using the simple package API while transparently consulting Postgres.

var (
	gstoreMu sync.RWMutex
	gstore   *Store
)

// SetStore wires the live Postgres-backed cache. Pass nil to revert to
// the stub maps (useful in tests).
func SetStore(s *Store) {
	gstoreMu.Lock()
	gstore = s
	gstoreMu.Unlock()
}

func liveStore() *Store {
	gstoreMu.RLock()
	defer gstoreMu.RUnlock()
	return gstore
}
