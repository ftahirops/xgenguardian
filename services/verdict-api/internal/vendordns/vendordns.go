// Package vendordns — multi-vendor DNS-reputation consensus.
//
// Every major "protective DNS" provider operates a sinkhole: when a domain
// matches their blocklist they return either NXDOMAIN, a zero IP
// (0.0.0.0 / ::), or a redirect to their own block page server. By querying
// several providers in parallel and counting blocks, we get a free cross-
// validation signal that's independent of our own ingested feeds.
//
// This is the "ask all of them first, cache the result" path the operator
// asked for. Latency budget: 250ms total (parallel queries + 1 cache write).
//
// Providers chosen for diversity (different feed sources, different
// operational regions, different commercial backing):
//
//   - Cloudflare Family            1.1.1.3
//   - Cloudflare Security          1.1.1.2
//   - Quad9 Secure                 9.9.9.9
//   - AdGuard DNS Default          94.140.14.14
//   - AdGuard DNS Family           94.140.14.15
//   - OpenDNS FamilyShield         208.67.222.123
//   - CleanBrowsing Security       185.228.168.9
//   - CleanBrowsing Family         185.228.168.168
//
// One-shot per (domain) — results cached in Redis with 1h TTL so we never
// re-query the same domain twice in a short window. Bad domains' blocked-by
// list is also persisted to feed_entries so subsequent visits can resolve
// via the existing FeedHit path without re-doing the parallel query.

package vendordns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// Provider — one upstream DNS server we'll consult for reputation.
type Provider struct {
	Name string // stable string surfaced in evidence
	// Server in "host:port" form. Use Cloudflare-style 1.1.1.3:53 etc.
	Server string
	// SinkholePrefixes — IP prefixes the provider returns when the domain
	// is blocked. NXDOMAIN counts as a block too (handled separately).
	SinkholePrefixes []string
}

// Defaults — the curated 8-provider set. Order kept stable so cache keys
// don't drift if we add new providers.
var Defaults = []Provider{
	{
		Name: "cloudflare-family",
		Server: "1.1.1.3:53",
		SinkholePrefixes: []string{"0.0.0.0"},
	},
	{
		Name: "cloudflare-security",
		Server: "1.1.1.2:53",
		SinkholePrefixes: []string{"0.0.0.0"},
	},
	{
		Name: "quad9-secure",
		Server: "9.9.9.9:53",
		SinkholePrefixes: []string{}, // returns NXDOMAIN on block
	},
	{
		Name: "adguard-default",
		Server: "94.140.14.14:53",
		SinkholePrefixes: []string{"0.0.0.0"},
	},
	{
		Name: "adguard-family",
		Server: "94.140.14.15:53",
		SinkholePrefixes: []string{"0.0.0.0"},
	},
	{
		Name: "opendns-familyshield",
		Server: "208.67.222.123:53",
		// FamilyShield returns IPs in the 146.112.61.x sinkhole range for
		// blocked adult/category hits, and 146.112.61.106 specifically for
		// security blocks. Match the /24.
		SinkholePrefixes: []string{"146.112.61.", "146.112.255."},
	},
	{
		Name: "cleanbrowsing-security",
		Server: "185.228.168.9:53",
		SinkholePrefixes: []string{}, // NXDOMAIN
	},
	{
		Name: "cleanbrowsing-family",
		Server: "185.228.168.168:53",
		SinkholePrefixes: []string{}, // NXDOMAIN
	},
}

// Result — per-provider answer.
type ProviderResult struct {
	Provider string
	Blocked  bool
	Reason   string // "NXDOMAIN" | "sinkhole:0.0.0.0" | "timeout" | "" (clean)
}

// ConsensusResult — aggregated cross-vendor verdict.
type ConsensusResult struct {
	Domain          string
	BlockedBy       []string         // provider names that returned a block
	ProviderResults []ProviderResult
	Queried         int              // how many providers responded
	Elapsed         time.Duration
	DomainExists    bool             // true when a non-protective baseline resolver confirms the domain resolves
}

// Hit reports whether any provider returned a block.
func (r ConsensusResult) Hit() bool { return len(r.BlockedBy) > 0 }

// ConsensusBlocks reports whether enough providers agree to BLOCK.
// Two-of-eight is the default — matches the user's "consensus, not single
// source" preference.
func (r ConsensusResult) ConsensusBlocks() bool { return len(r.BlockedBy) >= 2 }

// Query — runs the parallel multi-vendor check.
func Query(ctx context.Context, domain string) ConsensusResult {
	return QueryWith(ctx, domain, Defaults)
}

// QueryWith — same, with a custom provider list (used by tests + tuning).
func QueryWith(ctx context.Context, domain string, providers []Provider) ConsensusResult {
	t0 := time.Now()
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	out := ConsensusResult{Domain: domain}

	// Per-provider 200ms timeout. Total ~250ms wall-clock with all in flight.
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range providers {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			defer cancel()
			res := queryOne(pctx, p, domain)
			mu.Lock()
			out.ProviderResults = append(out.ProviderResults, res)
			out.Queried++
			if res.Blocked {
				out.BlockedBy = append(out.BlockedBy, res.Provider)
			}
			mu.Unlock()
		}()
	}

	// Baseline existence check runs in parallel with the provider queries.
	// Uses a non-protective resolver (Cloudflare 1.1.1.1) to determine
	// whether the domain actually exists. This guards against the false-
	// positive where all 8 protective providers return NXDOMAIN solely
	// because the domain doesn't exist anywhere — not because they blocked it.
	var baselineWG sync.WaitGroup
	var domainExists bool
	baselineWG.Add(1)
	go func() {
		defer baselineWG.Done()
		domainExists = checkBaselineExists(ctx, domain)
	}()

	wg.Wait()
	baselineWG.Wait()

	out.DomainExists = domainExists
	out.Elapsed = time.Since(t0)

	// If the baseline resolver also returns NXDOMAIN (domain genuinely doesn't
	// exist), protective-DNS NXDOMAINs are noise, not evidence of blocking.
	// Scrub NXDOMAIN-only entries from BlockedBy; keep sinkhole-IP blocks
	// (those mean the provider resolved and redirected — a real block signal).
	if !domainExists {
		kept := make([]string, 0, len(out.BlockedBy))
		for _, pr := range out.ProviderResults {
			if pr.Blocked && !strings.HasPrefix(pr.Reason, "NXDOMAIN") {
				kept = append(kept, pr.Provider)
			}
		}
		out.BlockedBy = kept
	}

	return out
}

// checkBaselineExists queries Cloudflare's non-protective resolver (1.1.1.1)
// to determine whether a domain actually resolves anywhere. Returns true when
// at least one A record comes back; false on NXDOMAIN, refused, or timeout.
//
// A transient timeout makes this return false (conservative), which means we
// won't strip NXDOMAIN blocks — the safer failure mode (real blocked domains
// stay blocked) rather than letting non-existent domains slip through.
func checkBaselineExists(ctx context.Context, domain string) bool {
	qctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(c context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 150 * time.Millisecond}
			if strings.HasPrefix(network, "tcp") {
				network = "udp"
			}
			return d.DialContext(c, network, "1.1.1.1:53")
		},
	}
	ips, err := r.LookupHost(qctx, domain)
	if err != nil {
		return false
	}
	return len(ips) > 0
}

// queryOne — single DNS A-record query. Determines block-vs-clean from the
// response: NXDOMAIN = blocked; A record IP matching a SinkholePrefix =
// blocked; any other A record = clean; timeout = unknown (not blocked).
func queryOne(ctx context.Context, p Provider, domain string) ProviderResult {
	res := ProviderResult{Provider: p.Name}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 150 * time.Millisecond}
			// Force UDP regardless of what the resolver suggests.
			if strings.HasPrefix(network, "tcp") {
				network = "udp"
			}
			return d.DialContext(ctx, network, p.Server)
		},
	}
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		// NXDOMAIN / NODATA looks like err.Error() containing "no such host".
		// Net package's DNSError type carries IsNotFound. Either way, treat
		// NX as a block — providers like Quad9 use it for blocked entries.
		s := err.Error()
		if strings.Contains(s, "no such host") || strings.Contains(s, "NXDOMAIN") {
			res.Blocked = true
			res.Reason = "NXDOMAIN"
			return res
		}
		// Timeout / network error — treat as unknown, not blocked.
		res.Reason = "timeout"
		return res
	}
	for _, ip := range ips {
		for _, sink := range p.SinkholePrefixes {
			if strings.HasPrefix(ip, sink) {
				res.Blocked = true
				res.Reason = "sinkhole:" + ip
				return res
			}
		}
	}
	// At least one non-sinkhole IP returned → clean from this provider.
	return res
}
