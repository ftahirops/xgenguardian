// Package rdap looks up domain registration data (registrar, creation date,
// expiry, status) via the IETF Registration Data Access Protocol (RFC 7483).
//
// RDAP replaced WHOIS for ICANN gTLDs in 2017 and for ccTLDs progressively
// since. We use it to populate `domains.registered_at`, `domains.expires_at`,
// and `domains.registrar` — the third clause of the universal phishing rule
// (fusion.isImpersonation: domain_age < 90d) is otherwise a dead branch
// because no other component writes those columns.
//
// Bootstrap registry: https://data.iana.org/rdap/dns.json maps TLD → RDAP
// base URL list. We fetch it once on Start and refresh hourly.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	BootstrapURL       = "https://data.iana.org/rdap/dns.json"
	BootstrapRefresh   = time.Hour
	DefaultLookupTime  = 5 * time.Second
	CacheTTLClean      = 7 * 24 * time.Hour
	CacheTTLNotFound   = 24 * time.Hour
	CacheTTLError      = 15 * time.Minute
	UserAgent          = "xgenguardian-rdap/1.0 (+https://xgenguardian.com)"
)

// Info is the subset of RDAP fields we care about. All time fields are zero
// when the registry did not return them — callers must check IsZero.
type Info struct {
	Domain       string
	Registrar    string
	RegisteredAt time.Time
	UpdatedAt    time.Time
	ExpiresAt    time.Time
	NameServers  []string
	Status       []string // e.g. "clientHold", "serverDeleteProhibited"
	Source       string   // RDAP base URL the answer came from
	FetchedAt    time.Time
}

// Age returns the time since registration, or 0 if registration date unknown.
// fusion.Inputs.DomainAge is the consumer.
func (i Info) Age() time.Duration {
	if i.RegisteredAt.IsZero() {
		return 0
	}
	return time.Since(i.RegisteredAt)
}

var (
	ErrNoRDAPForTLD = errors.New("no RDAP server registered for TLD")
	ErrNotFound     = errors.New("domain not found in RDAP")
)

// Client is the in-process RDAP lookup engine. Safe for concurrent use.
type Client struct {
	http      *http.Client
	bootstrap *bootstrapTable
	mu        sync.RWMutex
	cache     map[string]cachedInfo
}

type cachedInfo struct {
	info    Info
	err     error
	expires time.Time
}

// New creates a Client with default HTTP timeout. Call Start before first
// Lookup so the bootstrap table is populated.
func New() *Client {
	return &Client{
		http:      &http.Client{Timeout: DefaultLookupTime},
		bootstrap: &bootstrapTable{m: map[string][]string{}},
		cache:     map[string]cachedInfo{},
	}
}

// Start fetches the IANA bootstrap registry once, then refreshes it
// periodically. Returns after the first successful fetch.
func (c *Client) Start(ctx context.Context) error {
	if err := c.bootstrap.refresh(ctx, c.http); err != nil {
		return fmt.Errorf("rdap bootstrap: %w", err)
	}
	go func() {
		t := time.NewTicker(BootstrapRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = c.bootstrap.refresh(ctx, c.http)
			}
		}
	}()
	return nil
}

// Lookup queries RDAP for the given domain. Cached results respect the TTLs
// declared above; cache hits are sub-microsecond.
//
// Domain must be the registrable name (eTLD+1). Callers should strip
// subdomains before calling — see registry.sld for a cheap form.
func (c *Client) Lookup(ctx context.Context, domain string) (Info, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return Info{}, errors.New("empty domain")
	}

	c.mu.RLock()
	if e, ok := c.cache[domain]; ok && time.Now().Before(e.expires) {
		c.mu.RUnlock()
		return e.info, e.err
	}
	c.mu.RUnlock()

	info, err := c.lookupNoCache(ctx, domain)
	c.cacheStore(domain, info, err)
	return info, err
}

func (c *Client) cacheStore(domain string, info Info, err error) {
	ttl := CacheTTLClean
	switch {
	case errors.Is(err, ErrNotFound):
		ttl = CacheTTLNotFound
	case err != nil:
		ttl = CacheTTLError
	}
	c.mu.Lock()
	c.cache[domain] = cachedInfo{info: info, err: err, expires: time.Now().Add(ttl)}
	c.mu.Unlock()
}

func (c *Client) lookupNoCache(ctx context.Context, domain string) (Info, error) {
	tld := tldOf(domain)
	bases := c.bootstrap.serversFor(tld)
	if len(bases) == 0 {
		return Info{}, fmt.Errorf("%w: %s", ErrNoRDAPForTLD, tld)
	}

	var lastErr error
	for _, base := range bases {
		info, err := c.queryOne(ctx, base, domain)
		if err == nil {
			info.Source = base
			info.FetchedAt = time.Now()
			return info, nil
		}
		if errors.Is(err, ErrNotFound) {
			return Info{}, err
		}
		lastErr = err
	}
	return Info{}, lastErr
}

func (c *Client) queryOne(ctx context.Context, base, domain string) (Info, error) {
	u := strings.TrimRight(base, "/") + "/domain/" + domain

	ctx, cancel := context.WithTimeout(ctx, DefaultLookupTime)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Info{}, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return Info{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return Info{}, ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return Info{}, fmt.Errorf("rdap %s: HTTP %d", u, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB hard cap
	if err != nil {
		return Info{}, err
	}
	return parse(body, domain)
}

// parse extracts our subset of the RDAP response. RFC 7483 §5.3.
func parse(body []byte, domain string) (Info, error) {
	var raw struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles  []string `json:"roles"`
			VCardArray []any  `json:"vcardArray"`
		} `json:"entities"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
		Status []string `json:"status"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Info{}, fmt.Errorf("rdap parse: %w", err)
	}

	info := Info{Domain: domain, Status: raw.Status}

	for _, ev := range raw.Events {
		t, err := parseTime(ev.Date)
		if err != nil {
			continue
		}
		switch strings.ToLower(ev.Action) {
		case "registration":
			info.RegisteredAt = t
		case "expiration":
			info.ExpiresAt = t
		case "last changed", "last update of rdap database":
			info.UpdatedAt = t
		}
	}

	for _, ns := range raw.Nameservers {
		if ns.LDHName != "" {
			info.NameServers = append(info.NameServers, strings.ToLower(ns.LDHName))
		}
	}

	// Registrar from entity roles. Search for an entity with role "registrar"
	// and pull the "fn" property out of its vCard.
	for _, e := range raw.Entities {
		isRegistrar := false
		for _, r := range e.Roles {
			if strings.EqualFold(r, "registrar") {
				isRegistrar = true
				break
			}
		}
		if !isRegistrar {
			continue
		}
		info.Registrar = extractVCardFN(e.VCardArray)
		break
	}

	return info, nil
}

// parseTime accepts the RFC 3339 form RDAP servers use, plus a few common
// variants seen in the wild.
func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q", s)
}

// extractVCardFN walks an RDAP vCardArray ("jCard", RFC 7095) and returns
// the value of the first "fn" property. vCardArray shape is
// ["vcard", [ ["fn", {}, "text", "Acme Registrar"], ... ]].
func extractVCardFN(arr []any) string {
	if len(arr) < 2 {
		return ""
	}
	props, ok := arr[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		row, ok := p.([]any)
		if !ok || len(row) < 4 {
			continue
		}
		name, _ := row[0].(string)
		if !strings.EqualFold(name, "fn") {
			continue
		}
		if v, ok := row[3].(string); ok {
			return v
		}
	}
	return ""
}

func tldOf(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
