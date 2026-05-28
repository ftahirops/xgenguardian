package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// bootstrapTable holds the IANA TLD → RDAP-server-list mapping.
//
// Wire format (https://data.iana.org/rdap/dns.json) is documented in RFC 9224:
//
//	{
//	  "services": [
//	    [ ["com","net"], ["https://rdap.verisign.com/com/v1/"] ],
//	    [ ["uk"],         ["https://rdap.nominet.uk/uk/"] ],
//	    ...
//	  ]
//	}
//
// We flatten this on refresh into a TLD → []base-URLs map. Lookups are
// case-insensitive on the TLD.
type bootstrapTable struct {
	mu sync.RWMutex
	m  map[string][]string
}

func (b *bootstrapTable) refresh(ctx context.Context, h *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, BootstrapURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB cap
	if err != nil {
		return err
	}

	var raw struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("bootstrap parse: %w", err)
	}

	flat := map[string][]string{}
	for _, svc := range raw.Services {
		if len(svc) != 2 {
			continue
		}
		tlds, urls := svc[0], svc[1]
		for _, t := range tlds {
			flat[strings.ToLower(t)] = urls
		}
	}

	b.mu.Lock()
	b.m = flat
	b.mu.Unlock()
	return nil
}

// serversFor returns the configured RDAP base URLs for a TLD, or nil if no
// server is registered. Caller must not mutate the returned slice.
func (b *bootstrapTable) serversFor(tld string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.m[strings.ToLower(tld)]
}

// loadFromJSON is a test helper that lets unit tests bypass the network.
func (b *bootstrapTable) loadFromJSON(body []byte) error {
	var raw struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}
	flat := map[string][]string{}
	for _, svc := range raw.Services {
		if len(svc) != 2 {
			continue
		}
		for _, t := range svc[0] {
			flat[strings.ToLower(t)] = svc[1]
		}
	}
	b.mu.Lock()
	b.m = flat
	b.mu.Unlock()
	return nil
}
