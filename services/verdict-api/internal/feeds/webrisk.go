// Package feeds wraps external threat-intelligence APIs and populates the
// corresponding fields on fusion.Inputs (UNIFIED-PLAN.md §5.5).
//
// Google Web Risk is the first wired corroborator. The free /v1/uris:search
// endpoint accepts a single URL plus a list of threat types and returns
// whether any list flags it. Results are cached for 6 hours per URL to stay
// well inside the free quota and keep verdict latency low.
package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	webRiskEndpoint = "https://webrisk.googleapis.com/v1/uris:search"
	WebRiskCacheTTL = 6 * time.Hour
	webRiskTimeout  = 3 * time.Second
)

// WebRiskClient queries Google Web Risk. Safe for concurrent use.
type WebRiskClient struct {
	apiKey string
	http   *http.Client

	mu    sync.RWMutex
	cache map[string]webRiskEntry
}

type webRiskEntry struct {
	clean   bool
	threats []string
	expires time.Time
}

// NewWebRisk constructs a client. apiKey is required; pass an empty key to
// disable the corroborator (Lookup will return clean=true with no error).
// fusion.Inputs.GSBClean is `*bool` so callers can distinguish "not consulted"
// (nil) from "checked and clean" (true) — we return (nil, nil) when disabled.
func NewWebRisk(apiKey string) *WebRiskClient {
	return &WebRiskClient{
		apiKey: apiKey,
		http:   &http.Client{Timeout: webRiskTimeout},
		cache:  map[string]webRiskEntry{},
	}
}

// Enabled reports whether the client has an API key.
func (c *WebRiskClient) Enabled() bool { return c.apiKey != "" }

// Lookup returns (cleanPtr, threats, error).
//
//	cleanPtr == nil   → not consulted (no key, or transient error)
//	*cleanPtr == true → Web Risk says clean
//	*cleanPtr == false → Web Risk flagged threats; the threats slice lists which
func (c *WebRiskClient) Lookup(ctx context.Context, target string) (*bool, []string, error) {
	if !c.Enabled() {
		return nil, nil, nil
	}
	key := strings.ToLower(strings.TrimSpace(target))
	if key == "" {
		return nil, nil, errors.New("empty url")
	}

	c.mu.RLock()
	if e, ok := c.cache[key]; ok && time.Now().Before(e.expires) {
		c.mu.RUnlock()
		clean := e.clean
		return &clean, e.threats, nil
	}
	c.mu.RUnlock()

	clean, threats, err := c.query(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	c.cacheStore(key, clean, threats)
	return &clean, threats, nil
}

func (c *WebRiskClient) cacheStore(target string, clean bool, threats []string) {
	c.mu.Lock()
	c.cache[target] = webRiskEntry{
		clean:   clean,
		threats: threats,
		expires: time.Now().Add(WebRiskCacheTTL),
	}
	c.mu.Unlock()
}

// query issues one HTTPS request to Web Risk and parses the response.
//
// Wire format (https://cloud.google.com/web-risk/docs/reference/rest/v1/uris/search):
//
//	GET /v1/uris:search?key=…&uri=…&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING
//	→ {"threat":{"threatTypes":["MALWARE"], "expireTime":"..."}}
//	or {} when the URL is clean.
func (c *WebRiskClient) query(ctx context.Context, target string) (bool, []string, error) {
	q := url.Values{}
	q.Set("key", c.apiKey)
	q.Set("uri", target)
	q.Add("threatTypes", "MALWARE")
	q.Add("threatTypes", "SOCIAL_ENGINEERING")
	q.Add("threatTypes", "UNWANTED_SOFTWARE")
	q.Add("threatTypes", "SOCIAL_ENGINEERING_EXTENDED_COVERAGE")

	u := webRiskEndpoint + "?" + q.Encode()

	ctx, cancel := context.WithTimeout(ctx, webRiskTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, nil, fmt.Errorf("web risk HTTP %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, nil, err
	}

	var parsed struct {
		Threat *struct {
			ThreatTypes []string `json:"threatTypes"`
			ExpireTime  string   `json:"expireTime"`
		} `json:"threat"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, nil, fmt.Errorf("web risk parse: %w", err)
	}

	if parsed.Threat == nil || len(parsed.Threat.ThreatTypes) == 0 {
		return true, nil, nil
	}
	return false, parsed.Threat.ThreatTypes, nil
}
