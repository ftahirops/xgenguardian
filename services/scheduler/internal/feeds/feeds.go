// Package feeds ingests free / public threat-intel feeds into the deny
// cache (UNIFIED-PLAN.md §18.2). Three sources are wired:
//
//   - URLhaus (abuse.ch)      — confirmed malware URLs
//   - PhishTank (Cisco)       — confirmed phishing URLs
//   - OpenPhish               — confirmed phishing URLs
//
// All three publish refreshing CSV / JSON / plaintext feeds at stable URLs;
// no API keys required for the public tiers used here. Records are upserted
// into a `feed_entries` table that the verdict-api consults during fusion
// (BlocklistHit boolean on fusion.Inputs).
//
// Each ingestor knows its own format and TTL; the package presents a
// uniform Run() driver the scheduler invokes once a day.
package feeds

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	URLhausURL      = "https://urlhaus.abuse.ch/downloads/csv_recent/"
	OpenPhishURL    = "https://openphish.com/feed.txt"
	PhishTankURL    = "http://data.phishtank.com/data/online-valid.json"
	httpTimeout     = 30 * time.Second
	defaultMaxBytes = 50 << 20 // 50 MB cap per feed file
)

// Entry is one row in `feed_entries`.
type Entry struct {
	Source      string // "urlhaus" | "phishtank" | "openphish"
	URL         string
	Domain      string
	Category    string // "malware" | "phishing"
	FirstSeen   time.Time
	ReferenceID string // upstream id where available
}

// Run fetches all configured feeds once and upserts entries. Errors per-
// source are logged and do NOT abort the others.
func Run(ctx context.Context, pg *pgxpool.Pool) error {
	client := &http.Client{Timeout: httpTimeout}

	tasks := []struct {
		name string
		fn   func(context.Context, *http.Client) ([]Entry, error)
	}{
		{"urlhaus", fetchURLhaus},
		{"openphish", fetchOpenPhish},
		{"phishtank", fetchPhishTank},
	}
	var firstErr error
	for _, t := range tasks {
		entries, err := t.fn(ctx, client)
		if err != nil {
			log.Warn().Err(err).Str("feed", t.name).Msg("feed fetch failed")
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ins, err := upsert(ctx, pg, entries)
		if err != nil {
			log.Warn().Err(err).Str("feed", t.name).Msg("feed upsert failed")
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		log.Info().Str("feed", t.name).Int("fetched", len(entries)).Int("inserted", ins).Msg("feed ingest ok")
	}
	return firstErr
}

// Schedule starts a once-daily ingest goroutine. First fetch runs after
// `initialDelay` so we don't all-fetch at process start.
func Schedule(ctx context.Context, pg *pgxpool.Pool, initialDelay, interval time.Duration) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(initialDelay):
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		_ = Run(ctx, pg)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = Run(ctx, pg)
			}
		}
	}()
}

// ---------------- URLhaus (CSV) ----------------

// URLhaus CSV layout (header lines start with `#`):
//   id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
func fetchURLhaus(ctx context.Context, h *http.Client) ([]Entry, error) {
	return fetchURLhausFrom(ctx, h, URLhausURL)
}

func fetchURLhausFrom(ctx context.Context, h *http.Client, url string) ([]Entry, error) {
	body, err := httpGet(ctx, h, url)
	if err != nil {
		return nil, err
	}
	var out []Entry
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20) // grow up to 8 MB lines
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// URLhaus quotes fields, comma-separated. The 'tags' column contains
		// commas inside quotes; a naive split fails. Use a small CSV-aware
		// scanner: track quote state.
		fields := parseCSVLine(line)
		if len(fields) < 7 {
			continue
		}
		id := fields[0]
		dateStr := fields[1]
		urlStr := fields[2]
		urlStatus := fields[3]
		if urlStatus != "online" {
			continue // skip already-down URLs
		}
		t, _ := time.Parse("2006-01-02 15:04:05", dateStr)
		out = append(out, Entry{
			Source:      "urlhaus",
			URL:         urlStr,
			Domain:      hostOf(urlStr),
			Category:    "malware",
			FirstSeen:   t,
			ReferenceID: id,
		})
	}
	return out, sc.Err()
}

// parseCSVLine handles URLhaus's quote-then-comma format. Doesn't try to be
// a full RFC 4180 parser — sufficient for URLhaus's exact shape.
func parseCSVLine(line string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
		case c == ',' && !inQ:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// ---------------- OpenPhish (plain text, one URL per line) ----------------

func fetchOpenPhish(ctx context.Context, h *http.Client) ([]Entry, error) {
	return fetchOpenPhishFrom(ctx, h, OpenPhishURL)
}

func fetchOpenPhishFrom(ctx context.Context, h *http.Client, url string) ([]Entry, error) {
	body, err := httpGet(ctx, h, url)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, line := range strings.Split(string(body), "\n") {
		u := strings.TrimSpace(line)
		if u == "" || strings.HasPrefix(u, "#") {
			continue
		}
		out = append(out, Entry{
			Source:    "openphish",
			URL:       u,
			Domain:    hostOf(u),
			Category:  "phishing",
			FirstSeen: time.Now().UTC(),
		})
	}
	return out, nil
}

// ---------------- PhishTank (JSON array) ----------------
//
// Format excerpt:
//
//	[
//	  {
//	    "phish_id": "12345",
//	    "url": "http://...",
//	    "submission_time": "2024-01-15T10:30:00+00:00",
//	    "verified": "yes",
//	    "online": "yes"
//	  }, ...
//	]
//
// We only ingest verified == "yes" && online == "yes".

func fetchPhishTank(ctx context.Context, h *http.Client) ([]Entry, error) {
	return fetchPhishTankFrom(ctx, h, PhishTankURL)
}

func fetchPhishTankFrom(ctx context.Context, h *http.Client, url string) ([]Entry, error) {
	body, err := httpGet(ctx, h, url)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		PhishID        string `json:"phish_id"`
		URL            string `json:"url"`
		SubmissionTime string `json:"submission_time"`
		Verified       string `json:"verified"`
		Online         string `json:"online"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("phishtank parse: %w", err)
	}
	out := make([]Entry, 0, len(rows))
	for _, r := range rows {
		if r.Verified != "yes" || r.Online != "yes" {
			continue
		}
		t, _ := time.Parse(time.RFC3339, r.SubmissionTime)
		out = append(out, Entry{
			Source:      "phishtank",
			URL:         r.URL,
			Domain:      hostOf(r.URL),
			Category:    "phishing",
			FirstSeen:   t,
			ReferenceID: r.PhishID,
		})
	}
	return out, nil
}

// ---------------- shared ----------------

func httpGet(ctx context.Context, h *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xgenguardian-feeds/1.0")
	// NOTE: do NOT set Accept-Encoding manually. Go's net/http transparently
	// adds it and decompresses the response. Setting it manually disables
	// that and we get raw gzip bytes back.

	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, defaultMaxBytes))
}

func hostOf(rawurl string) string {
	// Cheap parse — we just want the host. Skip the scheme.
	s := rawurl
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// upsert inserts unseen entries; updates last_seen on duplicates. The
// `feed_entries` table is created by a Phase-1 migration that lives next to
// this commit.
func upsert(ctx context.Context, pg *pgxpool.Pool, entries []Entry) (int, error) {
	if pg == nil {
		// Caller (test) is fine running parsers without a DB.
		return 0, errors.New("nil pgxpool — provide a real pool")
	}
	if len(entries) == 0 {
		return 0, nil
	}
	tx, err := pg.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	const stmt = `
		INSERT INTO feed_entries (source, url, domain, category, first_seen, reference_id, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (source, url) DO UPDATE SET
		  last_seen = NOW(),
		  domain = EXCLUDED.domain,
		  category = EXCLUDED.category
	`
	inserted := 0
	for _, e := range entries {
		if _, err := tx.Exec(ctx, stmt, e.Source, e.URL, e.Domain, e.Category, e.FirstSeen, e.ReferenceID); err != nil {
			return inserted, err
		}
		inserted++
	}
	return inserted, tx.Commit(ctx)
}
