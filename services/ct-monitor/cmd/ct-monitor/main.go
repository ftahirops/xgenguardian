// XGenGuardian — ct-monitor.
//
// Subscribes to the Calidog Certstream WebSocket and watches for newly
// issued TLS certificates whose Subject Alternative Names contain a
// brand keyword (Levenshtein-distance ≤ 2). Matches are enqueued into
// the `prescan_queue` table for verdict-api to pre-scan before any user
// visits the domain.
//
// This is the single most differentiating signal in the system (#7).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	certstreamURL = "wss://certstream.calidog.io"
	// crt.sh fallback. Polled on a slow ticker to (a) catch certs CertStream
	// missed during reconnects and (b) keep enqueue working when CertStream
	// is offline. https://crt.sh/?q=...&output=json
	crtshAPIBase     = "https://crt.sh/"
	crtshPollInterval = 15 * time.Minute
	crtshLookbackHours = 24
	crtshPerKeyword    = 200 // hard cap on results parsed per keyword per cycle
)

type certStreamMsg struct {
	MessageType string `json:"message_type"`
	Data        struct {
		LeafCert struct {
			AllDomains []string `json:"all_domains"`
			NotBefore  float64  `json:"not_before"`
			Subject    struct {
				CN string `json:"CN"`
			} `json:"subject"`
		} `json:"leaf_cert"`
		Source struct {
			Name string `json:"name"`
		} `json:"source"`
	} `json:"data"`
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pg, err := pgxpool.New(ctx, env("DATABASE_URL", "postgres://xgg:xgg@localhost:5432/xgg"))
	if err != nil {
		log.Fatal().Err(err).Msg("pg")
	}
	defer pg.Close()

	keywords, err := loadKeywords(ctx, pg)
	if err != nil {
		log.Fatal().Err(err).Msg("load keywords")
	}
	log.Info().Int("keywords", len(keywords)).Msg("brand keywords loaded")

	go reloadKeywordsLoop(ctx, pg, &keywords)

	// crt.sh fallback poller — runs always (cheap; light queries), more
	// important when CertStream is disconnected. Tracks streamDown so it can
	// log "running in fallback mode".
	var streamDown atomic.Bool
	go crtshPollLoop(ctx, pg, &keywords, &streamDown)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		cancel()
	}()

	for {
		streamDown.Store(false)
		if err := streamLoop(ctx, pg, &keywords); err != nil {
			streamDown.Store(true)
			log.Warn().Err(err).Msg("certstream loop exited; retrying in 5s (crt.sh fallback active)")
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		} else {
			return
		}
	}
}

// crtshPollLoop periodically queries crt.sh for each brand keyword and
// enqueues new matches. Rotates through keywords to spread load —
// `crtshPerKeyword` results × N keywords per cycle. crt.sh has no published
// rate limit but we keep traffic modest.
func crtshPollLoop(ctx context.Context, pg *pgxpool.Pool, keywords *[]string, streamDown *atomic.Bool) {
	// Initial delay so we don't all-fetch at process start (CertStream gets
	// first crack at warming the brand match cache).
	select {
	case <-ctx.Done():
		return
	case <-time.After(90 * time.Second):
	}
	t := time.NewTicker(crtshPollInterval)
	defer t.Stop()

	// Round-robin index across keywords so each cycle queries a different
	// 10-key slice. Reduces wall-clock and total queries.
	idx := 0
	tick := func() {
		kws := *keywords
		if len(kws) == 0 {
			return
		}
		// Up to 10 keywords per cycle. With 15 min interval that's ~960
		// keywords/day at the busy end — well within crt.sh's tolerance.
		const perCycle = 10
		start := idx
		count := 0
		for n := 0; n < len(kws) && count < perCycle; n++ {
			k := kws[(start+n)%len(kws)]
			idx = (start + n + 1) % len(kws)
			if domains, err := crtshQuery(ctx, k); err == nil {
				for _, d := range domains {
					if hint, ok := matches(d, kws); ok {
						enqueueWithSource(ctx, pg, d, hint, "crtsh_brand_match")
					}
				}
			} else {
				log.Warn().Err(err).Str("keyword", k).Msg("crt.sh query failed")
			}
			count++
		}
		if streamDown.Load() {
			log.Info().Int("queries", count).Msg("crt.sh fallback cycle (certstream down)")
		}
	}

	tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// crtshQuery hits https://crt.sh/?q=<keyword>&output=json&exclude=expired
// and returns the recent-enough domain values. crt.sh returns one row per
// SAN; we de-dup here.
func crtshQuery(ctx context.Context, keyword string) ([]string, error) {
	if keyword == "" {
		return nil, nil
	}
	q := url.Values{}
	q.Set("q", "%"+keyword+"%")
	q.Set("output", "json")
	q.Set("exclude", "expired")
	u := crtshAPIBase + "?" + q.Encode()

	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xgenguardian-ct-monitor/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MB cap
	if err != nil {
		return nil, err
	}

	var rows []struct {
		NameValue string `json:"name_value"`
		NotBefore string `json:"not_before"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh parse: %w", err)
	}

	cutoff := time.Now().Add(-time.Duration(crtshLookbackHours) * time.Hour)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rows))
	for i, r := range rows {
		if i >= crtshPerKeyword {
			break
		}
		// not_before is e.g. "2024-09-13T08:51:00"
		t, err := time.Parse("2006-01-02T15:04:05", r.NotBefore)
		if err == nil && t.Before(cutoff) {
			continue
		}
		for _, raw := range strings.Split(r.NameValue, "\n") {
			d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "*.")
			if d == "" {
				continue
			}
			if _, dup := seen[d]; dup {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out, nil
}

// enqueueWithSource — same as enqueue but takes an explicit reason string so
// analytics can split CertStream-driven enqueues from crt.sh-driven ones.
func enqueueWithSource(ctx context.Context, pg *pgxpool.Pool, domain, brandHint, reason string) {
	_, err := pg.Exec(ctx, `
		INSERT INTO prescan_queue (domain, reason, brand_hint)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`, domain, reason, brandHint)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("enqueue (crt.sh)")
		return
	}
	log.Info().Str("domain", domain).Str("brand_hint", brandHint).Str("source", reason).Msg("prescan enqueued")
}

func streamLoop(ctx context.Context, pg *pgxpool.Pool, keywords *[]string) error {
	c, _, err := websocket.DefaultDialer.DialContext(ctx, certstreamURL, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	log.Info().Str("url", certstreamURL).Msg("connected to Certstream")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_, raw, err := c.ReadMessage()
		if err != nil {
			return err
		}
		var msg certStreamMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		if msg.MessageType != "certificate_update" {
			continue
		}
		for _, dom := range msg.Data.LeafCert.AllDomains {
			dom = strings.TrimPrefix(strings.ToLower(dom), "*.")
			if hint, ok := matches(dom, *keywords); ok {
				enqueue(ctx, pg, dom, hint)
			}
		}
	}
}

// matches — cheap Levenshtein-distance lookup against brand keywords.
// Returns (brand_hint, true) if any keyword is within edit-distance 2
// of any subdomain label.
func matches(domain string, keywords []string) (string, bool) {
	core := strings.SplitN(domain, ".", 2)[0]
	for _, k := range keywords {
		if k == "" {
			continue
		}
		if strings.Contains(core, k) && core != k {
			return k, true
		}
		if levenshtein(core, k) <= 2 && core != k {
			return k, true
		}
	}
	return "", false
}

func enqueue(ctx context.Context, pg *pgxpool.Pool, domain, brandHint string) {
	_, err := pg.Exec(ctx, `
		INSERT INTO prescan_queue (domain, reason, brand_hint)
		VALUES ($1, 'ct_log_brand_match', $2)
		ON CONFLICT DO NOTHING
	`, domain, brandHint)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("enqueue")
		return
	}
	log.Info().Str("domain", domain).Str("brand_hint", brandHint).Msg("prescan enqueued")
}

func loadKeywords(ctx context.Context, pg *pgxpool.Pool) ([]string, error) {
	rows, err := pg.Query(ctx, `SELECT unnest(keywords) FROM brands`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]struct{}{}
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if len(k) < 4 {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out, nil
}

func reloadKeywordsLoop(ctx context.Context, pg *pgxpool.Pool, keywords *[]string) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if k, err := loadKeywords(ctx, pg); err == nil {
				*keywords = k
				log.Info().Int("keywords", len(k)).Msg("keywords reloaded")
			}
		}
	}
}

// --- helpers ---

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			m := curr[j-1] + 1
			if prev[j]+1 < m {
				m = prev[j] + 1
			}
			if prev[j-1]+cost < m {
				m = prev[j-1] + cost
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
