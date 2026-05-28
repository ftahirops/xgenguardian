// Package subjack — subdomain-takeover scanner.
//
// Walks subdomains discovered by ct-monitor for canonical brand domains,
// resolves their CNAME targets, and flags any whose target points at a
// service-marker known to be claimable (S3 bucket, Heroku app, GitHub
// Pages, etc.). Findings land in feed_entries with source='subjack' so
// verdict-api's BlocklistHit lookup catches them on first user visit.
//
// We don't shell out to the Subjack binary — the fingerprint set is small
// and we want full control of timing and concurrency. Run weekly.
package subjack

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	RunInterval         = 7 * 24 * time.Hour
	HTTPTimeout         = 5 * time.Second
	maxConcurrentLookups = 16
)

// Fingerprint is one known-claimable provider. `cname_pattern` is matched
// as a suffix on the resolved CNAME target; `body_marker` is the string
// the dangling provider serves on a request to a claimed-but-empty
// resource (e.g. AWS's "NoSuchBucket"). Both must match.
type Fingerprint struct {
	Name        string
	CNamePat    string
	BodyMarker  string
}

// Curated fingerprint table. Source: can-i-take-over-xyz community dataset
// (https://github.com/EdOverflow/can-i-take-over-xyz). We ship a tight set
// of the most reliable signals; operators can extend via SUBJACK_FP_PATH.
var defaultFingerprints = []Fingerprint{
	{"github_pages", ".github.io", "There isn't a GitHub Pages site here."},
	{"heroku",       ".herokuapp.com", "No such app"},
	{"aws_s3",       ".s3.amazonaws.com", "NoSuchBucket"},
	{"aws_s3_2",     ".s3-website", "NoSuchBucket"},
	{"shopify",      ".myshopify.com", "Sorry, this shop is currently unavailable"},
	{"unbounce",     ".unbouncepages.com", "The requested URL was not found on this server."},
	{"tumblr",       ".tumblr.com", "Whatever you were looking for doesn't currently exist"},
	{"surge_sh",     ".surge.sh", "project not found"},
	{"webflow",      ".proxy.webflow.com", "The page you are looking for doesn't exist"},
	{"vercel",       ".vercel.app", "DEPLOYMENT_NOT_FOUND"},
	{"netlify",      ".netlify.app", "Not Found - Request ID:"},
}

// Run does a single sweep. Inserts findings into feed_entries.
func Run(ctx context.Context, pg *pgxpool.Pool) error {
	subdomains, err := loadSubdomains(ctx, pg)
	if err != nil {
		return fmt.Errorf("load subdomains: %w", err)
	}
	log.Info().Int("candidates", len(subdomains)).Msg("subjack sweep starting")

	sem := make(chan struct{}, maxConcurrentLookups)
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		findings   []finding
	)
	client := &http.Client{Timeout: HTTPTimeout}

	for _, sub := range subdomains {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()
			if f, ok := checkOne(ctx, client, d); ok {
				mu.Lock()
				findings = append(findings, f)
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()

	if len(findings) == 0 {
		log.Info().Msg("subjack sweep: no takeover-vulnerable subdomains found")
		return nil
	}
	if err := writeFindings(ctx, pg, findings); err != nil {
		return err
	}
	log.Info().Int("findings", len(findings)).Msg("subjack sweep complete")
	return nil
}

// Schedule kicks off a weekly run loop.
func Schedule(ctx context.Context, pg *pgxpool.Pool, initialDelay, interval time.Duration) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(initialDelay):
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		if err := Run(ctx, pg); err != nil {
			log.Warn().Err(err).Msg("subjack first run")
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := Run(ctx, pg); err != nil {
					log.Warn().Err(err).Msg("subjack run")
				}
			}
		}
	}()
}

type finding struct {
	Domain          string
	BrandHint       string
	FingerprintName string
}

func loadSubdomains(ctx context.Context, pg *pgxpool.Pool) ([]string, error) {
	// Use prescan_queue as the source — ct-monitor enqueues SAN matches there
	// already. We treat each unique domain as a candidate.
	rows, err := pg.Query(ctx, `
		SELECT DISTINCT domain
		FROM prescan_queue
		WHERE enqueued_at > NOW() - INTERVAL '60 days'
		LIMIT 5000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err == nil && d != "" {
			out = append(out, d)
		}
	}
	return out, nil
}

// checkOne does the CNAME resolution + body marker check. Returns (finding,
// true) only when both halves match — keeps false positives near zero.
func checkOne(ctx context.Context, client *http.Client, domain string) (finding, bool) {
	cname, err := lookupCNAME(domain)
	if err != nil || cname == "" {
		return finding{}, false
	}
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")

	for _, fp := range defaultFingerprints {
		if !strings.HasSuffix(cname, fp.CNamePat) && !strings.Contains(cname, fp.CNamePat) {
			continue
		}
		body, err := fetchBody(ctx, client, "https://"+domain+"/")
		if err != nil {
			// Try http://
			body, err = fetchBody(ctx, client, "http://"+domain+"/")
		}
		if err != nil {
			continue
		}
		if strings.Contains(body, fp.BodyMarker) {
			return finding{Domain: domain, FingerprintName: fp.Name}, true
		}
	}
	return finding{}, false
}

func lookupCNAME(domain string) (string, error) {
	r := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return r.LookupCNAME(ctx, domain)
}

func fetchBody(ctx context.Context, client *http.Client, u string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "xgenguardian-subjack/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func writeFindings(ctx context.Context, pg *pgxpool.Pool, fs []finding) error {
	tx, err := pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, f := range fs {
		// Store as feed_entries so verdict-api's BlocklistHit pathway catches
		// them. Source='subjack'; category='subdomain_takeover'.
		_, err := tx.Exec(ctx, `
			INSERT INTO feed_entries (source, url, domain, category, first_seen, reference_id, last_seen)
			VALUES ('subjack', $1, $2, 'subdomain_takeover', NOW(), $3, NOW())
			ON CONFLICT (source, url) DO UPDATE SET
			  last_seen = NOW(),
			  reference_id = EXCLUDED.reference_id
		`, "https://"+f.Domain+"/", f.Domain, f.FingerprintName)
		if err != nil {
			return err
		}
		log.Warn().Str("domain", f.Domain).Str("provider", f.FingerprintName).Msg("subdomain-takeover candidate")
	}
	return tx.Commit(ctx)
}
