// XGenGuardian — scheduler service entry point.
//
// Responsibilities (UNIFIED-PLAN.md §6):
//   - Poll `urls` for next_rescan_at <= now() and dispatch revalidation
//     jobs to verdict-api at the appropriate tier (light / medium / deep).
//   - Sweep expired overrides (Executive Mode 7-day rule), expired evidence
//     past retention_until, and popup_edges older than 90 days.
//   - Honor per-domain rate limit so we don't hammer a single site.
//
// Not yet implemented in this skeleton:
//   - Drift-trigger fast-path (when verdict-api reports drift, scheduler
//     should force re-queue at the higher tier immediately, not wait for
//     next TTL). Wired via a Redis stream in Phase 1.5.
//   - dnstwist nightly + OSS feed ingest jobs (Phase 1 OSS wave) — separate
//     cron files; will live as additional Run goroutines here.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/scheduler/internal/dnstwist"
	"github.com/xgenguardian/services/scheduler/internal/expiry"
	"github.com/xgenguardian/services/scheduler/internal/feeds"
	"github.com/xgenguardian/services/scheduler/internal/poller"
	"github.com/xgenguardian/services/scheduler/internal/subjack"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// httpDispatcher posts jobs to verdict-api's /scan endpoint. The endpoint
// itself is implemented as part of verdict-api Phase-1 wiring; until that
// lands the dispatcher logs and drops, which is intentional — we'd rather
// know how many TTL expiries fire without overflowing a yet-to-exist queue.
type httpDispatcher struct {
	base   string
	client *http.Client
}

func (d *httpDispatcher) Enqueue(ctx context.Context, j poller.Job) error {
	body, _ := json.Marshal(map[string]any{
		"url":    j.URL,
		"tier":   j.Tier.String(),
		"reason": j.Reason,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+"/v1/scan", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		// Don't block the poller on a single failed dispatch; the next TTL
		// sweep will retry.
		log.Warn().Err(err).Str("url", j.URL).Msg("dispatch http error")
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Warn().Int("status", resp.StatusCode).Str("url", j.URL).Msg("dispatch non-2xx")
	}
	return nil
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.With().Str("svc", "scheduler").Logger()

	dbURL := env("DATABASE_URL", "postgres://xgg:xgg@localhost:15432/xgg?sslmode=disable")
	verdictAPI := env("VERDICT_API_ADDR", "http://127.0.0.1:18080")
	pollIntervalStr := env("POLL_INTERVAL", "30s")
	expiryIntervalStr := env("EXPIRY_INTERVAL", "5m")

	pollInterval, err := time.ParseDuration(pollIntervalStr)
	if err != nil {
		log.Fatal().Err(err).Msg("bad POLL_INTERVAL")
	}
	expiryInterval, err := time.ParseDuration(expiryIntervalStr)
	if err != nil {
		log.Fatal().Err(err).Msg("bad EXPIRY_INTERVAL")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Fatal().Err(err).Msg("parse pg config")
	}
	pg, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("pgx pool")
	}
	defer pg.Close()

	disp := &httpDispatcher{
		base:   strings.TrimRight(verdictAPI, "/"),
		client: &http.Client{Timeout: 3 * time.Second},
	}

	p := poller.New(pg, disp).WithInterval(pollInterval)

	log.Info().
		Str("db", redactPg(dbURL)).
		Str("verdict_api", verdictAPI).
		Str("poll_interval", pollInterval.String()).
		Str("expiry_interval", expiryInterval.String()).
		Msg("scheduler starting")

	go expiry.Run(ctx, pg, expiryInterval)
	// OSS feed ingest: first run after 30 s so we don't all-fetch at startup;
	// every 24 h thereafter. The free tiers we use (URLhaus, PhishTank,
	// OpenPhish) tolerate this comfortably.
	feeds.Schedule(ctx, pg, 30*time.Second, 24*time.Hour)
	// dnstwist nightly typosquat sweep — first run after 5 min (let the
	// brand registry hydrate first), then every 24h.
	dnstwist.Schedule(ctx, dbURL, 5*time.Minute, dnstwist.RunInterval)
	// Subjack weekly subdomain-takeover sweep. Operates on the
	// prescan_queue (which ct-monitor + crt.sh populate).
	subjack.Schedule(ctx, pg, 15*time.Minute, subjack.RunInterval)
	p.Run(ctx)

	log.Info().Msg("scheduler shutting down")
}

// redactPg hides the password from logged conn strings.
func redactPg(s string) string {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return s
	}
	scheme := strings.Index(s, "://")
	if scheme < 0 || scheme+3 >= at {
		return s
	}
	creds := s[scheme+3 : at]
	colon := strings.Index(creds, ":")
	if colon < 0 {
		return s
	}
	return s[:scheme+3] + creds[:colon] + ":***" + s[at:]
}
