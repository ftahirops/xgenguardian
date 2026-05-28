// Package dnstwist drives the nightly typosquat sweep
// (UNIFIED-PLAN.md §18.2). The actual permutation + registration check
// lives in the Python tool at `tools/dnstwist-cron/run.py` — Go just
// shells out to it on a daily schedule.
//
// Why not reimplement in Go: dnstwist has 30+ permutation classes,
// active maintenance, and a JSON output format we already trust. The
// performance loss from a subprocess invocation (one fork per day) is
// negligible vs. the long-term maintenance burden of re-implementing.
package dnstwist

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

// RunInterval — once per 24h is plenty for typosquat-domain churn. Some
// kits rotate hourly but the long-tail permutation set is stable enough
// that a daily sweep with feed_entries last_seen TTL handles it.
const RunInterval = 24 * time.Hour

// Run invokes the dnstwist-cron Python script once. Returns when the
// subprocess exits. Errors are logged but never bubbled (we don't want
// a one-off failure to kill the scheduler).
//
// The script path is resolved relative to the working directory in dev
// and to the DNSTWIST_CRON_PATH env in production deployments.
func Run(ctx context.Context, dbURL string) {
	script := os.Getenv("DNSTWIST_CRON_PATH")
	if script == "" {
		// Walk up from CWD looking for tools/dnstwist-cron/run.py. Lets us
		// run from either repo root or services/scheduler dir.
		for _, candidate := range []string{
			"tools/dnstwist-cron/run.py",
			"../../tools/dnstwist-cron/run.py",
			"../../../tools/dnstwist-cron/run.py",
		} {
			if abs, err := filepath.Abs(candidate); err == nil {
				if _, err := os.Stat(abs); err == nil {
					script = abs
					break
				}
			}
		}
	}
	if script == "" {
		log.Warn().Msg("dnstwist-cron: run.py not found; set DNSTWIST_CRON_PATH")
		return
	}

	pyctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()

	cmd := exec.CommandContext(pyctx, "python3", script)
	cmd.Env = append(os.Environ(), "DATABASE_URL="+dbURL)

	log.Info().Str("script", script).Msg("dnstwist-cron starting")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn().Err(err).Bytes("output", lastLines(out, 2048)).Msg("dnstwist-cron failed")
		return
	}
	log.Info().Bytes("output", lastLines(out, 1024)).Msg("dnstwist-cron complete")
}

// Schedule kicks off a daily run loop. Initial run is delayed by
// initialDelay to avoid all-fetch at scheduler start.
func Schedule(ctx context.Context, dbURL string, initialDelay, interval time.Duration) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(initialDelay):
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		Run(ctx, dbURL)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				Run(ctx, dbURL)
			}
		}
	}()
}

// lastLines returns the last `n` bytes of `b`, useful for log capping.
func lastLines(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
