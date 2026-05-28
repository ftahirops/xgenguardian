// Package expiry sweeps expired records: tenant overrides past their
// expires_at (UNIFIED-PLAN.md §4.4 hard-rule "all overrides expire in 7
// days"), evidence past retention_until, popup_edges older than 90 days.
package expiry

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// PopupEdgeRetention — popup_edges older than this are deleted by the
// sweep. The popup-edge graph view (UNIFIED-PLAN.md §9) doesn't need
// older history; analytics keeps aggregates separately.
const PopupEdgeRetention = 90 * 24 * time.Hour

// Sweep runs all expiry jobs once. Returns the per-table delete counts.
type SweepStats struct {
	OverridesDeleted   int64
	EvidenceDeleted    int64
	PopupEdgesDeleted  int64
}

func Sweep(ctx context.Context, pg *pgxpool.Pool) (SweepStats, error) {
	var s SweepStats

	// Overrides past expires_at. Soft-delete by marking deleted_at would be
	// nicer for audit, but the column isn't in the schema; hard delete is
	// fine given the analytics requirement is "count of evictions per day"
	// which we capture in the log.
	tag, err := pg.Exec(ctx, `DELETE FROM overrides WHERE expires_at < NOW()`)
	if err != nil {
		return s, err
	}
	s.OverridesDeleted = tag.RowsAffected()

	tag, err = pg.Exec(ctx, `DELETE FROM evidence WHERE retention_until IS NOT NULL AND retention_until < NOW()`)
	if err != nil {
		return s, err
	}
	s.EvidenceDeleted = tag.RowsAffected()

	cutoff := time.Now().Add(-PopupEdgeRetention)
	tag, err = pg.Exec(ctx, `DELETE FROM popup_edges WHERE occurred_at < $1`, cutoff)
	if err != nil {
		return s, err
	}
	s.PopupEdgesDeleted = tag.RowsAffected()

	log.Info().
		Int64("overrides", s.OverridesDeleted).
		Int64("evidence", s.EvidenceDeleted).
		Int64("popup_edges", s.PopupEdgesDeleted).
		Msg("expiry sweep complete")

	return s, nil
}

// Run starts the sweep loop. Sweeps every interval; returns when ctx is done.
func Run(ctx context.Context, pg *pgxpool.Pool, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	// Sweep once at startup so a freshly-deployed scheduler doesn't wait
	// `interval` to catch already-expired rows.
	if _, err := Sweep(ctx, pg); err != nil {
		log.Warn().Err(err).Msg("expiry sweep error")
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := Sweep(ctx, pg); err != nil {
				log.Warn().Err(err).Msg("expiry sweep error")
			}
		}
	}
}
