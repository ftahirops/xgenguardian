// vendordnscache.go — Redis cache layer around vendordns.Query.
//
// The 8-provider DNS consensus query takes ~250ms even with parallel UDP
// queries. DNS blocklists change slowly (typically hour-granular updates),
// so caching the result for 1h trades a tiny detection-latency for ~250ms
// off every repeat-domain check.
package httpgw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/vendordns"
)

const vendorDNSCacheTTL = 1 * time.Hour

func vendorDNSCacheKey(domain string) string {
	h := sha256.Sum256([]byte(domain))
	return "vendordns:" + hex.EncodeToString(h[:])
}

// queryVendorDNSCached returns a vendordns consensus result, served from
// Redis when present and freshly queried (then cached) on miss. Network
// timeouts on the Redis side fail-open: we still run the live query.
func queryVendorDNSCached(ctx context.Context, rdb *redis.Client, domain string) vendordns.ConsensusResult {
	// Redis lookup (bounded by request ctx so a stalled Redis can't hang us).
	if rdb != nil {
		if val, err := rdb.Get(ctx, vendorDNSCacheKey(domain)).Bytes(); err == nil {
			var cached vendordns.ConsensusResult
			if err := json.Unmarshal(val, &cached); err == nil {
				return cached
			}
		}
	}

	// Live query — vendordns has its own ~250ms internal budget.
	qctx, c := context.WithTimeout(ctx, 600*time.Millisecond)
	defer c()
	res := vendordns.Query(qctx, domain)

	// Write back to Redis on a detached background context so a cancelled
	// request still seeds the cache for the next request.
	if rdb != nil && res.Queried > 0 {
		if data, err := json.Marshal(res); err == nil {
			if err := rdb.Set(context.Background(), vendorDNSCacheKey(domain), data, vendorDNSCacheTTL).Err(); err != nil {
				log.Warn().Err(err).Str("domain", domain).Msg("vendordnscache: set failed")
			}
		}
	}
	return res
}
