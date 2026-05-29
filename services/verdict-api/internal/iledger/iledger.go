// Package iledger reads the "returned-IP ledger" written by the resolver.
// See services/resolver/internal/iledger for the writer and the wire-format
// rationale.
//
// The contract between resolver and verdict-api is the Redis key shape:
//
//	key:   iledger:{client_id}:{domain}
//	value: JSON {ip, ttl, ts} per LIST element (newest first)
//
// verdict-api reads this list when scoring connection identity. If the
// browser's actual remote IP is present in the recent ledger, the DNS
// path is consistent (USER_DNS_PATH_MATCH). If it isn't, the path
// diverged (USER_DNS_PATH_MISMATCH) — local hijack, browser DoH, VPN
// DNS override, etc.
package iledger

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix    = "iledger:"
	readBatchMax = 32
)

// Entry mirrors the writer's struct. Must stay in sync.
type Entry struct {
	IP  string `json:"ip"`
	TTL uint32 `json:"ttl"`
	TS  int64  `json:"ts"`
}

// Key derives the Redis key for (clientID, domain). Must produce the same
// string as the resolver's iledger.Key — this is the inter-service contract.
func Key(clientID, domain string) string {
	c := strings.ToLower(strings.TrimSpace(clientID))
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	if c == "" {
		c = "unknown"
	}
	return keyPrefix + c + ":" + d
}

// Recent returns ledger entries that are still inside their TTL window
// (entry.TS + entry.TTL >= now). Stale entries are skipped. Returns at
// most readBatchMax results.
//
// Nil Redis client → (nil, nil): callers treat "ledger cold" the same as
// "extension is on a non-XGG DNS path." The caller decides what to emit:
// typically EXPECTED_RESOLVER_BYPASSED when the user opted into XGG DNS
// but the ledger is empty.
func Recent(ctx context.Context, rdb *redis.Client, clientID, domain string) ([]Entry, error) {
	if rdb == nil {
		return nil, nil
	}
	raws, err := rdb.LRange(ctx, Key(clientID, domain), 0, readBatchMax-1).Result()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	out := make([]Entry, 0, len(raws))
	for _, raw := range raws {
		var e Entry
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			continue
		}
		if e.TS+int64(e.TTL) < now {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// HasIP reports whether the given IP appears in the recent ledger for
// (clientID, domain). The core "is DNS path consistent" question.
func HasIP(ctx context.Context, rdb *redis.Client, clientID, domain, ip string) (bool, error) {
	if ip == "" {
		return false, nil
	}
	entries, err := Recent(ctx, rdb, clientID, domain)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.IP == ip {
			return true, nil
		}
	}
	return false, nil
}
