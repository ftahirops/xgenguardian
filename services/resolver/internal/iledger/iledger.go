// Package iledger writes the "returned-IP ledger" — the record of what the
// XGenGuardian resolver returned to each client for each domain. Phase B.4
// of docs/final-engine-architecture-plan.md §5.
//
// Why this exists
//
// Backend-DNS-only protection cannot answer the question
//
//	"Did the user's browser actually connect to a legitimate endpoint
//	 for the domain it thinks it visited?"
//
// because a backend resolver can be looking at an entirely different DNS
// path than the browser. The browser may have been redirected by:
//
//   - local hosts-file tampering
//   - router DNS hijack
//   - malicious ISP resolver
//   - browser DoH bypass of the system resolver
//   - VPN DNS override
//   - captive portal rewrite
//   - malware-installed root CA + DNS poisoning
//
// When the user uses XGG DNS, the resolver knows exactly what it answered
// for that (client, domain). verdict-api can compare the IP the browser
// actually connected to against this ledger and detect the discrepancy.
//
// Wire format
//
// One Redis LIST per (client_id, domain):
//
//	key:   iledger:{client_id}:{domain}
//	value: JSON {ip, ttl, ts} per entry
//
// LPUSH new entries to the front, LTRIM to MaxEntriesPerKey, EXPIRE to
// the max observed TTL plus GraceSeconds. The grace window lets verdict-api
// still find the entry when the browser connects right at TTL expiry.
package iledger

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix         = "iledger:"
	maxEntriesPerKey  = 10
	graceSeconds      = 300
	maxTTLSeconds     = 24 * 60 * 60 // cap pathological TTLs at 24h
	minTTLSeconds     = 60           // floor so tiny TTLs don't expire instantly
)

// Entry is one ledger record. Stored as JSON in a Redis list.
type Entry struct {
	IP  string `json:"ip"`
	TTL uint32 `json:"ttl"`
	TS  int64  `json:"ts"` // unix seconds
}

// Key builds the Redis key. Exported so verdict-api's reader can use the
// same key derivation — the Redis key format is the inter-service contract.
func Key(clientID, domain string) string {
	c := strings.ToLower(strings.TrimSpace(clientID))
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	if c == "" {
		c = "unknown"
	}
	return keyPrefix + c + ":" + d
}

// Write appends one ledger row per IP. clientID is typically the browser's
// public IP (the source of the DNS query). domain is the queried name
// (lowercase, trailing-dot stripped). ips is the set of A/AAAA addresses
// being returned. ttl is the smallest TTL among them.
//
// Best-effort: any Redis error is returned but callers should NOT block
// DNS resolution on this. Typical call site is a goroutine inside the
// resolver's deferred completion block.
func Write(ctx context.Context, rdb *redis.Client, clientID, domain string, ips []string, ttl uint32) error {
	if rdb == nil || len(ips) == 0 {
		return nil
	}
	if ttl < minTTLSeconds {
		ttl = minTTLSeconds
	}
	if ttl > maxTTLSeconds {
		ttl = maxTTLSeconds
	}
	now := time.Now().Unix()
	key := Key(clientID, domain)

	pipe := rdb.Pipeline()
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		b, err := json.Marshal(Entry{IP: ip, TTL: ttl, TS: now})
		if err != nil {
			continue
		}
		pipe.LPush(ctx, key, b)
	}
	pipe.LTrim(ctx, key, 0, maxEntriesPerKey-1)
	pipe.Expire(ctx, key, time.Duration(int64(ttl)+graceSeconds)*time.Second)
	_, err := pipe.Exec(ctx)
	return err
}
