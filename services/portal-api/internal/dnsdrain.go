// Package internal — drains the Redis stream `xgg:dns` into the
// dns_queries table. One row per resolver query. Best-effort: failure
// here is logged but doesn't crash portal-api.
package internal

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	stream = "xgg:dns"
	group  = "portal-api"
)

type DnsDrain struct {
	Pg  *pgxpool.Pool
	Rdb *redis.Client
}

// Start runs forever (until ctx cancels), draining the stream into Postgres.
// Creates the consumer group on first run.
func (d *DnsDrain) Start(ctx context.Context) {
	// Best-effort group create; ignore "BUSYGROUP" already-exists.
	_ = d.Rdb.XGroupCreateMkStream(ctx, stream, group, "$").Err()

	consumer := "portal-api-1"
	for {
		if ctx.Err() != nil {
			return
		}
		res, err := d.Rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    group,
			Consumer: consumer,
			Streams:  []string{stream, ">"},
			Count:    256,
			Block:    5 * time.Second,
		}).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			log.Warn().Err(err).Msg("dns-drain xreadgroup")
			time.Sleep(2 * time.Second)
			continue
		}
		for _, s := range res {
			ids := make([]string, 0, len(s.Messages))
			for _, m := range s.Messages {
				if err := d.insert(ctx, m.Values); err != nil {
					log.Warn().Err(err).Msg("dns-drain insert")
					continue
				}
				ids = append(ids, m.ID)
			}
			if len(ids) > 0 {
				_ = d.Rdb.XAck(ctx, stream, group, ids...).Err()
			}
		}
	}
}

func (d *DnsDrain) insert(ctx context.Context, v map[string]any) error {
	ts := str(v["ts"])
	parsedTs, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		parsedTs = time.Now().UTC()
	}
	dur, _ := strconv.Atoi(str(v["duration_ms"]))
	cacheHit := str(v["cache_hit"]) == "1" || str(v["cache_hit"]) == "true"
	sinkhole := str(v["sinkhole"]) == "1" || str(v["sinkhole"]) == "true"

	clientIP := str(v["client_ip"])
	// Postgres INET wants nil for unparseable / empty values, not "".
	var ip any
	if clientIP != "" {
		ip = clientIP
	}
	_, err = d.Pg.Exec(ctx, `
		INSERT INTO dns_queries (ts, domain, qtype, client_ip, client_id, verdict, cache_hit, duration_ms, sinkhole)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`,
		parsedTs,
		str(v["domain"]),
		str(v["qtype"]),
		ip,
		str(v["client_id"]),
		str(v["verdict"]),
		cacheHit,
		dur,
		sinkhole,
	)
	return err
}

func str(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return ""
	}
}
