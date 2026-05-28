// Package internal — VerdictService: implements the gRPC Verdict server.
package internal

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type VerdictService struct {
	Pg          *pgxpool.Pool
	Rdb         *redis.Client
	SandboxURL  string
	VisualURL   string
	Tier1Budget time.Duration
	Tier2Budget time.Duration
	// UnimplementedVerdictServer  // re-enable once `protoc-gen-go` stubs are wired
}

// CheckURL — see proto/verdict/v1/verdict.proto.
//
// Phase-1 flow:
//   1. Look up cached verdict in Redis. If fresh → return.
//   2. Run Tier-1 (≤250ms). If confident → cache + return.
//   3. Dispatch Tier-2 (sandbox + visual-match). If client wants to block,
//      return ANALYZING with a sinkhole CNAME; finish Tier-2 async and
//      cache the eventual verdict for the next caller.
//
// TODO XGG-9, XGG-10, XGG-18.
func (s *VerdictService) CheckURL(ctx context.Context /*, req *verdictv1.CheckURLRequest*/) error {
	_ = ctx
	return nil
}
