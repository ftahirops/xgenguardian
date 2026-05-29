// XGenGuardian — verdict-api entry point.
//
// Central scoring service. Receives CheckURL / CheckDomain RPCs from
// resolver, browser extension, portal. Runs the Tier-1 / Tier-2 pipeline
// and returns a verdict.
//
// Phase-1 scope: rule-based Tier-1 (WHOIS, cert, lexical, homoglyph) +
// async dispatch to sandbox-render & visual-match for Tier-2.

package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"

	"github.com/xgenguardian/services/verdict-api/internal/brandgraph"
	"github.com/xgenguardian/services/verdict-api/internal/feeds"
	"github.com/xgenguardian/services/verdict-api/internal/httpgw"
	"github.com/xgenguardian/services/verdict-api/internal/metrics"
	"github.com/xgenguardian/services/verdict-api/internal/oauthreg"
	"github.com/xgenguardian/services/verdict-api/internal/rdap"
	"github.com/xgenguardian/services/verdict-api/internal/registry"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Register Prometheus metrics before anything else.
	metrics.MustRegister(prometheus.DefaultRegisterer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pg, err := pgxpool.New(ctx, env("DATABASE_URL", "postgres://xgg:xgg@localhost:5432/xgg"))
	if err != nil {
		log.Fatal().Err(err).Msg("postgres connect")
	}
	defer pg.Close()

	rdb := redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "localhost:6379")})

	svc := &verdictService{
		pg:          pg,
		rdb:         rdb,
		sandboxURL:  env("SANDBOX_RENDER_URL", "http://localhost:8002"),
		visualURL:   env("VISUAL_MATCH_URL", "http://localhost:8003"),
		tier1Budget: 250 * time.Millisecond,
		tier2Budget: 6 * time.Second,
	}

	lis, err := net.Listen("tcp", env("LISTEN", ":50051"))
	if err != nil {
		log.Fatal().Err(err).Msg("listen")
	}
	srv := grpc.NewServer()
	// verdictv1.RegisterVerdictServer(srv, svc) // after `protoc` generates stubs

	_ = svc

	go func() {
		log.Info().Str("addr", lis.Addr().String()).Msg("verdict-api gRPC listening")
		if err := srv.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("serve")
		}
	}()

	// Brand registry: hydrate from Postgres, refresh every 5 minutes.
	brandsCache := registry.New(pg)
	if err := brandsCache.Start(ctx, 5*time.Minute); err != nil {
		log.Warn().Err(err).Msg("brand registry initial load failed; starting empty")
	}

	// Brand-relationship graph (action-scoped trust): replaces flat trustreg
	// hostname matching with (host, scope) edges loaded from brand_hosts.
	// On Postgres failure, brandgraph falls back to its in-process stub.
	if bgStore, err := brandgraph.NewStore(ctx, pg); err != nil {
		log.Warn().Err(err).Msg("brand_hosts initial load failed; falling back to stub")
	} else {
		brandgraph.SetStore(bgStore)
		ex, sfx := bgStore.Stats()
		log.Info().Int("exact", ex).Int("suffix", sfx).Msg("brandgraph hydrated")
	}

	// RDAP corroborator — populates fusion.Inputs.DomainAge so the third
	// clause of the universal phishing rule can fire. Best-effort: if the
	// IANA bootstrap fetch fails we keep running with the client disabled.
	rdapClient := rdap.New()
	if err := rdapClient.Start(ctx); err != nil {
		log.Warn().Err(err).Msg("rdap bootstrap failed; domain-age signal disabled")
		rdapClient = nil
	}

	// Google Web Risk corroborator — only enabled when GOOGLE_WEBRISK_API_KEY
	// is set. Without a key we leave fusion.Inputs.GSBClean as nil ("not
	// consulted") so it doesn't falsely up- or down-weight the verdict.
	var webRisk *feeds.WebRiskClient
	if k := os.Getenv("GOOGLE_WEBRISK_API_KEY"); k != "" {
		webRisk = feeds.NewWebRisk(k)
	}

	// OAuth client_id reputation registry (§16.4).
	oauthCache := oauthreg.New(pg)
	if err := oauthCache.Start(ctx, 10*time.Minute); err != nil {
		log.Warn().Err(err).Msg("oauth registry initial load failed; check unavailable")
		oauthCache = nil
	}

	// Optional persistent session log (one JSONL line per verdict).
	// Enabled by setting SESSION_LOG_DIR; used during internal testing.
	httpgw.EnableSessionLog()

	// Shared HTTP client for sandbox-render and visual-match calls.
	// A single pooled transport avoids ephemeral-port exhaustion under load.
	// Per-call timeouts are applied via context, not on the Client directly,
	// so idle connections can be reused across calls.
	sharedHTTPClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
		// No Timeout here — per-request context deadline is used instead.
	}

	// HTTP gateway alongside gRPC.
	httpAddr := env("HTTP_LISTEN", "127.0.0.1:18080")
	gw := &httpgw.Server{
		Pg:               pg,
		Rdb:              rdb,
		Brands:           brandsCache,
		RDAP:             rdapClient,
		WebRisk:          webRisk,
		OAuthReg:         oauthCache,
		Tier1Budget:      svc.tier1Budget,
		SharedHTTPClient: sharedHTTPClient,
	}
	go func() {
		log.Info().Str("addr", httpAddr).Msg("verdict-api HTTP listening")
		if err := http.ListenAndServe(httpAddr, gw.Routes()); err != nil {
			log.Fatal().Err(err).Msg("http serve")
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	srv.GracefulStop()
}

// verdictService is the gRPC server impl. Will register against the
// generated VerdictServer interface once protoc stubs are wired (see
// scripts/gen-proto.sh). For Phase-1 the HTTP gateway alone is sufficient.
type verdictService struct {
	pg          *pgxpool.Pool
	rdb         *redis.Client
	sandboxURL  string
	visualURL   string
	tier1Budget time.Duration
	tier2Budget time.Duration
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
