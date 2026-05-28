// XGenGuardian — healthcheck.
//
// One Go binary that pings every service and produces a single-line JSON
// summary suitable for status pages, smoke tests, and the operator dashboard.
//
//   $ healthcheck
//   {"overall":"healthy","resolver":"ok","verdict_api":"ok",...,"brands":47,"last_verdict_age_s":12}
//
// Exit codes:
//   0 — everything healthy
//   1 — one or more services degraded
//   2 — critical (postgres / resolver / verdict-api down)

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

type result struct {
	Overall          string `json:"overall"`
	Resolver         string `json:"resolver"`
	VerdictAPI       string `json:"verdict_api"`
	PortalAPI        string `json:"portal_api"`
	SandboxRender    string `json:"sandbox_render"`
	VisualMatch      string `json:"visual_match"`
	Portal           string `json:"portal"`
	Postgres         string `json:"postgres"`
	Brands           int    `json:"brands"`
	BlocklistDomains int    `json:"blocklist_domains,omitempty"`
	LastVerdictAgeS  int    `json:"last_verdict_age_s"`
}

func main() {
	r := result{Overall: "healthy"}
	bad, critBad := 0, 0

	probe := func(url string) string {
		client := &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}
		resp, err := client.Get(url)
		if err != nil {
			return "down"
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "degraded"
		}
		return "ok"
	}

	r.Resolver      = probe(envOr("RESOLVER_HEALTH", "https://localhost:8543/healthz"))
	r.VerdictAPI    = probe(envOr("VERDICT_HEALTH",  "http://localhost:18080/healthz"))
	r.PortalAPI     = probe(envOr("PORTAL_API_HEALTH","http://localhost:18081/healthz"))
	r.SandboxRender = probe(envOr("SANDBOX_HEALTH",  "http://localhost:8002/healthz"))
	r.VisualMatch   = probe(envOr("VISUAL_HEALTH",   "http://localhost:8003/healthz"))
	r.Portal        = probe(envOr("PORTAL_HEALTH",   "http://localhost:13000"))

	for name, v := range map[string]*string{
		"resolver": &r.Resolver, "verdict_api": &r.VerdictAPI,
	} {
		if *v != "ok" {
			critBad++
			_ = name
		}
	}
	for _, v := range []string{r.PortalAPI, r.SandboxRender, r.VisualMatch, r.Portal} {
		if v != "ok" {
			bad++
		}
	}

	// Postgres + counts
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dsn := envOr("DATABASE_URL", "postgres://xgg:xgg@localhost:5432/xgg")
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		r.Postgres = "down"
		critBad++
	} else {
		defer conn.Close(ctx)
		r.Postgres = "ok"
		_ = conn.QueryRow(ctx, "SELECT count(*) FROM brands").Scan(&r.Brands)
		var ts *time.Time
		if err := conn.QueryRow(ctx, "SELECT max(created_at) FROM evidence").Scan(&ts); err == nil && ts != nil {
			r.LastVerdictAgeS = int(time.Since(*ts).Seconds())
		} else {
			r.LastVerdictAgeS = -1
		}
	}

	switch {
	case critBad > 0:
		r.Overall = "critical"
	case bad > 0 || r.Brands == 0:
		r.Overall = "degraded"
	}

	b, _ := json.Marshal(r)
	fmt.Println(string(b))

	switch r.Overall {
	case "healthy":
		os.Exit(0)
	case "degraded":
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
