// trustreg-to-brandgraph — one-shot migrator.
//
// Reads the curated entries from internal/trustreg and writes them into
// the brand_hosts table (migration 0009). Per-host scope is guessed from
// subdomain prefix (login. → login, docs. → docs, cdn./gstatic.com → cdn,
// api. → api, console./portal./app. → app, checkout./pay. → payment,
// everything else → full-trust).
//
// Brands missing from the `brands` table are auto-inserted with the brand
// name from trustreg.Entry.Brand title-cased.
//
// Idempotent: ON CONFLICT (brand_id, host_pattern, scope) DO NOTHING.
//
// Usage:
//
//	go run tools/trustreg-to-brandgraph DATABASE_URL=postgres://...
//	go run tools/trustreg-to-brandgraph --dry-run
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xgenguardian/services/verdict-api/internal/trustreg"
)

// scope strings — kept in sync with migration 0009's CHECK constraint.
const (
	scopeFullTrust     = "full-trust"
	scopeLogin         = "login"
	scopePayment       = "payment"
	scopeOAuthRedirect = "oauth-redirect"
	scopeScriptSource  = "script-source"
	scopeCDN           = "cdn"
	scopeDocs          = "docs"
	scopeSupport       = "support"
	scopeApp           = "app"
	scopeAPI           = "api"
)

// guessScope — heuristic per-host scope assignment. Conservative: when
// in doubt, full-trust (matches existing trustreg behavior).
func guessScope(host string) string {
	h := strings.ToLower(strings.TrimPrefix(host, "."))
	first := strings.SplitN(h, ".", 2)[0]
	switch first {
	case "login", "signin", "sign-in", "signon", "logon", "auth", "accounts",
		"account", "idmsa", "appleid", "myaccount":
		return scopeLogin
	case "docs", "developer", "developers", "help", "manuals", "doc":
		return scopeDocs
	case "api":
		return scopeAPI
	case "console", "portal", "app", "dash", "dashboard", "admin", "manage",
		"manager", "studio":
		return scopeApp
	case "checkout", "pay", "payments", "billing", "buy":
		return scopePayment
	case "support", "contact":
		return scopeSupport
	case "cdn", "static", "assets", "media":
		return scopeCDN
	}
	// CDN-by-suffix heuristics — these widen the net for common CDN hosts.
	for _, sfx := range []string{
		".gstatic.com", ".googleusercontent.com", ".cloudfront.net",
		".akamaihd.net", ".doubleclick.net", ".googletagmanager.com",
		".googlevideo.com",
	} {
		if strings.HasSuffix(h, strings.TrimPrefix(sfx, ".")) {
			return scopeCDN
		}
	}
	return scopeFullTrust
}

// titleCase — best-effort brand-name display from a trustreg slug.
// "openai" → "OpenAI", "continue-dev" → "Continue Dev", "mail-ru" → "Mail Ru".
// Used only when the brand isn't already in the brands table.
func titleCase(slug string) string {
	special := map[string]string{
		"openai":        "OpenAI",
		"jetbrains":     "JetBrains",
		"cline":         "Cline",
		"continue-dev":  "Continue.dev",
		"rust-lang":     "Rust",
		"golang":        "Go",
		"npm":           "npm",
		"nodejs":        "Node.js",
		"python":        "Python",
		"docker":        "Docker",
		"kubernetes":    "Kubernetes",
		"homebrew":      "Homebrew",
		"huawei":        "Huawei",
		"mail-ru":       "Mail.ru",
		"perplexity":    "Perplexity",
		"huggingface":   "Hugging Face",
		"replicate":     "Replicate",
		"snowflake":     "Snowflake",
		"cursor":        "Cursor",
		"anthropic":     "Anthropic",
		"google":        "Google",
		"microsoft":     "Microsoft",
		"apple":         "Apple",
		"amazon":        "Amazon",
		"paypal":        "PayPal",
		"stripe":        "Stripe",
		"facebook-meta": "Meta",
		"twitter-x":     "Twitter / X",
		"tiktok":        "TikTok",
		"reddit":        "Reddit",
		"spotify":       "Spotify",
		"netflix":       "Netflix",
		"discord":       "Discord",
	}
	if v, ok := special[slug]; ok {
		return v
	}
	// Generic: replace dashes with spaces and title-case each word.
	parts := strings.Split(slug, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func main() {
	dryRun := flag.Bool("dry-run", false, "print actions without writing")
	flag.Parse()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://xgg:xgg@localhost:15432/xgg"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var pg *pgxpool.Pool
	if !*dryRun {
		var err error
		pg, err = pgxpool.New(ctx, dsn)
		if err != nil {
			log.Fatalf("pg connect: %v", err)
		}
		defer pg.Close()
	}

	entries := trustreg.Entries()
	fmt.Printf("loaded %d trustreg entries\n", len(entries))

	var brandIDsCreated, brandIDsExisting, hostsInserted, suffixesInserted, skipped int

	for _, e := range entries {
		// Skip the env-var-loaded "personal-infra" placeholder if it ever
		// surfaces here — those belong to operator-specific config, not
		// the curated graph.
		if e.Brand == "" || e.Brand == "local" || e.Brand == "personal-infra" {
			continue
		}

		displayName := titleCase(e.Brand)
		var brandID string

		if !*dryRun {
			// Try existing brand by display name first (case-insensitive).
			err := pg.QueryRow(ctx,
				`SELECT brand_id::text FROM brands WHERE LOWER(brand_name) = LOWER($1)`,
				displayName,
			).Scan(&brandID)
			if err != nil {
				// Create the brand row. canonical_domains is required (NOT NULL)
				// so seed it from the Hosts list.
				canonical := make([]string, 0, len(e.Hosts))
				for _, h := range e.Hosts {
					canonical = append(canonical, strings.ToLower(h))
				}
				err := pg.QueryRow(ctx,
					`INSERT INTO brands (brand_name, canonical_domains)
				     VALUES ($1, $2) RETURNING brand_id::text`,
					displayName, canonical,
				).Scan(&brandID)
				if err != nil {
					log.Printf("  [ERR] insert brand %q: %v", displayName, err)
					skipped++
					continue
				}
				brandIDsCreated++
				fmt.Printf("  + created brand %q (%s)\n", displayName, brandID[:8])
			} else {
				brandIDsExisting++
			}
		} else {
			brandID = "<dry-run>"
		}

		// Insert exact hosts.
		for _, h := range e.Hosts {
			scope := guessScope(h)
			if *dryRun {
				fmt.Printf("  - %-40s scope=%-12s brand=%s\n", h, scope, displayName)
				continue
			}
			_, err := pg.Exec(ctx,
				`INSERT INTO brand_hosts (brand_id, host_pattern, scope, source, confidence)
				 VALUES ($1, $2, $3, 'manual', 'high')
				 ON CONFLICT (brand_id, host_pattern, scope) DO NOTHING`,
				brandID, strings.ToLower(h), scope,
			)
			if err != nil {
				log.Printf("  [ERR] insert host %q: %v", h, err)
				skipped++
				continue
			}
			hostsInserted++
		}

		// Insert suffix patterns as `*.suffix`.
		for _, s := range e.Suffixes {
			sfx := strings.ToLower(strings.TrimPrefix(s, "."))
			pattern := "*." + sfx
			scope := guessScope(s)
			if *dryRun {
				fmt.Printf("  - %-40s scope=%-12s brand=%s\n", pattern, scope, displayName)
				continue
			}
			_, err := pg.Exec(ctx,
				`INSERT INTO brand_hosts (brand_id, host_pattern, scope, source, confidence)
				 VALUES ($1, $2, $3, 'manual', 'high')
				 ON CONFLICT (brand_id, host_pattern, scope) DO NOTHING`,
				brandID, pattern, scope,
			)
			if err != nil {
				log.Printf("  [ERR] insert suffix %q: %v", pattern, err)
				skipped++
				continue
			}
			suffixesInserted++
		}
	}

	fmt.Printf("\n=== migration summary ===\n")
	fmt.Printf("brands existing:  %d\n", brandIDsExisting)
	fmt.Printf("brands created:   %d\n", brandIDsCreated)
	fmt.Printf("hosts inserted:   %d\n", hostsInserted)
	fmt.Printf("suffixes inserted:%d\n", suffixesInserted)
	fmt.Printf("rows skipped:     %d\n", skipped)
}
