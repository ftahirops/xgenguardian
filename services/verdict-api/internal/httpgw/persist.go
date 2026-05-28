// persist.go — write-side of the pipeline. Inserts evidence + url +
// scan_history rows so /v1/evidence/:id can serve a full deep payload and
// the scheduler has fresh fingerprints to diff against.
//
// Idempotent on url_hash: a second scan of the same URL produces a new
// evidence row + scan_history row and updates the urls row's evidence_id
// pointer. Old evidence rows stay for the audit trail until the scheduler's
// expiry sweep collects them.

package httpgw

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/fusion"
	"github.com/xgenguardian/services/verdict-api/internal/trustreg"
)

// urlHash — canonical key shared with /report/[id] lookups and the resolver
// cache. Lower-cases the scheme + host, leaves path/query as-is.
func urlHash(rawurl string) []byte {
	s := rawurl
	if i := strings.Index(s, "://"); i > 0 {
		s = strings.ToLower(s[:i+3]) + s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i > 0 {
		head := s[:i]
		s = strings.ToLower(head) + s[i:]
	}
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// persistScan writes evidence + urls + scan_history rows for a completed
// pipeline run. All writes happen in one transaction; a failure leaves the
// DB untouched.
//
// The url row holds the latest grade/verdict/fingerprints (drift detection
// compares against these). The evidence row holds the renderable artifacts.
// scan_history is append-only for audit.
func persistScan(
	ctx context.Context,
	pg *pgxpool.Pool,
	in fusion.Inputs,
	out fusion.Output,
	render *renderResponse,
	codes []string,
	evidenceID string,
	finalVerdict string,
	pageClass string,
	grade string,
	tier1Score float64,
) error {
	if pg == nil || evidenceID == "" {
		return nil // nothing to persist (test paths, schema-less runs)
	}

	// Compose the signals JSON for the evidence row. We embed both the raw
	// fusion signals (analyst view) and the canonical codes (user view).
	signalsJSON, _ := json.Marshal(map[string]any{
		"signals": out.Signals,
		"codes":   codes,
	})

	formActions := []string{}
	if render != nil {
		for _, f := range render.Forms {
			if f.HasPassword {
				formActions = append(formActions, f.Action)
			}
		}
	}

	tx, err := pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Ensure the domain row exists so urls.domain FK is satisfied.
	if _, err := tx.Exec(ctx, `
		INSERT INTO domains (domain, last_seen)
		VALUES ($1, NOW())
		ON CONFLICT (domain) DO UPDATE SET last_seen = NOW()
	`, in.Domain); err != nil {
		return err
	}

	// Persist evidence.
	var screenshotURL, domURL, harURL, finalURL, faviconMatch string
	if render != nil {
		screenshotURL = render.ScreenshotURL
		domURL        = render.DOMURL
		harURL        = render.HARURL
		finalURL      = render.FinalURL
	}
	visualTopBrand := in.VisualTopBrand
	if in.FaviconMatchBrand != "" {
		faviconMatch = in.FaviconMatchBrand
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO evidence (
		  evidence_id, screenshot_url, dom_url, har_url,
		  visual_top_brand, visual_top_score, favicon_match,
		  form_actions, signals, created_at, url_hash
		) VALUES ($1, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''),
		          NULLIF($5,''), $6, NULLIF($7,''),
		          $8, $9, NOW(), $10)
		ON CONFLICT (evidence_id) DO UPDATE SET
		  signals = EXCLUDED.signals
	`,
		evidenceID,
		screenshotURL, domURL, harURL,
		visualTopBrand, in.VisualTopScore, faviconMatch,
		formActions, signalsJSON,
		urlHash(in.URL),
	); err != nil {
		return err
	}

	// Upsert the urls row. Compose the redirect_chain from render if present.
	var redirectChain []string
	if render != nil {
		redirectChain = make([]string, 0, len(render.Forms))
		// renderResponse doesn't currently carry redirect_chain through to
		// here — sandbox-render returns it but the gateway struct dropped
		// the field. Future cleanup: thread it through. For now, leave nil
		// and let scheduler.drift treat empty as "no baseline".
		_ = redirectChain
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO urls (
		  url_hash, url, domain, final_url,
		  verdict, verdict_confidence, evidence_id,
		  last_scanned_at, grade, page_class,
		  last_seen
		) VALUES (
		  $1, $2, $3, NULLIF($4,''),
		  $5, $6, $7,
		  NOW(), NULLIF($8,''), $9,
		  NOW()
		)
		ON CONFLICT (url_hash) DO UPDATE SET
		  final_url          = EXCLUDED.final_url,
		  verdict            = EXCLUDED.verdict,
		  verdict_confidence = EXCLUDED.verdict_confidence,
		  evidence_id        = EXCLUDED.evidence_id,
		  last_scanned_at    = NOW(),
		  grade              = EXCLUDED.grade,
		  page_class         = EXCLUDED.page_class,
		  last_seen          = NOW()
	`,
		urlHash(in.URL), in.URL, in.Domain, finalURL,
		strings.ToLower(finalVerdict), out.Confidence, evidenceID,
		grade, pageClass,
	); err != nil {
		return err
	}

	// Append to scan_history.
	if _, err := tx.Exec(ctx, `
		INSERT INTO scan_history (
		  url_hash, scanned_at,
		  tier1_score, tier2_score, verdict, verdict_confidence,
		  evidence_id
		) VALUES ($1, NOW(), $2, $3, $4, $5, $6)
	`,
		urlHash(in.URL),
		tier1Score, out.Confidence, strings.ToLower(finalVerdict), out.Confidence,
		evidenceID,
	); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

// sharedHostingDomains — popular platforms where each path is effectively
// a separate tenant. We never auto-block based on the bare domain matching
// feed_entries; we require an exact URL match for these.
var sharedHostingDomains = map[string]struct{}{
	"github.com":                  {},
	"raw.githubusercontent.com":   {},
	"githubusercontent.com":       {},
	"gitlab.com":                  {},
	"bitbucket.org":               {},
	"cdn.discordapp.com":          {},
	"discordapp.com":              {},
	"media.discordapp.net":        {},
	"vercel.app":                  {},
	"netlify.app":                 {},
	"pages.dev":                   {},
	"workers.dev":                 {},
	"herokuapp.com":               {},
	"blogspot.com":                {},
	"wordpress.com":               {},
	"medium.com":                  {},
	"telegra.ph":                  {},
	"t.me":                        {},
	"ngrok.io":                    {},
	"ngrok-free.app":              {},
	"cfargotunnel.com":            {},
	"trycloudflare.com":           {},
	"web.app":                     {},
	"firebaseapp.com":             {},
	"appspot.com":                 {},
	"r2.dev":                      {},
	"amazonaws.com":               {},
	"azureedge.net":               {},
	"cloudfront.net":              {},
	// Added 2026-05-27 after fp-bench surfaced FPs:
	"sites.google.com":            {},
	"storage.googleapis.com":      {},
	"firebasestorage.googleapis.com": {},
	"googleusercontent.com":       {},
	"googleapis.com":              {},
	"s3.amazonaws.com":            {},
	"backblazeb2.com":             {},
	"b-cdn.net":                   {},
	"fly.dev":                     {},
	"replit.dev":                  {},
	"glitch.me":                   {},
	"webflow.io":                  {},
	"squarespace.com":             {},
	"wixsite.com":                 {},
	"weebly.com":                  {},
	"shopify.com":                 {},
	"myshopify.com":               {},
}

// isSharedHosting reports whether domain belongs to a shared-hosting platform
// (multi-tenant subdomain space). Matches both bare and subdomain forms.
func isSharedHosting(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if _, ok := sharedHostingDomains[d]; ok {
		return true
	}
	for suffix := range sharedHostingDomains {
		if strings.HasSuffix(d, "."+suffix) {
			return true
		}
	}
	return false
}

// FeedHit captures the source-tiered result of a feed_entries lookup.
// Callers consume both the sources and the confidence to decide whether
// to auto-BLOCK (high) or escalate to deep scan (medium/low).
type FeedHit struct {
	// Sources — distinct feed sources that matched (URLhaus, OpenPhish, ...).
	Sources []string
	// HighSources — subset of Sources whose confidence='high'. A single hit
	// here is sufficient to BLOCK. URLhaus, OpenPhish, Web Risk, and
	// manually-curated IOC sets all count as high.
	HighSources []string
	// MediumSources — subset whose confidence='medium'. Single hit alone
	// is advisory (force Tier-2, optional WARN); two or more across distinct
	// sources is BLOCK by consensus.
	MediumSources []string
	// LowSources — subset whose confidence='low'. Informational only,
	// never blocks on its own.
	LowSources []string
	// Categories — distinct content-category labels associated with the
	// matched rows. Lets the policy honor per-mode category-block toggles
	// (adult/gambling/piracy/crack_keygen/malvertising) instead of treating
	// every high-confidence feed equally.
	Categories []string
}

// Hit reports whether at least one source matched.
func (h FeedHit) Hit() bool { return len(h.Sources) > 0 }

// ShouldBlock encodes the consensus rule:
//
//	high-confidence hit         -> block
//	2+ medium hits (distinct)   -> block
//	otherwise                   -> advisory (caller may WARN + force Tier-2)
func (h FeedHit) ShouldBlock() bool {
	return len(h.HighSources) > 0 || len(h.MediumSources) >= 2
}

// queryFeedHit asks Postgres whether the URL — and, for non-shared-hosting
// domains, the domain itself — has an entry in feed_entries within the last
// 14 days. Returns a tiered result so the policy can apply consensus rules.
//
// Shared-hosting domains (github.com, vercel.app, discordapp.com etc.) are
// matched on exact URL only: many of these legitimately appear in URLhaus
// because *some* tenant hosted malware, but the platform itself is fine.
func queryFeedHit(ctx context.Context, pg *pgxpool.Pool, rawurl, domain string) (FeedHit, error) {
	if pg == nil {
		return FeedHit{}, nil
	}
	var rows pgx.Rows
	var err error
	// Trusted-identity brands (amazon.com, accounts.google.com, github.com,
	// login.microsoftonline.com etc.) get the same exact-URL-only treatment
	// as shared hosting. One bad feed row containing "https://www.Amazon.com"
	// must NOT blacklist the whole brand. The trustreg has a small curated
	// list of major brands; everything else falls through to the broader
	// (url OR domain) match below.
	if isSharedHosting(domain) || trustreg.IsTrusted(domain) {
		rows, err = pg.Query(ctx, `
			SELECT DISTINCT source, confidence, category FROM feed_entries
			WHERE url = $1
			  AND last_seen > NOW() - INTERVAL '14 days'
			LIMIT 8
		`, rawurl)
	} else {
		rows, err = pg.Query(ctx, `
			SELECT DISTINCT source, confidence, category FROM feed_entries
			WHERE (url = $1 OR domain = $2)
			  AND last_seen > NOW() - INTERVAL '14 days'
			LIMIT 8
		`, rawurl, domain)
	}
	if err != nil {
		log.Warn().Err(err).Msg("feed_entries query")
		return FeedHit{}, err
	}
	defer rows.Close()

	out := FeedHit{}
	catSeen := map[string]bool{}
	for rows.Next() {
		var src, conf, cat string
		if err := rows.Scan(&src, &conf, &cat); err != nil {
			continue
		}
		out.Sources = append(out.Sources, src)
		switch conf {
		case "high":
			out.HighSources = append(out.HighSources, src)
		case "low":
			out.LowSources = append(out.LowSources, src)
		default: // medium or unrecognized -> treat as medium
			out.MediumSources = append(out.MediumSources, src)
		}
		if cat != "" && !catSeen[cat] {
			catSeen[cat] = true
			out.Categories = append(out.Categories, cat)
		}
	}
	return out, nil
}

// chooseGrade derives a single trust grade from the fusion verdict +
// confidence. The scheduler will recompute this on next scan with full
// history; this is the inline value so the URL has a grade after first scan.
func chooseGrade(verdict string, confidence float64) string {
	switch verdict {
	case "BLOCK":
		if confidence >= 0.95 {
			return "F+"
		}
		return "F"
	case "WARN":
		return "D"
	case "ISOLATE":
		return "C"
	case "ALLOW", "CLEAN":
		if confidence >= 0.9 {
			return "A"
		}
		if confidence >= 0.5 {
			return "B"
		}
		return "C"
	}
	return "C"
}

// pageClassOf — mirrors the extension's heuristic so we tag URLs with the
// same page_class the extension uses for sensitive-class cache bypass.
// docs/UNIFIED-PLAN.md §4.2.
func pageClassOf(rawurl string) string {
	l := strings.ToLower(rawurl)
	switch {
	case strings.Contains(l, "/oauth"), strings.Contains(l, "/authorize"), strings.Contains(l, "/consent"):
		return "oauth"
	case strings.Contains(l, "/login"), strings.Contains(l, "/signin"), strings.Contains(l, "/sign-in"), strings.Contains(l, "/log-in"):
		return "login"
	case strings.Contains(l, "/verify"), strings.Contains(l, "/mfa"), strings.Contains(l, "/2fa"), strings.Contains(l, "/recover"), strings.Contains(l, "/reset"):
		return "login"
	case strings.Contains(l, "/payment"), strings.Contains(l, "/pay"), strings.Contains(l, "/checkout"), strings.Contains(l, "/billing"):
		return "payment"
	case strings.Contains(l, "/admin"), strings.Contains(l, "/dashboard"), strings.Contains(l, "/console"):
		return "admin"
	case strings.Contains(l, "/download"):
		return "download"
	}
	return "generic"
}

