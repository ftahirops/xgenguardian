// XGenGuardian — portal-api.
//
// Public read-only API for the Transparency Portal +
// password-gated admin API for the operator dashboard.
//
// Routes:
//   public:
//     GET  /healthz
//     GET  /v1/evidence/:id        full evidence bundle
//     GET  /v1/recent              recent verdicts (rate-limited, no PII)
//
//   admin (requires HTTP Basic, password from ADMIN_PASSWORD env):
//     GET  /v1/admin/stats         counters + last-N-hour buckets
//     GET  /v1/admin/queries       DNS query log (paged, filterable)
//     GET  /v1/admin/verdicts      URL verdicts (paged, filterable)
//
// Side process:
//   Drains the Redis stream `xgg:dns` into the dns_queries table.

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/portal-api/internal"
)

type server struct {
	pg     *pgxpool.Pool
	rdb    *redis.Client
	adminP string
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pg, err := pgxpool.New(ctx, env("DATABASE_URL", "postgres://xgg:xgg@localhost:5432/xgg"))
	if err != nil {
		log.Fatal().Err(err).Msg("postgres")
	}
	defer pg.Close()

	rdb := redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "localhost:6379")})

	adminP := os.Getenv("ADMIN_PASSWORD")
	if adminP == "" {
		log.Warn().Msg("ADMIN_PASSWORD not set — /v1/admin/* will refuse all requests")
	}

	s := &server{pg: pg, rdb: rdb, adminP: adminP}

	// Drain DNS stream → Postgres in the background.
	drain := &internal.DnsDrain{Pg: pg, Rdb: rdb}
	go drain.Start(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/v1/evidence/", s.getEvidence)
	mux.HandleFunc("/v1/recent", s.recent)

	mux.HandleFunc("/v1/admin/stats",    s.adminAuth(s.stats))
	mux.HandleFunc("/v1/admin/queries",  s.adminAuth(s.queries))
	mux.HandleFunc("/v1/admin/verdicts", s.adminAuth(s.verdicts))

	addr := env("LISTEN", "127.0.0.1:18081")
	srv := &http.Server{Addr: addr, Handler: cors(mux), ReadHeaderTimeout: 5 * time.Second}

	go func() {
		log.Info().Str("addr", addr).Msg("portal-api listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("serve")
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = srv.Shutdown(shutdownCtx)
}

// ─── auth ──────────────────────────────────────────────────────

func (s *server) adminAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminP == "" {
			http.Error(w, "admin disabled (ADMIN_PASSWORD unset)", http.StatusForbidden)
			return
		}
		_, pw, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pw), []byte(s.adminP)) != 1 {
			w.Header().Set("www-authenticate", `Basic realm="xgg-admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// ─── public ────────────────────────────────────────────────────

// evidenceRow is the deep-evidence payload returned by /v1/evidence/:id.
// Joins evidence with the originating urls + domain rows so the consumer
// (extension blocked.html, portal /report/[id]) renders the full picture
// in one round-trip.
type evidenceRow struct {
	EvidenceID     string         `json:"evidence_id"`

	// From `evidence`
	ScreenshotURL  *string        `json:"screenshot_url,omitempty"`
	DOMURL         *string        `json:"dom_url,omitempty"`
	HARURL         *string        `json:"har_url,omitempty"`
	VisualTopBrand *string        `json:"visual_top_brand,omitempty"`
	VisualTopScore *float64       `json:"visual_top_score,omitempty"`
	FaviconMatch   *string        `json:"favicon_match,omitempty"`
	FormActions    []string       `json:"form_actions,omitempty"`
	Signals        map[string]any `json:"signals,omitempty"`
	ReasonCodes    []string       `json:"reason_codes,omitempty"`
	LLMExplanation *string        `json:"llm_explanation,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`

	// From `urls`
	URL                *string  `json:"url,omitempty"`
	Domain             *string  `json:"domain,omitempty"`
	FinalURL           *string  `json:"final_url,omitempty"`
	RedirectChain      []string `json:"redirect_chain,omitempty"`
	Verdict            *string  `json:"verdict,omitempty"`
	VerdictConfidence  *float64 `json:"verdict_confidence,omitempty"`
	Grade              *string  `json:"grade,omitempty"`
	PageClass          *string  `json:"page_class,omitempty"`

	// From `domains` — the third clause of the universal phishing rule.
	Registrar          *string    `json:"registrar,omitempty"`
	RegisteredAt       *time.Time `json:"registered_at,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	CurrentASN         *int32     `json:"current_asn,omitempty"`
	CertIssuer         *string    `json:"cert_issuer,omitempty"`
	CertSHA256         *string    `json:"cert_sha256,omitempty"`
	BrandMatch         *string    `json:"brand_match,omitempty"`
	BrandCanonical     *bool      `json:"brand_canonical,omitempty"`
	ReputationScore    *float32   `json:"reputation_score,omitempty"`
	DomainAgeDays      *int       `json:"domain_age_days,omitempty"`

	// External corroborators (from scan_history.external_verdicts).
	External           map[string]any `json:"external,omitempty"`
}

func (s *server) getEvidence(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/evidence/")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var row evidenceRow
	var signalsJSON, externalJSON []byte
	err := s.pg.QueryRow(ctx, `
		SELECT
		  e.evidence_id::text,
		  e.screenshot_url, e.dom_url, e.har_url,
		  e.visual_top_brand, e.visual_top_score, e.favicon_match,
		  e.form_actions, e.signals, e.llm_explanation, e.created_at,
		  u.url, u.domain, u.final_url, u.redirect_chain,
		  u.verdict, u.verdict_confidence, u.grade, u.page_class,
		  d.registrar, d.registered_at, d.expires_at,
		  d.current_asn, d.cert_issuer, d.current_cert_sha256,
		  d.brand_match, d.brand_canonical, d.reputation_score,
		  (SELECT external_verdicts FROM scan_history
		     WHERE evidence_id = e.evidence_id
		     ORDER BY scanned_at DESC LIMIT 1) AS external
		FROM evidence e
		LEFT JOIN urls    u ON u.evidence_id = e.evidence_id
		LEFT JOIN domains d ON d.domain      = u.domain
		WHERE e.evidence_id = $1
	`, id).Scan(
		&row.EvidenceID,
		&row.ScreenshotURL, &row.DOMURL, &row.HARURL,
		&row.VisualTopBrand, &row.VisualTopScore, &row.FaviconMatch,
		&row.FormActions, &signalsJSON, &row.LLMExplanation, &row.CreatedAt,
		&row.URL, &row.Domain, &row.FinalURL, &row.RedirectChain,
		&row.Verdict, &row.VerdictConfidence, &row.Grade, &row.PageClass,
		&row.Registrar, &row.RegisteredAt, &row.ExpiresAt,
		&row.CurrentASN, &row.CertIssuer, &row.CertSHA256,
		&row.BrandMatch, &row.BrandCanonical, &row.ReputationScore,
		&externalJSON,
	)
	if err != nil {
		log.Warn().Str("id", id).Err(err).Msg("evidence lookup")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if len(signalsJSON) > 0 {
		_ = json.Unmarshal(signalsJSON, &row.Signals)
		// signals.codes[] is the canonical reason-code list emitted by fusion.
		// Promote it to its own field so the UI doesn't have to dig.
		if codes, ok := row.Signals["codes"].([]any); ok {
			for _, c := range codes {
				if s, ok := c.(string); ok {
					row.ReasonCodes = append(row.ReasonCodes, s)
				}
			}
		}
	}
	if len(externalJSON) > 0 {
		_ = json.Unmarshal(externalJSON, &row.External)
	}
	if row.RegisteredAt != nil && !row.RegisteredAt.IsZero() {
		days := int(time.Since(*row.RegisteredAt).Hours() / 24)
		row.DomainAgeDays = &days
	}

	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "public, max-age=60")
	w.Header().Set("access-control-allow-origin", "*") // extension calls this from chrome-extension://
	_ = json.NewEncoder(w).Encode(row)
}

func (s *server) recent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	rows, err := s.pg.Query(ctx, `
		SELECT evidence_id::text, visual_top_brand, visual_top_score, created_at
		FROM evidence ORDER BY created_at DESC LIMIT 25
	`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	out := []evidenceRow{}
	for rows.Next() {
		var e evidenceRow
		_ = rows.Scan(&e.EvidenceID, &e.VisualTopBrand, &e.VisualTopScore, &e.CreatedAt)
		out = append(out, e)
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ─── admin ─────────────────────────────────────────────────────

type adminStats struct {
	DnsTotal24h     int64            `json:"dns_total_24h"`
	DnsBlocked24h   int64            `json:"dns_blocked_24h"`
	DnsCacheHits24h int64            `json:"dns_cache_hits_24h"`
	Verdicts24h     int64            `json:"verdicts_24h"`
	Brands          int64            `json:"brands"`
	HourBuckets     []hourBucket     `json:"hour_buckets"`
	TopBlocked      []topBlocked     `json:"top_blocked"`
}

type hourBucket struct {
	Hour    time.Time `json:"hour"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
}

type topBlocked struct {
	Domain string `json:"domain"`
	Hits   int64  `json:"hits"`
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var st adminStats
	_ = s.pg.QueryRow(ctx, `SELECT count(*) FROM dns_queries WHERE ts > NOW() - INTERVAL '24 hours'`).Scan(&st.DnsTotal24h)
	_ = s.pg.QueryRow(ctx, `SELECT count(*) FROM dns_queries WHERE ts > NOW() - INTERVAL '24 hours' AND verdict='block'`).Scan(&st.DnsBlocked24h)
	_ = s.pg.QueryRow(ctx, `SELECT count(*) FROM dns_queries WHERE ts > NOW() - INTERVAL '24 hours' AND cache_hit`).Scan(&st.DnsCacheHits24h)
	_ = s.pg.QueryRow(ctx, `SELECT count(*) FROM evidence WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&st.Verdicts24h)
	_ = s.pg.QueryRow(ctx, `SELECT count(*) FROM brands`).Scan(&st.Brands)

	// hour buckets
	rows, _ := s.pg.Query(ctx, `
		SELECT date_trunc('hour', ts) AS h,
		       count(*),
		       count(*) FILTER (WHERE verdict='block')
		FROM dns_queries
		WHERE ts > NOW() - INTERVAL '24 hours'
		GROUP BY 1 ORDER BY 1
	`)
	if rows != nil {
		for rows.Next() {
			var b hourBucket
			_ = rows.Scan(&b.Hour, &b.Total, &b.Blocked)
			st.HourBuckets = append(st.HourBuckets, b)
		}
		rows.Close()
	}

	// top blocked
	rows, _ = s.pg.Query(ctx, `
		SELECT domain, count(*) FROM dns_queries
		WHERE ts > NOW() - INTERVAL '24 hours' AND verdict='block'
		GROUP BY domain ORDER BY 2 DESC LIMIT 20
	`)
	if rows != nil {
		for rows.Next() {
			var t topBlocked
			_ = rows.Scan(&t.Domain, &t.Hits)
			st.TopBlocked = append(st.TopBlocked, t)
		}
		rows.Close()
	}

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

type queryRow struct {
	TS         time.Time `json:"ts"`
	Domain     string    `json:"domain"`
	Qtype      string    `json:"qtype"`
	ClientIP   string    `json:"client_ip"`
	Verdict    string    `json:"verdict"`
	CacheHit   bool      `json:"cache_hit"`
	Sinkhole   bool      `json:"sinkhole"`
	DurationMs int       `json:"duration_ms"`
	ClientID   string    `json:"client_id"`
}

func (s *server) queries(w http.ResponseWriter, r *http.Request) {
	limit := atoiDef(r.URL.Query().Get("limit"), 20)
	if limit > 100 {
		limit = 100
	}
	if limit < 1 {
		limit = 20
	}
	offset := atoiDef(r.URL.Query().Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	q := r.URL.Query().Get("q")
	verdict := r.URL.Query().Get("verdict")

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Build WHERE once and reuse for both the data SELECT and the count.
	where := `WHERE 1=1`
	args := []any{}
	if q != "" {
		where += ` AND domain ILIKE $` + strconv.Itoa(len(args)+1)
		args = append(args, "%"+q+"%")
	}
	if verdict != "" {
		where += ` AND verdict = $` + strconv.Itoa(len(args)+1)
		args = append(args, verdict)
	}

	dataSQL := `SELECT ts, domain, COALESCE(qtype,''),
	                COALESCE(host(client_ip),''), COALESCE(verdict,''),
	                cache_hit, sinkhole,
	                COALESCE(duration_ms,0), COALESCE(client_id,'')
	         FROM dns_queries ` + where +
		` ORDER BY ts DESC LIMIT $` + strconv.Itoa(len(args)+1) +
		` OFFSET $` + strconv.Itoa(len(args)+2)
	dataArgs := append([]any{}, args...)
	dataArgs = append(dataArgs, limit, offset)

	rows, err := s.pg.Query(ctx, dataSQL, dataArgs...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := []queryRow{}
	for rows.Next() {
		var x queryRow
		if err := rows.Scan(&x.TS, &x.Domain, &x.Qtype, &x.ClientIP, &x.Verdict, &x.CacheHit, &x.Sinkhole, &x.DurationMs, &x.ClientID); err == nil {
			out = append(out, x)
		}
	}
	rows.Close()

	// Total count for the same WHERE so the UI can show "X of Y" and disable
	// Load More at the end. Uses the (ts DESC) index, count is fast at this scale.
	var total int
	_ = s.pg.QueryRow(ctx, `SELECT count(*) FROM dns_queries `+where, args...).Scan(&total)

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"rows":   out,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

type verdictRow struct {
	EvidenceID     string    `json:"evidence_id"`
	VisualTopBrand string    `json:"visual_top_brand"`
	VisualTopScore float64   `json:"visual_top_score"`
	CreatedAt      time.Time `json:"created_at"`
	URLHash        string    `json:"url_hash"`
}

func (s *server) verdicts(w http.ResponseWriter, r *http.Request) {
	limit := atoiDef(r.URL.Query().Get("limit"), 20)
	if limit > 100 {
		limit = 100
	}
	if limit < 1 {
		limit = 20
	}
	offset := atoiDef(r.URL.Query().Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	brand := r.URL.Query().Get("brand")

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	where := `WHERE 1=1`
	args := []any{}
	if brand != "" {
		where += ` AND visual_top_brand ILIKE $` + strconv.Itoa(len(args)+1)
		args = append(args, "%"+brand+"%")
	}
	dataSQL := `SELECT evidence_id::text, COALESCE(visual_top_brand,''),
	                COALESCE(visual_top_score,0), created_at,
	                COALESCE(encode(url_hash,'hex'),'')
	         FROM evidence ` + where +
		` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(len(args)+1) +
		` OFFSET $` + strconv.Itoa(len(args)+2)
	dataArgs := append([]any{}, args...)
	dataArgs = append(dataArgs, limit, offset)

	rows, err := s.pg.Query(ctx, dataSQL, dataArgs...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := []verdictRow{}
	for rows.Next() {
		var x verdictRow
		if err := rows.Scan(&x.EvidenceID, &x.VisualTopBrand, &x.VisualTopScore, &x.CreatedAt, &x.URLHash); err == nil {
			out = append(out, x)
		}
	}
	rows.Close()

	var total int
	_ = s.pg.QueryRow(ctx, `SELECT count(*) FROM evidence `+where, args...).Scan(&total)

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"rows":   out,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

// ─── helpers ──────────────────────────────────────────────────

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("access-control-allow-origin", "*")
		w.Header().Set("access-control-allow-headers", "authorization, content-type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func atoiDef(s string, d int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return d
	}
	return n
}
