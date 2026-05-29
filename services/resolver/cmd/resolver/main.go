// XGenGuardian — DoH/DoT resolver entry point.
//
// Responsibilities:
//   1. Terminate DoH (RFC 8484) over HTTPS at /dns-query.
//   2. Check Redis verdict cache; if HIT → return real IP or sinkhole.
//   3. On MISS, run cheap local checks (Tranco allow Bloom, blocklist Bloom).
//   4. If still unknown, call verdict-api Tier-1; respect 250ms budget.
//   5. If verdict ANALYZING → return sinkhole CNAME pointing to scan portal.
//
// This is the Phase-1 skeleton. DNSSEC validation, QNAME minimization,
// and DoT termination are TODO (tracked as separate tickets).

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/resolver/internal/iledger"
	resolvermetrics "github.com/xgenguardian/services/resolver/internal/metrics"
	"github.com/xgenguardian/services/resolver/internal/rebind"
)

type Config struct {
	DNSListenUDP    string // classic DNS, e.g. ":53" (public-facing)
	DNSListenTCP    string // classic DNS over TCP, e.g. ":53"
	DoHListenAddr   string // optional DoH HTTPS endpoint; empty = disabled
	DoHTLSCert      string
	DoHTLSKey       string
	UpstreamAddr    string // recursive resolver to delegate to (e.g. 9.9.9.9:53)
	RedisAddr       string
	VerdictAPIAddr  string
	SinkholeIP      string // returned for BLOCK
	InterstitialIP  string // returned for ANALYZING/WARN
	BlocklistPath   string // path to newline-delimited domains
	AllowlistPath   string // Tranco top-1M
	NeverBlockPath  string // permanent never-NXDOMAIN list (one domain per line)
}

type Resolver struct {
	cfg        Config
	cache      *redis.Client
	bfMu       sync.RWMutex
	blockBF    *bloom.BloomFilter
	allowBF    *bloom.BloomFilter
	neverBlock map[string]struct{} // permanent never-NXDOMAIN list (matches suffixes)
	upstream   *dns.Client
}

// sharedHostingSuffixes — platforms where each subdomain is a separate
// tenant. For these we never-block ONLY the bare domain, not subdomains.
// Otherwise an attacker squats `evil-paypal-login.blogspot.com` and we
// allow it just because blogspot.com is popular.
var sharedHostingSuffixes = map[string]struct{}{
	"blogspot.com":       {},
	"blogger.com":        {},
	"webflow.io":         {},
	"weebly.com":         {},
	"weeblysite.com":     {},
	"github.io":          {},
	"gitlab.io":          {},
	"vercel.app":         {},
	"netlify.app":        {},
	"netlify.com":        {},
	"herokuapp.com":      {},
	"repl.co":            {},
	"replit.app":         {},
	"replit.dev":         {},
	"fly.dev":            {},
	"pages.dev":          {},
	"workers.dev":        {},
	"r2.dev":             {},
	"firebaseapp.com":    {},
	"web.app":            {},
	"appspot.com":        {},
	"azurewebsites.net":  {},
	"azurestaticapps.net": {},
	"glitch.me":          {},
	"surge.sh":           {},
	"onrender.com":       {},
	"render.app":         {},
	"deno.dev":           {},
	"shopify.com":        {},
	"myshopify.com":      {},
	"wordpress.com":      {},
	"wixsite.com":        {},
	"squarespace.com":    {},
	"medium.com":         {},
	"substack.com":       {},
	"tumblr.com":         {},
	"livejournal.com":    {},
	"tripod.com":         {},
	"angelfire.com":      {},
	"sites.google.com":   {},
	"docs.google.com":    {},
	"drive.google.com":   {},
	"forms.gle":          {},
	"goo.gl":             {},
	"bit.ly":             {},
	"tinyurl.com":        {},
	"t.co":               {},
	"discord.gg":         {},
	"telegra.ph":         {},
	"t.me":               {},
}

// isNeverBlock — checks `domain` and every parent suffix against the
// permanent never-block set. Entry "paypal.com" matches "paypal.com",
// "signin.paypal.com", and "objects.paypal.com".
//
// EXCEPTION: shared-hosting suffixes (blogspot.com, webflow.io, vercel.app,
// etc.) match exactly only — they shouldn't be allowed to immunize their
// tenant subdomains. So `defre321.blogspot.com` is NOT covered by a
// never-block entry for `blogspot.com`.
func (r *Resolver) isNeverBlock(domain string) bool {
	r.bfMu.RLock()
	defer r.bfMu.RUnlock()
	if r.neverBlock == nil {
		return false
	}
	d := domain
	for {
		if _, ok := r.neverBlock[d]; ok {
			// If we matched on a shared-hosting suffix while looking up a
			// subdomain (i.e. d != original domain), the match doesn't count.
			if d != domain {
				if _, isShared := sharedHostingSuffixes[d]; isShared {
					// keep climbing
					i := strings.IndexByte(d, '.')
					if i < 0 {
						return false
					}
					d = d[i+1:]
					continue
				}
			}
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
	}
}

// blockHas / allowHas — concurrency-safe Bloom probes. Held briefly under
// an RLock so SIGHUP-driven hot reload can swap the filters under us.
func (r *Resolver) blockHas(s string) bool {
	r.bfMu.RLock()
	defer r.bfMu.RUnlock()
	return r.blockBF.TestString(s)
}
func (r *Resolver) allowHas(s string) bool {
	r.bfMu.RLock()
	defer r.bfMu.RUnlock()
	return r.allowBF.TestString(s)
}

// loadNeverBlock — reads the permanent allowlist file plus the top-N rows
// of Tranco. Tranco top-10k auto-promotes to never-block because that's
// the threshold where false-positives from threat-intel feeds are real
// (newly-popular legitimate sites, sites with one abused subpath, etc.).
// Anything below the top-N stays subject to the strict blocklist.
func loadNeverBlock(path string) map[string]struct{} {
	out := map[string]struct{}{}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				out[strings.ToLower(line)] = struct{}{}
			}
		} else {
			log.Warn().Str("path", path).Err(err).Msg("never-block file missing")
		}
	}
	// Promote Tranco top-N to never-block. N defaults to 10000; set to
	// 0 to disable. We read the same Tranco file the allowlist uses.
	topN := envInt("PROMOTE_TRANCO_TOP_N", 10000)
	trancoPath := os.Getenv("ALLOWLIST_PATH")
	if trancoPath == "" {
		trancoPath = "./data/tranco.txt"
	}
	if topN > 0 {
		if b, err := os.ReadFile(trancoPath); err == nil {
			added := 0
			for _, line := range strings.Split(string(b), "\n") {
				if added >= topN {
					break
				}
				d := strings.TrimSpace(strings.ToLower(line))
				if d == "" {
					continue
				}
				if _, dup := out[d]; !dup {
					out[d] = struct{}{}
					added++
				} else {
					added++
				}
			}
			log.Info().Int("tranco_top_n", topN).Msg("promoted Tranco top to never-block")
		}
	}
	return out
}

// reloadBloom — rebuilds both Bloom filters AND the never-block set from
// disk and atomically swaps them under a write-lock. Called from the
// SIGHUP goroutine after the blocklist-fetcher writes new files.
func (r *Resolver) reloadBloom() {
	t0 := time.Now()
	newBlock := loadBloom(r.cfg.BlocklistPath, 5_000_000, 0.001)
	newAllow := loadBloom(r.cfg.AllowlistPath, 1_000_000, 0.001)
	newNB    := loadNeverBlock(r.cfg.NeverBlockPath)
	r.bfMu.Lock()
	r.blockBF = newBlock
	r.allowBF = newAllow
	r.neverBlock = newNB
	r.bfMu.Unlock()
	log.Info().Dur("dur", time.Since(t0)).Msg("bloom filters reloaded")
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Register Prometheus metrics before anything else.
	resolvermetrics.MustRegister(prometheus.DefaultRegisterer)

	// Write our PID where the blocklist-refresh systemd unit can find it,
	// so it can send us SIGHUP after a successful fetch.
	if pidPath := env("PID_FILE", "/run/xgg-resolver.pid"); pidPath != "" {
		_ = os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644)
		defer os.Remove(pidPath)
	}

	cfg := Config{
		DNSListenUDP:   env("DNS_LISTEN_UDP", ":53"),
		DNSListenTCP:   env("DNS_LISTEN_TCP", ":53"),
		DoHListenAddr:  env("DOH_LISTEN", ""), // empty = disabled
		DoHTLSCert:     env("DOH_TLS_CERT", "tls/cert.pem"),
		DoHTLSKey:      env("DOH_TLS_KEY", "tls/key.pem"),
		UpstreamAddr:   env("RESOLVER_UPSTREAM", "9.9.9.9:53"),
		RedisAddr:      env("REDIS_ADDR", "localhost:6379"),
		VerdictAPIAddr: env("VERDICT_API_ADDR", "http://localhost:18080"),
		SinkholeIP:     env("SINKHOLE_IP", "0.0.0.0"),
		InterstitialIP: env("INTERSTITIAL_IP", "127.0.0.2"),
		// Default to the STRICT-only file. Anything in strict has crossed
		// the 0%-FP confidence bar (2+ independent feeds, or a phishing /
		// malware feed). Set BLOCKLIST_PATH=blocklist.txt to revert to the
		// union-of-everything file (more recall, more FP risk).
		BlocklistPath:  env("BLOCKLIST_PATH", "./data/blocklist.strict.txt"),
		AllowlistPath:  env("ALLOWLIST_PATH", "./data/tranco.txt"),
		NeverBlockPath: env("NEVER_BLOCK_PATH", "./data/never-block.txt"),
	}
	flag.Parse()

	r := &Resolver{
		cfg:        cfg,
		cache:      redis.NewClient(&redis.Options{Addr: cfg.RedisAddr}),
		blockBF:    loadBloom(cfg.BlocklistPath, 5_000_000, 0.001),
		allowBF:    loadBloom(cfg.AllowlistPath, 1_000_000, 0.001),
		neverBlock: loadNeverBlock(cfg.NeverBlockPath),
		upstream:   &dns.Client{Net: "udp", Timeout: 2 * time.Second},
	}
	log.Info().Int("never_block_entries", len(r.neverBlock)).Msg("never-block guard loaded")

	// --- classic DNS server on UDP + TCP (the public-facing path) ---
	// This is the simple "set your DNS to 135.181.79.27" interface. It
	// answers every standard DNS client.
	dns.HandleFunc(".", r.dnsHandler)

	udpSrv := &dns.Server{Addr: cfg.DNSListenUDP, Net: "udp"}
	tcpSrv := &dns.Server{Addr: cfg.DNSListenTCP, Net: "tcp"}

	go func() {
		log.Info().Str("addr", cfg.DNSListenUDP).Msg("DNS resolver listening (UDP)")
		if err := udpSrv.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("udp server crashed")
		}
	}()
	go func() {
		log.Info().Str("addr", cfg.DNSListenTCP).Msg("DNS resolver listening (TCP)")
		if err := tcpSrv.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("tcp server crashed")
		}
	}()

	// --- optional DoH HTTPS endpoint ---
	// Off by default for the simple setup; enable by setting DOH_LISTEN=:8543.
	var dohSrv *http.Server
	if cfg.DoHListenAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", r.handleDoH)
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		dohSrv = &http.Server{Addr: cfg.DoHListenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Info().Str("addr", cfg.DoHListenAddr).Msg("DoH resolver listening")
			err := dohSrv.ListenAndServeTLS(cfg.DoHTLSCert, cfg.DoHTLSKey)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn().Err(err).Msg("DoH server crashed (continuing with classic DNS)")
			}
		}()
	}

	// --- Prometheus metrics HTTP listener ---
	// Separate small HTTP server on METRICS_LISTEN (default 127.0.0.1:19053).
	// Operators should firewall this port; the data is operational counters only.
	metricsAddr := env("METRICS_LISTEN", "127.0.0.1:19053")
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	metricsSrv := &http.Server{Addr: metricsAddr, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Info().Str("addr", metricsAddr).Msg("resolver metrics HTTP listening")
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn().Err(err).Msg("resolver metrics server failed")
		}
	}()

	// SIGHUP → hot-reload Bloom filters from disk. Sent by the
	// xgg-blocklists systemd service after a successful fetch.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Info().Msg("SIGHUP — reloading Bloom filters")
			r.reloadBloom()
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = udpSrv.ShutdownContext(ctx)
	_ = tcpSrv.ShutdownContext(ctx)
	if dohSrv != nil {
		_ = dohSrv.Shutdown(ctx)
	}
	_ = metricsSrv.Shutdown(ctx)
}

// trustedProxies holds CIDRs whose immediate peers may set X-Forwarded-For.
// Populated at startup from TRUSTED_PROXY_CIDRS (comma-separated). nil means
// no proxies are trusted and X-Forwarded-For is always ignored (Audit Finding #7).
var trustedProxies []*net.IPNet

func init() {
	raw := os.Getenv("TRUSTED_PROXY_CIDRS")
	if raw == "" {
		return
	}
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			log.Warn().Err(err).Str("cidr", c).Msg("TRUSTED_PROXY_CIDRS: skipping invalid entry")
			continue
		}
		trustedProxies = append(trustedProxies, n)
	}
}

// isTrusted reports whether host (bare IP string) falls within any trusted CIDR.
func isTrusted(host string) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIPFromRequest extracts the best client IP from an HTTP request.
// X-Forwarded-For is only honoured when the immediate peer (RemoteAddr) is
// in the TRUSTED_PROXY_CIDRS list; otherwise RemoteAddr is used directly.
// This prevents untrusted callers from forging source IPs in the query log.
func clientIPFromRequest(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if isTrusted(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// First value is the original client per RFC 7239 convention.
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	return host
}

// dnsHandler is the classic-DNS entrypoint. Reuses the same resolve()
// pipeline as the DoH path.
func (r *Resolver) dnsHandler(w dns.ResponseWriter, q *dns.Msg) {
	if len(q.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}
	domain := strings.TrimSuffix(strings.ToLower(q.Question[0].Name), ".")
	clientIP := remoteIP(w.RemoteAddr())
	// 500ms deadline prevents a hung verdict-api call from stalling the
	// classic-DNS goroutine indefinitely (Audit Finding #18).
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	resp := r.resolve(ctx, q, domain, clientIP)
	_ = w.WriteMsg(resp)
}

// remoteIP — pull the address portion from a UDP/TCP addr string.
func remoteIP(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

// handleDoH parses RFC 8484 DoH requests (GET ?dns=... or POST body) and answers.
func (r *Resolver) handleDoH(w http.ResponseWriter, req *http.Request) {
	var raw []byte
	var err error
	switch req.Method {
	case http.MethodGet:
		raw, err = base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
	case http.MethodPost:
		raw, err = io.ReadAll(req.Body)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(raw) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	if len(msg.Question) == 0 {
		http.Error(w, "no question", http.StatusBadRequest)
		return
	}
	domain := strings.TrimSuffix(strings.ToLower(msg.Question[0].Name), ".")

	clientIP := clientIPFromRequest(req)
	resp := r.resolve(req.Context(), msg, domain, clientIP)
	out, _ := resp.Pack()
	w.Header().Set("content-type", "application/dns-message")
	_, _ = w.Write(out)
}

// resolve runs the verdict pipeline for one query.
func (r *Resolver) resolve(ctx context.Context, q *dns.Msg, domain, clientIP string) *dns.Msg {
	t0 := time.Now()
	used := "unknown"
	cacheHit := false
	sinkholed := false
	var resp *dns.Msg
	defer func() {
		dur := time.Since(t0)
		resolvermetrics.DNSLatency.Observe(dur.Seconds())
		// Map verdict/response to rcode label.
		rcode := "NOERROR"
		if resp != nil {
			switch resp.Rcode {
			case dns.RcodeNameError:
				rcode = "NXDOMAIN"
			case dns.RcodeRefused:
				rcode = "REFUSED"
			case dns.RcodeServerFailure:
				rcode = "SERVFAIL"
			default:
				rcode = dns.RcodeToString[resp.Rcode]
				if rcode == "" {
					rcode = "NOERROR"
				}
			}
		}
		resolvermetrics.DNSQueriesTotal.WithLabelValues(rcode).Inc()
		log.Info().Str("domain", domain).Str("client", clientIP).Str("verdict", used).Bool("cache", cacheHit).Dur("dur", dur).Msg("resolved")
		// Best-effort emit to the admin stream. Never block DNS on this.
		go r.emitQueryLog(domain, q, clientIP, used, cacheHit, sinkholed, dur)
		// Phase B.4: returned-IP ledger. Only write when we actually returned
		// real A/AAAA records (not a sinkhole/NXDOMAIN). verdict-api reads
		// this via internal/iledger to answer "did the browser connect to an
		// IP we just told it to?" — the core of connection-identity scoring.
		// Best-effort: a Redis failure must never affect DNS correctness.
		if !sinkholed && resp != nil && len(resp.Answer) > 0 {
			ips, ttl := extractAnswers(resp)
			if len(ips) > 0 {
				go func() {
					ctx2, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
					defer cancel()
					if err := iledger.Write(ctx2, r.cache, clientIP, domain, ips, ttl); err != nil {
						log.Debug().Err(err).Str("domain", domain).Msg("iledger write failed (non-fatal)")
					}
				}()
			}
		}
	}()

	// Decision order (top wins):
	//
	//   0. never_block  (hardcoded essentials)  → upstream
	//   1. strict_block (≥2 feeds OR phish/mal) → NXDOMAIN
	//   2. allowlist    (Tranco top-1M)         → upstream
	//   3. weak_block   (single low-trust feed) → upstream (logged as warn)
	//   4. fall through to verdict-api Tier-1
	//
	// Strict-block beating Tranco is deliberate: Tranco ranks by traffic, not
	// trust — sketchy-but-popular sites land there too. The hardcoded
	// never_block list (banks, .gov, payment, CAs, dev infra) is the
	// authoritative "this can never be wrong" set.

	// 0) never_block — hand-curated, subdomain-suffix match.
	if r.isNeverBlock(domain) {
		used, cacheHit = "clean", true
		resp = r.upstreamAnswer(q)
		return resp
	}

	// 1) strict_block — 2+ feeds or phishing/malware-tagged. Bloom + Redis exact.
	if r.blockHas(domain) {
		if r.cache.SIsMember(ctx, "blocklist:strict", domain).Val() {
			used, cacheHit, sinkholed = "block", true, true
			resp = r.nxdomain(q)
			return resp
		}
	}

	// 2) allowlist — Bloom hint + Redis exact verify.
	if r.allowHas(domain) {
		if r.cache.SIsMember(ctx, "allowlist:exact", domain).Val() {
			used, cacheHit = "clean", true
			resp = r.upstreamAnswer(q)
			return resp
		}
	}

	// 3) weak_block — flagged but not blocked.
	if r.blockHas(domain) {
		if r.cache.SIsMember(ctx, "blocklist:weak", domain).Val() {
			used = "warn"
			resp = r.upstreamAnswer(q)
			return resp
		}
	}

	// 3) Cached verdict
	if v, err := r.cache.Get(ctx, "verdict:"+domain).Result(); err == nil {
		cacheHit = true
		switch v {
		case "clean":
			used = "clean"
			resp = r.upstreamAnswer(q)
			return resp
		case "block":
			used, sinkholed = "block", true
			resp = r.nxdomain(q)
			return resp
		case "warn":
			// WARN: still resolve normally so user can decide; flagged in dashboard.
			used = "warn"
			resp = r.upstreamAnswer(q)
			return resp
		case "analyzing":
			used, sinkholed = "analyzing", true
			resp = r.nxdomain(q) // brief while async scan completes
			return resp
		}
	}

	// 4) Call verdict-api Tier-1 (deadline 250ms).
	verdict := r.tier1Verdict(ctx, domain)
	_ = r.cache.Set(ctx, "verdict:"+domain, verdict.kind, verdict.ttl).Err()
	used = verdict.kind

	switch verdict.kind {
	case "block":
		sinkholed = true
		resp = r.nxdomain(q)
	case "warn":
		// WARN passes through to upstream — flagged but not blocked.
		// Operator reviews in /admin/queries.
		resp = r.upstreamAnswer(q)
	case "analyzing":
		sinkholed = true
		resp = r.nxdomain(q)
	default:
		resp = r.upstreamAnswer(q)
	}
	return resp
}

// emitQueryLog pushes one record onto the Redis stream `xgg:dns`. The
// portal-api drains this stream into the dns_queries table. Best-effort:
// failure here never affects DNS correctness.
func (r *Resolver) emitQueryLog(domain string, q *dns.Msg, clientIP, verdict string, cacheHit, sinkholed bool, dur time.Duration) {
	qtype := ""
	if len(q.Question) > 0 {
		qtype = dns.TypeToString[q.Question[0].Qtype]
	}
	values := map[string]any{
		"ts":          time.Now().UTC().Format(time.RFC3339Nano),
		"domain":      domain,
		"qtype":       qtype,
		"client_ip":   clientIP,
		"verdict":     verdict,
		"cache_hit":   cacheHit,
		"sinkhole":    sinkholed,
		"duration_ms": dur.Milliseconds(),
		"client_id":   "resolver",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _ = r.cache.XAdd(ctx, &redis.XAddArgs{
		Stream: "xgg:dns",
		MaxLen: 100_000,
		Approx: true,
		Values: values,
	}).Result()

	// Also broadcast to the pub/sub channel that drives the /live activity feed.
	live := map[string]any{
		"ts":         values["ts"],
		"scanned_at": values["ts"],
		"domain":     domain,
		"url":        "dns://" + domain,
		"client_ip":  clientIP,
		"client_id":  "resolver",
		"verdict":    strings.ToUpper(verdict),
		"signals":    []any{},
	}
	if b, err := json.Marshal(live); err == nil {
		_, _ = r.cache.Publish(ctx, "xgg:verdicts", string(b)).Result()
	}
}

type tier1Result struct {
	kind string
	ttl  time.Duration
}

// tier1Verdict calls verdict-api over HTTP. Phase-1 chooses HTTP over gRPC
// to skip the protoc dependency; gRPC swap-in lands once stubs are generated.
//
// The resolver only needs the *domain*-level verdict here; we pass a synthetic
// https://<domain>/ URL so verdict-api treats it as an L0 check. The full URL
// path is handled by the browser extension's /v1/check call.
func (r *Resolver) tier1Verdict(ctx context.Context, domain string) tier1Result {
	body, _ := json.Marshal(map[string]string{
		"url":       "https://" + domain + "/",
		"client_id": "resolver",
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.VerdictAPIAddr+"/v1/check", bytes.NewReader(body))
	req.Header.Set("content-type", "application/json")
	// Attach the inter-service shared secret (Architecture Audit Finding #3).
	// /v1/check is a public endpoint but we still send the token so that if it
	// is later locked down (e.g. by a network policy that rate-limits public
	// callers), resolver requests get priority routing. No token = dev mode;
	// the header is simply omitted when XGG_INTERNAL_TOKEN is unset.
	if tok := os.Getenv("XGG_INTERNAL_TOKEN"); tok != "" {
		req.Header.Set("X-Internal-Token", tok)
	}

	client := &http.Client{Timeout: 280 * time.Millisecond}
	httpResp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("verdict-api unreachable; failing open")
		// Classify timeout vs network error for metrics.
		result := "error"
		if strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "timeout") {
			result = "timeout"
		}
		resolvermetrics.VerdictAPICallsTotal.WithLabelValues(result).Inc()
		return tier1Result{kind: "unknown", ttl: 0}
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 400 {
		resolvermetrics.VerdictAPICallsTotal.WithLabelValues("error").Inc()
		return tier1Result{kind: "unknown", ttl: 0}
	}

	var v struct {
		Verdict    string  `json:"verdict"`
		Confidence float64 `json:"confidence"`
	}
	if err := json.NewDecoder(httpResp.Body).Decode(&v); err != nil {
		resolvermetrics.VerdictAPICallsTotal.WithLabelValues("error").Inc()
		return tier1Result{kind: "unknown", ttl: 0}
	}
	resolvermetrics.VerdictAPICallsTotal.WithLabelValues("success").Inc()

	switch strings.ToUpper(v.Verdict) {
	case "BLOCK":
		return tier1Result{kind: "block", ttl: 30 * 24 * time.Hour}
	case "WARN":
		return tier1Result{kind: "warn", ttl: 6 * time.Hour}
	case "CLEAN":
		return tier1Result{kind: "clean", ttl: 24 * time.Hour}
	case "ANALYZING":
		return tier1Result{kind: "analyzing", ttl: 30 * time.Second}
	default:
		return tier1Result{kind: "unknown", ttl: 0}
	}
}

func (r *Resolver) upstreamAnswer(q *dns.Msg) *dns.Msg {
	resp, _, err := r.upstream.Exchange(q, r.cfg.UpstreamAddr)
	if err != nil || resp == nil {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeServerFailure)
		return m
	}
	// DNS rebinding mitigation: strip A/AAAA records pointing at
	// private / reserved space. If every A/AAAA was filtered, rewrite to
	// NXDOMAIN so the client fails cleanly instead of trying a stripped IP.
	dropped, anyA, wasA := rebind.Filter(resp)
	if dropped > 0 {
		qn := ""
		if len(q.Question) > 0 {
			qn = q.Question[0].Name
		}
		log.Warn().Str("qname", qn).Int("dropped", dropped).Msg("rebind filter dropped private answer")
	}
	if wasA && !anyA {
		return r.nxdomain(q)
	}
	return resp
}

// extractAnswers walks msg.Answer and returns the A/AAAA addresses plus
// the minimum TTL seen across them. Used by the iledger writer in
// resolve()'s defer. Returns (nil, 0) if no A/AAAA records present.
func extractAnswers(msg *dns.Msg) ([]string, uint32) {
	if msg == nil {
		return nil, 0
	}
	var ips []string
	var minTTL uint32
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A.String())
		case *dns.AAAA:
			ips = append(ips, v.AAAA.String())
		default:
			continue
		}
		ttl := rr.Header().Ttl
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	return ips, minTTL
}

func (r *Resolver) sinkhole(q *dns.Msg, ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	for _, qq := range q.Question {
		if qq.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(qq.Name + " 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		}
	}
	return m
}

// nxdomain — returns NXDOMAIN ("domain does not exist") for blocked queries.
// Cleaner UX than a sinkhole IP: the browser shows "this site can't be
// reached" instead of ERR_CONNECTION_REFUSED. Without a TLS cert for the
// target hostname we can't render an HTTPS block page anyway.
func (r *Resolver) nxdomain(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(q, dns.RcodeNameError)
	// Add SOA in authority section so resolvers cache the negative answer briefly.
	if len(q.Question) > 0 {
		soa := &dns.SOA{
			Hdr:     dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:      "blackhole.xgenguardian.invalid.",
			Mbox:    "abuse.xgenguardian.invalid.",
			Serial:  1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
		}
		m.Ns = append(m.Ns, soa)
	}
	return m
}

// --- helpers ---

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func loadBloom(path string, n uint, fp float64) *bloom.BloomFilter {
	bf := bloom.NewWithEstimates(n, fp)
	f, err := os.Open(path)
	if err != nil {
		log.Warn().Str("path", path).Err(err).Msg("bloom source missing — starting empty")
		return bf
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	for {
		nb, err := f.Read(buf)
		if nb > 0 {
			for _, line := range strings.Split(string(buf[:nb]), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					bf.AddString(line)
				}
			}
		}
		if err != nil {
			break
		}
	}
	return bf
}
