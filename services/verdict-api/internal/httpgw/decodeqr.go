// decodeqr.go — POST /v1/decode-qr (v0.3.6 Surface Shield).
//
// Thin proxy in front of sandbox-render's /decode-qr endpoint. The
// extension calls this when its client-side jsQR can't decode a QR
// image and the image host looks suspicious enough that we want a
// best-effort server-side decode.
//
// Why proxy instead of having the extension hit sandbox-render directly:
// sandbox-render is internal-only (binds 127.0.0.1) and requires
// X-Internal-Token. The extension talks only to verdict-api's public
// surface; this endpoint forwards the call with the internal token.
//
// Failure mode: fail-open. Any error (sandbox down, network, malformed
// body, oversized image, unparseable image) returns parsed=false +
// empty decoded[]. The Surface Shield treats absent decode as "no
// signal" rather than "clean" or "block" — which is honest: we
// couldn't read the QR, so we have no opinion.
package httpgw

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// isSSRFBlockedIP returns true when `ip` is in a range we refuse to
// fetch from. Mirrors the sandbox-side check so attackers can't slip
// an internal target past us by going via the verdict-api proxy.
//
// Categories blocked:
//
//	loopback         127.0.0.0/8  ::1
//	private (RFC1918)10/8  172.16/12  192.168/16  fc00::/7
//	link-local       169.254/16  fe80::/10
//	CGNAT            100.64/10
//	unspecified      0.0.0.0  ::
//	multicast        224.0.0.0/4  ff00::/8
//	IPv4-mapped IPv6 ::ffff:x.x.x.x  (recursively re-check)
func isSSRFBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// CGNAT 100.64.0.0/10 — net.IP.IsPrivate covers RFC1918 but not
	// CGNAT in some Go versions; be explicit.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	// IPv4-mapped IPv6 (::ffff:x.x.x.x): re-check the embedded v4.
	if ip.To4() != nil && ip.To16() != nil && !ip.Equal(ip.To4()) {
		return isSSRFBlockedIP(ip.To4())
	}
	return false
}

// validateNoSSRFHost parses `rawURL`, resolves its host, and returns
// nil iff the host's address(es) are all publicly routable. Generic
// error messages — never echo resolver internals to the caller.
func validateNoSSRFHost(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errBadURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errBadURL
	}
	host := u.Hostname()
	if host == "" {
		return errBadURL
	}
	// Refuse bare IP literals that are themselves internal. Resolver
	// would still return them, but failing early is cheaper.
	if ip := net.ParseIP(host); ip != nil && isSSRFBlockedIP(ip) {
		return errFetchRefused
	}
	rctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	ips, err := (&net.Resolver{}).LookupIPAddr(rctx, host)
	if err != nil || len(ips) == 0 {
		return errFetchRefused
	}
	for _, ip := range ips {
		if isSSRFBlockedIP(ip.IP) {
			return errFetchRefused
		}
	}
	return nil
}

// errBadURL / errFetchRefused — opaque sentinel errors so the caller
// can return a generic response body without leaking which validation
// step failed.
var (
	errBadURL       = &decodeQRError{msg: "invalid image_url"}
	errFetchRefused = &decodeQRError{msg: "fetch refused"}
)

type decodeQRError struct{ msg string }

func (e *decodeQRError) Error() string { return e.msg }

type decodeQRRequest struct {
	ImageURL string `json:"image_url"`
}

type decodeQRResponse struct {
	Decoded   []string `json:"decoded"`
	DecodeMs  int      `json:"decode_ms"`
	Parsed    bool     `json:"parsed"`
	Reason    string   `json:"reason,omitempty"`
}

func (s *Server) decodeQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req decodeQRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.ImageURL = strings.TrimSpace(req.ImageURL)
	if !strings.HasPrefix(req.ImageURL, "http://") && !strings.HasPrefix(req.ImageURL, "https://") {
		http.Error(w, "image_url must be http(s)://", http.StatusBadRequest)
		return
	}

	// Forward to sandbox-render.
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	// SSRF defense: resolve the host and reject any address in
	// loopback / private / link-local / CGNAT / multicast space.
	// Without this, the public /v1/decode-qr endpoint would let an
	// attacker probe internal services (verdict-api itself on :18080,
	// Postgres on :15432, Redis on :16379, cloud metadata at
	// 169.254.169.254, etc.). Sandbox-render also enforces this same
	// check — the defense is layered, not redundant: each layer must
	// be safe by itself.
	if err := validateNoSSRFHost(ctx, req.ImageURL); err != nil {
		writeJSON(w, decodeQRResponse{Parsed: false, Reason: "fetch refused"})
		return
	}

	body, err := json.Marshal(req)
	if err != nil {
		writeJSON(w, decodeQRResponse{Parsed: false, Reason: "internal marshal"})
		return
	}
	httpReq, err := http.NewRequestWithContext(
		ctx, "POST", sandboxRenderURL()+"/decode-qr",
		strings.NewReader(string(body)),
	)
	if err != nil {
		writeJSON(w, decodeQRResponse{Parsed: false, Reason: "internal request"})
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Internal-Token", goGetenv("XGG_INTERNAL_TOKEN"))

	client := s.SharedHTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Warn().Err(err).Msg("decode-qr: sandbox-render unreachable")
		writeJSON(w, decodeQRResponse{Parsed: false, Reason: "sandbox unreachable"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		writeJSON(w, decodeQRResponse{
			Parsed: false,
			Reason: "sandbox " + resp.Status,
		})
		return
	}

	// Re-parse the sandbox response and re-emit a STRIPPED shape so
	// internal-side fields can't leak through the public endpoint
	// (the `reason` field on the sandbox response is for operator
	// logs only; it could carry timing / TLS / DNS details that
	// help an attacker fingerprint internal state).
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		writeJSON(w, decodeQRResponse{Parsed: false, Reason: "read body"})
		return
	}
	var inner decodeQRResponse
	if err := json.Unmarshal(raw, &inner); err != nil {
		writeJSON(w, decodeQRResponse{Parsed: false, Reason: "decode failed"})
		return
	}
	// Re-emit ONLY the fields the extension consumes — decoded[]
	// and parsed. decode_ms is operationally useful and contains
	// no internal-state info. reason is GENERIC: either empty (parsed
	// true) or a fixed "fetch refused" / "decode failed" string we
	// own, never the upstream message.
	stripped := decodeQRResponse{
		Decoded:  inner.Decoded,
		DecodeMs: inner.DecodeMs,
		Parsed:   inner.Parsed,
	}
	if !inner.Parsed {
		stripped.Reason = "fetch failed"
	}
	writeJSON(w, stripped)
}
