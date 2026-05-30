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
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

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

	// Sandbox response is the same shape — just forward it.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		writeJSON(w, decodeQRResponse{Parsed: false, Reason: "read body"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
