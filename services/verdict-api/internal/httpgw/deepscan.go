// deepscan.go — /v1/deep-scan: recursive BFS page crawler.
//
// Walks the link graph rooted at the requested URL up to max_depth=2 /
// max_pages=15, running the full verdict pipeline on each page. Requires
// X-Internal-Token because each request fans out into multiple sandbox renders.
//
// Design notes:
//   - BFS visits shallow pages first (most representative of user experience).
//   - same_origin_only defaults to true; cross-origin capped at 5 destinations.
//   - Per-page 8s deadline inside a 60s parent budget.
//   - Reuses s.runPipelineWithTier for all caching, rate-limiting, policy.
//
// NOTE: The JSON bool zero-value is false, so same_origin_only omitted in the
// body is treated as "allow cross-origin". Callers should pass
// "same_origin_only": true explicitly for the safe default. A future revision
// can use *bool to distinguish omit from explicit-false.
package httpgw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"
)

// Hard limits — enforced regardless of request body values.
const (
	deepScanMaxDepth    = 2
	deepScanMaxPages    = 15
	deepScanBudget      = 60 * time.Second
	deepScanPageTimeout = 8 * time.Second
	deepScanMaxCross    = 5 // cross-origin page cap when same_origin_only=false
)

type deepScanRequest struct {
	URL            string `json:"url"`
	ClientID       string `json:"client_id,omitempty"`
	MaxDepth       int    `json:"max_depth,omitempty"`        // default 1, capped at 2
	MaxPages       int    `json:"max_pages,omitempty"`        // default 5, capped at 15
	SameOriginOnly bool   `json:"same_origin_only,omitempty"` // see package note above
	Mode           string `json:"mode,omitempty"`
}

type deepScanResponse struct {
	RootURL                string              `json:"root_url"`
	RootVerdict            checkResponse       `json:"root_verdict"`
	LinkedPages            []linkedPageVerdict `json:"linked_pages"`
	DownloadsSummary       []downloadSummary   `json:"downloads_summary"`
	HiddenElementsCount    int                 `json:"hidden_elements_count"`
	SuspiciousJSIndicators []string            `json:"suspicious_js_indicators,omitempty"`
	OverlayTrapsCount      int                 `json:"overlay_traps_count"`
	ElapsedMs              int64               `json:"elapsed_ms"`
}

type linkedPageVerdict struct {
	URL         string   `json:"url"`
	Verdict     string   `json:"verdict"`
	Confidence  float64  `json:"confidence"`
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

type downloadSummary struct {
	URL              string `json:"url"`
	Extension        string `json:"extension,omitempty"`
	PageClassVerdict string `json:"page_class_verdict"` // "BLOCK_ON_SENSITIVE" | "WARN_NON_DEV" | "ALLOW_DEV_PAGE"
}

// bfsItem is a work item in the BFS queue.
type bfsItem struct {
	pageURL string
	depth   int
}

func (s *Server) deepScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req deepScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, "bad request: url required", http.StatusBadRequest)
		return
	}

	// Apply defaults and hard caps.
	if req.MaxDepth <= 0 {
		req.MaxDepth = 1
	}
	if req.MaxDepth > deepScanMaxDepth {
		req.MaxDepth = deepScanMaxDepth
	}
	if req.MaxPages <= 0 {
		req.MaxPages = 5
	}
	if req.MaxPages > deepScanMaxPages {
		req.MaxPages = deepScanMaxPages
	}

	start := time.Now()
	budget, budgetCancel := context.WithTimeout(r.Context(), deepScanBudget)
	defer budgetCancel()

	rootHost := hostFromURL(req.URL)
	sameOriginOnly := req.SameOriginOnly

	visited := map[string]struct{}{req.URL: {}}
	queue := []bfsItem{{pageURL: req.URL, depth: 0}}

	resp := deepScanResponse{
		RootURL:     req.URL,
		LinkedPages: []linkedPageVerdict{},
	}

	jsIndicatorSeen := map[string]struct{}{}
	crossOriginCrawled := 0

	for len(queue) > 0 && len(visited) <= req.MaxPages && budget.Err() == nil {
		item := queue[0]
		queue = queue[1:]

		pageCtx, pageCancel := context.WithTimeout(budget, deepScanPageTimeout)
		cr := checkRequest{
			URL:      item.pageURL,
			ClientID: req.ClientID,
			Mode:     req.Mode,
		}
		verdict := s.runPipelineWithTier(pageCtx, cr, "deep")
		pageCancel()

		if item.pageURL == req.URL {
			resp.RootVerdict = verdict
		} else {
			resp.LinkedPages = append(resp.LinkedPages, linkedPageVerdict{
				URL:         item.pageURL,
				Verdict:     verdict.Verdict,
				Confidence:  verdict.Confidence,
				ReasonCodes: verdict.ReasonCodes,
			})
		}

		// Pull the cached render to extract Phase 6 DOM inventory metadata.
		// runPipelineWithTier stored it in the Redis render cache; retrieve it
		// here without re-hitting sandbox.
		renderCtx, renderCancel := context.WithTimeout(budget, 3*time.Second)
		cachedRender := getRenderCache(renderCtx, s.Rdb, item.pageURL, hostFromURL(item.pageURL))
		renderCancel()

		if cachedRender != nil {
			resp.HiddenElementsCount += len(cachedRender.HiddenElements)
			for _, o := range cachedRender.Overlays {
				if o.CoveragePct >= 25 && o.Transparent && o.InterceptsClicks {
					resp.OverlayTrapsCount++
				}
			}
			for _, j := range cachedRender.SuspiciousJS {
				if j.Indicator == "external" {
					continue
				}
				if _, seen := jsIndicatorSeen[j.Indicator]; !seen {
					jsIndicatorSeen[j.Indicator] = struct{}{}
					resp.SuspiciousJSIndicators = append(resp.SuspiciousJSIndicators, j.Indicator)
				}
			}
			for _, l := range cachedRender.Links {
				if l.IsRiskyDownload {
					resp.DownloadsSummary = append(resp.DownloadsSummary, downloadSummary{
						URL:              l.URL,
						Extension:        l.Extension,
						PageClassVerdict: classifyDownloadForSummary(l, verdict.PageClass),
					})
				}
			}

			// Enqueue linked pages when depth budget remains.
			if item.depth < req.MaxDepth {
				for _, l := range cachedRender.Links {
					if l.URL == "" {
						continue
					}
					if _, already := visited[l.URL]; already {
						continue
					}
					linkHost := hostFromURL(l.URL)
					isCrossOrigin := linkHost != rootHost
					if sameOriginOnly && isCrossOrigin {
						continue
					}
					if isCrossOrigin {
						if crossOriginCrawled >= deepScanMaxCross {
							continue
						}
						crossOriginCrawled++
					}
					if len(visited) >= req.MaxPages {
						break
					}
					visited[l.URL] = struct{}{}
					queue = append(queue, bfsItem{pageURL: l.URL, depth: item.depth + 1})
				}
			}
		}
	}

	resp.ElapsedMs = time.Since(start).Milliseconds()

	log.Info().
		Str("root", req.URL).
		Int("pages_visited", len(visited)).
		Int("linked_verdicts", len(resp.LinkedPages)).
		Int64("elapsed_ms", resp.ElapsedMs).
		Msg("deep-scan complete")

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// classifyDownloadForSummary maps a risky download link to a page-class-based
// risk label, matching the policy logic in policy.Apply Stage F.4.
func classifyDownloadForSummary(l linkFinding, pageClass string) string {
	switch pageClass {
	case "login", "payment", "oauth-consent", "mfa", "password-step", "crypto-withdrawal":
		return "BLOCK_ON_SENSITIVE"
	case "download", "developer-tool-install-lure":
		return "ALLOW_DEV_PAGE"
	default:
		return "WARN_NON_DEV"
	}
}

// hostFromURL extracts the hostname from a URL string. Returns empty string
// on parse error (treated as unknown origin → cross-origin).
func hostFromURL(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
