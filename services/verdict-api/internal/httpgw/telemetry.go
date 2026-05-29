// telemetry.go — Phase G data-flywheel endpoint.
//
// POST /v1/telemetry/override accepts override / FP-report / FN-report
// events from the extension or operator portal. Writes a privacy-scrubbed
// row to policy_events and increments per-rule counters that drive the
// weekly rule-health report.
//
// Privacy invariants (enforced here, not negotiable):
//   - Raw URL is NEVER stored. We persist host + sha256(url-minus-query).
//   - Raw client_id is NEVER stored. We persist sha256(client_id).
//   - Endpoint is opt-in via XGG_TELEMETRY_ENABLED=1. Disabled-state is
//     a silent 204 — no persistence, no log line. The contract for the
//     extension is "you can always POST; the server decides whether to
//     keep it." That keeps the privacy gate server-side.
//
// Threat model: the endpoint is public (extension calls from the user's
// network). It is rate-limited at the gateway like /v1/check. The body
// is strictly validated and codes are filtered against reasons.IsKnown
// so an attacker can't poison the per-code counters with arbitrary labels.
package httpgw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/xgenguardian/services/verdict-api/internal/metrics"
	"github.com/xgenguardian/services/verdict-api/internal/reasons"
)

// telemetryRequest is the wire shape POSTed by the extension and portal.
//
// Action determines counter targets:
//
//	override_warn  + override_block  → xgg_rule_override_total{code}
//	report_fp                        → xgg_rule_fp_report_total{code}
//	report_fn                        → (DB only; no counter — FN reports
//	                                    are reviewed manually before any
//	                                    rule change)
type telemetryRequest struct {
	URL         string   `json:"url"`
	Verdict     string   `json:"verdict"`
	ReasonCodes []string `json:"reason_codes"`
	Action      string   `json:"action"`
	Source      string   `json:"source,omitempty"`    // defaults "extension"
	ClientID    string   `json:"client_id,omitempty"` // hashed before storage
	Note        string   `json:"note,omitempty"`      // portal flow only
}

// validActions / validVerdicts gate the request before we persist or
// touch metrics. Anything outside the set is a 400.
var validActions = map[string]bool{
	"override_warn":  true,
	"override_block": true,
	"report_fp":      true,
	"report_fn":      true,
}

var validVerdicts = map[string]bool{
	"ALLOW":   true,
	"WARN":    true,
	"BLOCK":   true,
	"ISOLATE": true,
}

// telemetryOverride is the registered handler. Kept exported via the
// Server method form so the route table mirrors the other endpoints.
func (s *Server) telemetryOverride(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Opt-in gate. When disabled we still return 204 so the extension's
	// fire-and-forget behaviour is unchanged across operator configs.
	if !telemetryEnabled() {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var req telemetryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !validActions[req.Action] {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}
	// Verdict is optional for report_fn (we may not have rendered a
	// verdict yet for an FN), required otherwise.
	if req.Action != "report_fn" && !validVerdicts[req.Verdict] {
		http.Error(w, "invalid verdict", http.StatusBadRequest)
		return
	}
	source := req.Source
	if source == "" {
		source = "extension"
	}
	if source != "extension" && source != "portal" {
		http.Error(w, "invalid source", http.StatusBadRequest)
		return
	}

	host, urlHash := scrubURL(req.URL)
	codes := filterKnownReasonCodes(req.ReasonCodes)
	clientHash := hashOrEmpty(req.ClientID)

	// Update per-code metrics first — counter updates are cheap and
	// independent of DB latency. We do this only for known codes so a
	// malicious extension can't synthesize counter labels.
	switch req.Action {
	case "override_warn", "override_block":
		for _, c := range codes {
			metrics.RuleOverrideTotal.WithLabelValues(c).Inc()
		}
	case "report_fp":
		for _, c := range codes {
			metrics.RuleFPReportTotal.WithLabelValues(c).Inc()
		}
	}

	if s.Pg != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := insertPolicyEvent(ctx, s.Pg, policyEventRow{
			Action:       req.Action,
			Source:       source,
			Host:         host,
			URLHash:      urlHash,
			Verdict:      req.Verdict,
			ReasonCodes:  codes,
			ClientIDHash: clientHash,
			Note:         req.Note,
		}); err != nil {
			// Non-fatal: telemetry is best-effort. Log and 204 — losing
			// a single event must not break the user-visible flow.
			log.Warn().Err(err).Str("action", req.Action).Msg("policy_event insert failed")
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// policyEventRow mirrors the table; passed to the inserter as a struct
// so column changes are one-source.
type policyEventRow struct {
	Action       string
	Source       string
	Host         string
	URLHash      string
	Verdict      string
	ReasonCodes  []string
	ClientIDHash string
	Note         string
}

func insertPolicyEvent(ctx context.Context, pg *pgxpool.Pool, row policyEventRow) error {
	codesJSON, err := json.Marshal(row.ReasonCodes)
	if err != nil {
		// Cannot happen for []string but check is cheap.
		return err
	}
	_, err = pg.Exec(ctx, `
		INSERT INTO policy_events
		    (action, source, host, url_hash, verdict, reason_codes, client_id_hash, note)
		VALUES
		    ($1,     $2,     NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), $6::jsonb, NULLIF($7,''), NULLIF($8,''))
	`,
		row.Action, row.Source, row.Host, row.URLHash, row.Verdict,
		string(codesJSON), row.ClientIDHash, row.Note,
	)
	return err
}

// scrubURL is the privacy gate. Returns (host, sha256_of_url_minus_query).
// On a malformed URL we still return ("", "") rather than refusing —
// the operator can review unparseable submissions via raw row count.
func scrubURL(raw string) (host, urlHash string) {
	if raw == "" {
		return "", ""
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "", ""
	}
	host = strings.ToLower(u.Hostname())
	// Drop query + fragment before hashing so two clicks on the same
	// page from different campaigns collapse to one bucket.
	u.RawQuery = ""
	u.Fragment = ""
	sum := sha256.Sum256([]byte(u.String()))
	return host, hex.EncodeToString(sum[:])
}

// filterKnownReasonCodes drops codes that are not registered in the
// reasons package. Prevents the counter cardinality blow-up an attacker
// would otherwise get by POSTing made-up labels.
func filterKnownReasonCodes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		if reasons.IsKnown(reasons.Code(c)) {
			out = append(out, c)
		}
	}
	return out
}

// hashOrEmpty returns sha256 hex of s, or "" when s is empty.
func hashOrEmpty(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// telemetryEnabled reports whether the operator has opted into the
// data-flywheel collection. Default off; the unit file should set
// XGG_TELEMETRY_ENABLED=1 on self-host installs that want the weekly
// rule-health report to have data to work with.
func telemetryEnabled() bool {
	return goGetenv("XGG_TELEMETRY_ENABLED") == "1"
}
