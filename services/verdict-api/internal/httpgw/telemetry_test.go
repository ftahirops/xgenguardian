package httpgw

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/xgenguardian/services/verdict-api/internal/metrics"
)

func newTelemetryServer() *Server { return &Server{} }

func postTelemetry(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := newTelemetryServer()
	r := httptest.NewRequest("POST", "/v1/telemetry/override", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	s.telemetryOverride(w, r)
	return w
}

// readCounter snapshots one labeled cell of a Prometheus CounterVec.
// Lets tests assert "this counter went up by exactly N" without
// resetting global metric state between tests.
func readCounter(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m, err := vec.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return pb.GetCounter().GetValue()
}

// --- Opt-in gate ---

func TestTelemetry_DisabledByDefault_ReturnsNoContent_AndDoesNotIncrement(t *testing.T) {
	os.Unsetenv("XGG_TELEMETRY_ENABLED")
	before := readCounter(t, metrics.RuleOverrideTotal, "HIDDEN_MALICIOUS_LINK")
	w := postTelemetry(t, telemetryRequest{
		URL:         "https://untrusted.example/path?q=secret",
		Verdict:     "WARN",
		ReasonCodes: []string{"HIDDEN_MALICIOUS_LINK"},
		Action:      "override_warn",
	})
	if w.Code != http.StatusNoContent {
		t.Errorf("disabled state must 204; got %d", w.Code)
	}
	after := readCounter(t, metrics.RuleOverrideTotal, "HIDDEN_MALICIOUS_LINK")
	if after != before {
		t.Errorf("override counter must NOT increment when telemetry disabled (before=%v after=%v)", before, after)
	}
}

// --- Happy path ---

func TestTelemetry_OverrideWarn_IncrementsOverrideCounter(t *testing.T) {
	t.Setenv("XGG_TELEMETRY_ENABLED", "1")
	before := readCounter(t, metrics.RuleOverrideTotal, "HIDDEN_MALICIOUS_LINK")
	w := postTelemetry(t, telemetryRequest{
		URL:         "https://untrusted.example/path?q=secret",
		Verdict:     "WARN",
		ReasonCodes: []string{"HIDDEN_MALICIOUS_LINK"},
		Action:      "override_warn",
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	after := readCounter(t, metrics.RuleOverrideTotal, "HIDDEN_MALICIOUS_LINK")
	if after-before != 1 {
		t.Errorf("override counter delta=%v; want 1", after-before)
	}
}

func TestTelemetry_ReportFP_IncrementsFPCounter(t *testing.T) {
	t.Setenv("XGG_TELEMETRY_ENABLED", "1")
	before := readCounter(t, metrics.RuleFPReportTotal, "OBFUSCATED_JS_DETECTED")
	postTelemetry(t, telemetryRequest{
		URL:         "https://benign.example/",
		Verdict:     "WARN",
		ReasonCodes: []string{"OBFUSCATED_JS_DETECTED"},
		Action:      "report_fp",
		Source:      "portal",
	})
	after := readCounter(t, metrics.RuleFPReportTotal, "OBFUSCATED_JS_DETECTED")
	if after-before != 1 {
		t.Errorf("fp_report counter delta=%v; want 1", after-before)
	}
}

// --- Privacy: URL is hashed, query string stripped ---

func TestTelemetry_ScrubURL_StripsQueryAndHashes(t *testing.T) {
	host, h := scrubURL("https://Example.com/path?token=secret&u=1#frag")
	if host != "example.com" {
		t.Errorf("host = %q; want example.com (lowercased)", host)
	}
	want := sha256.Sum256([]byte("https://Example.com/path"))
	if h != hex.EncodeToString(want[:]) {
		t.Errorf("url_hash does not match sha256 of query-stripped URL\n got %s\nwant %s", h, hex.EncodeToString(want[:]))
	}
	if strings.Contains(h, "secret") || strings.Contains(h, "token") {
		t.Errorf("hash contains query material")
	}
}

func TestTelemetry_ScrubURL_MalformedReturnsEmpty(t *testing.T) {
	// url.Parse is permissive — most "malformed" strings parse as relative
	// URLs and yield empty host. The contract is: empty host + empty hash
	// only when the input is unparseable. Two cases to cover:
	host, h := scrubURL("")
	if host != "" || h != "" {
		t.Errorf("empty input must return empty pair; got host=%q hash=%q", host, h)
	}
}

// --- Privacy: unknown reason codes are filtered, can't blow up counter cardinality ---

func TestTelemetry_UnknownCodes_AreFilteredFromCounter(t *testing.T) {
	t.Setenv("XGG_TELEMETRY_ENABLED", "1")
	before := readCounter(t, metrics.RuleOverrideTotal, "MADE_UP_CODE_DOES_NOT_EXIST")
	postTelemetry(t, telemetryRequest{
		URL:         "https://example.com/",
		Verdict:     "WARN",
		ReasonCodes: []string{"MADE_UP_CODE_DOES_NOT_EXIST", "HIDDEN_MALICIOUS_LINK"},
		Action:      "override_warn",
	})
	after := readCounter(t, metrics.RuleOverrideTotal, "MADE_UP_CODE_DOES_NOT_EXIST")
	if after != before {
		t.Errorf("unknown code must NOT add to counter (before=%v after=%v)", before, after)
	}
}

// --- ClientID is hashed before any further handling ---

func TestTelemetry_HashOrEmpty(t *testing.T) {
	if h := hashOrEmpty(""); h != "" {
		t.Errorf("empty client_id must hash to empty; got %q", h)
	}
	h := hashOrEmpty("abc-123-device")
	want := sha256.Sum256([]byte("abc-123-device"))
	if h != hex.EncodeToString(want[:]) {
		t.Errorf("client_id hash mismatch")
	}
}

// --- Validation ---

func TestTelemetry_BadAction_400(t *testing.T) {
	t.Setenv("XGG_TELEMETRY_ENABLED", "1")
	w := postTelemetry(t, telemetryRequest{
		URL:     "https://example.com/",
		Verdict: "WARN",
		Action:  "delete_everything",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad action must 400; got %d", w.Code)
	}
}

func TestTelemetry_BadVerdict_400(t *testing.T) {
	t.Setenv("XGG_TELEMETRY_ENABLED", "1")
	w := postTelemetry(t, telemetryRequest{
		URL:     "https://example.com/",
		Verdict: "MAYBE",
		Action:  "override_warn",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad verdict must 400; got %d", w.Code)
	}
}

func TestTelemetry_ReportFN_AllowsEmptyVerdict(t *testing.T) {
	t.Setenv("XGG_TELEMETRY_ENABLED", "1")
	w := postTelemetry(t, telemetryRequest{
		URL:    "https://unflagged-bad.example/",
		Action: "report_fn",
	})
	if w.Code != http.StatusNoContent {
		t.Errorf("report_fn with empty verdict must 204; got %d body=%s", w.Code, w.Body.String())
	}
}

func TestTelemetry_GET_405(t *testing.T) {
	s := newTelemetryServer()
	r := httptest.NewRequest("GET", "/v1/telemetry/override", nil)
	w := httptest.NewRecorder()
	s.telemetryOverride(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET must 405; got %d", w.Code)
	}
}
