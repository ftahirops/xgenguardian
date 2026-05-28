package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newWebRiskMock(t *testing.T, threatTypes []string, status int) *httptest.Server {
	body := `{}`
	if len(threatTypes) > 0 {
		body = `{"threat":{"threatTypes":["` + strings.Join(threatTypes, `","`) + `"],"expireTime":"2030-01-01T00:00:00Z"}}`
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			t.Errorf("missing key param")
		}
		if r.URL.Query().Get("uri") == "" {
			t.Errorf("missing uri param")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// withEndpoint lets a test swap the endpoint without polluting the prod
// constant. We achieve this by giving the client an http.Client that
// rewrites the destination to the test server.
type rewriteRT struct {
	to string
}

func (r rewriteRT) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the host but preserve path + query (which carries ?key=&uri=).
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(r.to, "http://")
	return http.DefaultTransport.RoundTrip(req)
}

func TestWebRisk_DisabledWithoutKey(t *testing.T) {
	c := NewWebRisk("")
	clean, threats, err := c.Lookup(context.Background(), "http://example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if clean != nil {
		t.Errorf("disabled client should return clean=nil, got %v", *clean)
	}
	if len(threats) != 0 {
		t.Errorf("disabled client should return no threats")
	}
}

func TestWebRisk_Clean(t *testing.T) {
	srv := newWebRiskMock(t, nil, 200)
	defer srv.Close()
	c := NewWebRisk("test-key")
	c.http.Transport = rewriteRT{to: srv.URL}
	clean, threats, err := c.Lookup(context.Background(), "http://good.example/")
	if err != nil {
		t.Fatal(err)
	}
	if clean == nil || !*clean {
		t.Errorf("expected clean=true")
	}
	if len(threats) != 0 {
		t.Errorf("expected no threats, got %v", threats)
	}
}

func TestWebRisk_Flagged(t *testing.T) {
	srv := newWebRiskMock(t, []string{"MALWARE", "SOCIAL_ENGINEERING"}, 200)
	defer srv.Close()
	c := NewWebRisk("test-key")
	c.http.Transport = rewriteRT{to: srv.URL}
	clean, threats, err := c.Lookup(context.Background(), "http://bad.example/")
	if err != nil {
		t.Fatal(err)
	}
	if clean == nil || *clean {
		t.Errorf("expected clean=false")
	}
	if len(threats) != 2 {
		t.Errorf("expected 2 threat types, got %v", threats)
	}
}

func TestWebRisk_Cache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := NewWebRisk("test-key")
	c.http.Transport = rewriteRT{to: srv.URL}
	for i := 0; i < 5; i++ {
		_, _, _ = c.Lookup(context.Background(), "http://example.com/")
	}
	if calls != 1 {
		t.Errorf("expected 1 HTTP call (4 cache hits), got %d", calls)
	}
}

func TestWebRisk_EmptyURL(t *testing.T) {
	c := NewWebRisk("k")
	_, _, err := c.Lookup(context.Background(), "")
	if err == nil {
		t.Errorf("expected error for empty URL")
	}
}
