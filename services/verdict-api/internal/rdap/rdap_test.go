package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const bootstrapFixture = `{
  "version": "1.0",
  "publication": "2026-01-01T00:00:00Z",
  "services": [
    [["com","net"], ["__SERVER__"]],
    [["org"],       ["__SERVER__"]]
  ]
}`

const rdapFixture = `{
  "objectClassName": "domain",
  "ldhName": "example.com",
  "events": [
    {"eventAction": "registration",      "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration",         "eventDate": "2030-08-13T04:00:00Z"},
    {"eventAction": "last changed",       "eventDate": "2024-08-14T04:00:00Z"}
  ],
  "nameservers": [
    {"ldhName": "a.iana-servers.net"},
    {"ldhName": "b.iana-servers.net"}
  ],
  "status": ["client delete prohibited", "client transfer prohibited"],
  "entities": [
    {
      "roles": ["registrar"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn",      {}, "text", "Example Registrar, Inc."]
      ]]
    }
  ]
}`

func newFakeRDAPServer(t *testing.T, status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestLookup_HappyPath(t *testing.T) {
	srv := newFakeRDAPServer(t, 200, rdapFixture)
	defer srv.Close()

	c := New()
	if err := c.bootstrap.loadFromJSON([]byte(strings.ReplaceAll(bootstrapFixture, "__SERVER__", srv.URL+"/"))); err != nil {
		t.Fatal(err)
	}

	info, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if info.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar: got %q", info.Registrar)
	}
	if info.RegisteredAt.Year() != 1995 {
		t.Errorf("registered year: got %d", info.RegisteredAt.Year())
	}
	if info.ExpiresAt.Year() != 2030 {
		t.Errorf("expires year: got %d", info.ExpiresAt.Year())
	}
	if len(info.NameServers) != 2 {
		t.Errorf("nameservers: got %d", len(info.NameServers))
	}
	if len(info.Status) != 2 {
		t.Errorf("status: got %d entries", len(info.Status))
	}
	if info.Age() < 25*365*24*time.Hour {
		t.Errorf("age looks wrong: %v", info.Age())
	}
}

func TestLookup_Cache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(rdapFixture))
	}))
	defer srv.Close()

	c := New()
	_ = c.bootstrap.loadFromJSON([]byte(strings.ReplaceAll(bootstrapFixture, "__SERVER__", srv.URL+"/")))

	for i := 0; i < 5; i++ {
		if _, err := c.Lookup(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("cache should have served 4 of 5 — got %d HTTP calls", calls)
	}
}

func TestLookup_NotFound(t *testing.T) {
	srv := newFakeRDAPServer(t, 404, `{"errorCode":404}`)
	defer srv.Close()

	c := New()
	_ = c.bootstrap.loadFromJSON([]byte(strings.ReplaceAll(bootstrapFixture, "__SERVER__", srv.URL+"/")))

	_, err := c.Lookup(context.Background(), "neverexisted.com")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestLookup_NoRDAPForTLD(t *testing.T) {
	c := New()
	_ = c.bootstrap.loadFromJSON([]byte(`{"services":[]}`))
	_, err := c.Lookup(context.Background(), "example.unknowntld")
	if !errors.Is(err, ErrNoRDAPForTLD) {
		t.Errorf("expected ErrNoRDAPForTLD, got %v", err)
	}
}

func TestParse_HandlesMissingFields(t *testing.T) {
	minimal := `{"objectClassName":"domain","ldhName":"x.com"}`
	info, err := parse([]byte(minimal), "x.com")
	if err != nil {
		t.Fatal(err)
	}
	if !info.RegisteredAt.IsZero() || info.Registrar != "" {
		t.Errorf("expected zero values, got %+v", info)
	}
	if info.Age() != 0 {
		t.Errorf("Age() with zero RegisteredAt should be 0, got %v", info.Age())
	}
}

func TestParseTime_Variants(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		year int
	}{
		{"2024-01-15T10:30:00Z", true, 2024},
		{"2024-01-15T10:30:00.123456Z", true, 2024},
		{"2024-01-15 10:30:00", true, 2024},
		{"2024-01-15", true, 2024},
		{"not a date", false, 0},
	}
	for _, c := range cases {
		got, err := parseTime(c.in)
		if c.ok && err != nil {
			t.Errorf("parseTime(%q): expected ok, got %v", c.in, err)
		}
		if c.ok && got.Year() != c.year {
			t.Errorf("parseTime(%q): year %d, want %d", c.in, got.Year(), c.year)
		}
		if !c.ok && err == nil {
			t.Errorf("parseTime(%q): expected error", c.in)
		}
	}
}

func TestTLDOf(t *testing.T) {
	cases := map[string]string{
		"example.com":         "com",
		"sub.example.co.uk":   "uk",
		"single":              "single",
		"a.b.c.d.example.org": "org",
	}
	for in, want := range cases {
		if got := tldOf(in); got != want {
			t.Errorf("tldOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractVCardFN(t *testing.T) {
	var v []any
	if err := json.Unmarshal([]byte(`["vcard", [["fn", {}, "text", "Acme"]]]`), &v); err != nil {
		t.Fatal(err)
	}
	if got := extractVCardFN(v); got != "Acme" {
		t.Errorf("got %q", got)
	}
	// vcard with no fn property
	v2 := []any{"vcard", []any{[]any{"version", map[string]any{}, "text", "4.0"}}}
	if got := extractVCardFN(v2); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestBootstrapTable_LoadsAndLooksUp(t *testing.T) {
	b := &bootstrapTable{m: map[string][]string{}}
	body := []byte(strings.ReplaceAll(bootstrapFixture, "__SERVER__", "https://rdap.example/"))
	if err := b.loadFromJSON(body); err != nil {
		t.Fatal(err)
	}
	srvs := b.serversFor("COM")
	if len(srvs) != 1 || srvs[0] != "https://rdap.example/" {
		t.Errorf("serversFor com: got %v", srvs)
	}
	if got := b.serversFor("zz"); got != nil {
		t.Errorf("unknown TLD: expected nil, got %v", got)
	}
}

// Smoke that the error message contains the TLD — handy in logs.
func TestErrorIncludesTLD(t *testing.T) {
	c := New()
	_ = c.bootstrap.loadFromJSON([]byte(`{"services":[]}`))
	_, err := c.Lookup(context.Background(), "example.weirdtld")
	if err == nil || !strings.Contains(err.Error(), "weirdtld") {
		t.Errorf("error should mention TLD, got %v", err)
	}
	_ = fmt.Sprintf("%v", err) // keep fmt import live for future test additions
}
