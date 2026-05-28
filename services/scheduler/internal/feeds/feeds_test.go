package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM/path?q=1":                 "example.com",
		"http://user:pass@bad.example/page":            "bad.example",
		"https://bad.example:8443/foo":                 "bad.example",
		"badurl":                                       "badurl",
		"":                                             "",
		"https://sub.deep.example.org/some/path#frag": "sub.deep.example.org",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseCSVLine(t *testing.T) {
	// URLhaus shape: quoted strings, commas inside quoted tag fields.
	in := `1,2024-01-15 10:00:00,"http://bad.example/x","online","2024-01-15 10:05:00","malware_download","emotet,banking","https://urlhaus.abuse.ch/url/1/","reporter"`
	fields := parseCSVLine(in)
	if len(fields) != 9 {
		t.Errorf("expected 9 fields, got %d: %v", len(fields), fields)
	}
	if fields[2] != "http://bad.example/x" {
		t.Errorf("url field: got %q", fields[2])
	}
	if fields[6] != "emotet,banking" {
		t.Errorf("tags should keep internal comma intact, got %q", fields[6])
	}
}

func TestFetchURLhaus(t *testing.T) {
	// Realistic feed shape with header + one online + one offline row.
	body := `# URLhaus comment line
"id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
1,2024-01-15 10:00:00,"http://bad.example/m.exe","online","2024-01-15 10:05:00","malware_download","emotet,banking","https://urlhaus.abuse.ch/url/1/","reporter"
2,2024-01-14 10:00:00,"http://gone.example/x","offline","2024-01-14 10:05:00","malware_download","","","reporter"
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	// Cheap override: swap URLhausURL via direct call.
	entries, err := fetchURLhausFrom(context.Background(), &http.Client{Timeout: 5 * time.Second}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 online entry, got %d", len(entries))
	}
	if entries[0].Source != "urlhaus" || entries[0].Category != "malware" {
		t.Errorf("bad entry: %+v", entries[0])
	}
}

func TestFetchOpenPhish(t *testing.T) {
	body := strings.Join([]string{
		"# OpenPhish feed",
		"",
		"http://phish.example/login",
		"http://phish.example/pay",
	}, "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	entries, err := fetchOpenPhishFrom(context.Background(), &http.Client{Timeout: 5 * time.Second}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestFetchPhishTank(t *testing.T) {
	body := `[
		{"phish_id":"1","url":"http://verified.example/","submission_time":"2024-01-15T10:00:00+00:00","verified":"yes","online":"yes"},
		{"phish_id":"2","url":"http://offline.example/","submission_time":"2024-01-15T10:00:00+00:00","verified":"yes","online":"no"},
		{"phish_id":"3","url":"http://unverified.example/","submission_time":"2024-01-15T10:00:00+00:00","verified":"no","online":"yes"}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	entries, err := fetchPhishTankFrom(context.Background(), &http.Client{Timeout: 5 * time.Second}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected only 1 (verified+online) entry, got %d", len(entries))
	}
	if entries[0].ReferenceID != "1" {
		t.Errorf("entry ID: got %q", entries[0].ReferenceID)
	}
}
