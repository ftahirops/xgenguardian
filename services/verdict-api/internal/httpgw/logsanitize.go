// logsanitize.go — strip query strings and fragments from URLs before they
// reach structured logs or the on-disk session log.
//
// Submitted URLs frequently carry authentication tokens, OAuth state, password
// reset tokens, and personally-identifiable identifiers in their query strings.
// Logging raw URLs to stderr (collected by log aggregators) or to a JSONL file
// on disk creates a long-term sensitive-data footprint that is disproportionate
// to the operational value of the log line. The verdict only needs scheme +
// host + path to be operationally meaningful; the parameters are noise.
package httpgw

import (
	"net/url"
	"strings"
)

// sanitizeURLForLog returns a log-safe form of the URL with the query string
// and fragment stripped. Falls back to a coarse split on '?' / '#' when
// url.Parse fails so we never panic on malformed input.
func sanitizeURLForLog(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil {
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}
