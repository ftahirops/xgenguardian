package iledger

import (
	"context"
	"testing"
)

func TestKey_MatchesResolver(t *testing.T) {
	// Must produce the exact same key the resolver writes. If this drifts,
	// the ledger silently stops being useful — verdict-api would look up
	// keys nobody is writing.
	cases := []struct {
		client, domain, want string
	}{
		{"1.2.3.4", "Example.COM", "iledger:1.2.3.4:example.com"},
		{"  1.2.3.4  ", "example.com.", "iledger:1.2.3.4:example.com"},
		{"", "example.com", "iledger:unknown:example.com"},
	}
	for _, c := range cases {
		if got := Key(c.client, c.domain); got != c.want {
			t.Errorf("Key(%q,%q) = %q, want %q", c.client, c.domain, got, c.want)
		}
	}
}

func TestRecent_NilRedisReturnsNilNil(t *testing.T) {
	got, err := Recent(context.Background(), nil, "1.2.3.4", "example.com")
	if err != nil {
		t.Errorf("nil redis should not error, got %v", err)
	}
	if got != nil {
		t.Errorf("nil redis should return nil entries, got %v", got)
	}
}

func TestHasIP_EmptyIPIsFalse(t *testing.T) {
	got, err := HasIP(context.Background(), nil, "1.2.3.4", "example.com", "")
	if err != nil || got {
		t.Errorf("empty ip should return (false,nil); got (%v,%v)", got, err)
	}
}
