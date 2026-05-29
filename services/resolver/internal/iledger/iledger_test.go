package iledger

import "testing"

func TestKey_Normalization(t *testing.T) {
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

func TestWrite_NilRedisIsNoop(t *testing.T) {
	if err := Write(nil, nil, "1.2.3.4", "example.com", []string{"203.0.113.1"}, 60); err != nil {
		t.Errorf("nil redis should noop, got err=%v", err)
	}
}

func TestWrite_EmptyIPsIsNoop(t *testing.T) {
	if err := Write(nil, nil, "1.2.3.4", "example.com", nil, 60); err != nil {
		t.Errorf("nil ips should noop, got err=%v", err)
	}
}
