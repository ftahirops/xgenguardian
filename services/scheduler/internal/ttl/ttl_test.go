package ttl

import (
	"testing"
	"time"
)

func TestFor_NormalMode(t *testing.T) {
	d := 24 * time.Hour
	cases := []struct {
		g    Grade
		want time.Duration
	}{
		{APlus, 38 * d},
		{A, 30 * d},
		{B, 24 * time.Hour},
		{C, 6 * time.Hour},
		{D, 30 * time.Minute},
		{F, 12 * time.Hour},
		{FPlus, 14 * d},
	}
	for _, c := range cases {
		got := For(c.g, Generic, false)
		if got != c.want {
			t.Errorf("grade=%s normal: got %v, want %v", c.g, got, c.want)
		}
	}
}

func TestFor_Paranoid_TighterDecay(t *testing.T) {
	d := 24 * time.Hour
	if got := For(APlus, Generic, true); got != 30*d {
		t.Errorf("paranoid A+: got %v, want 30d", got)
	}
	if got := For(A, Generic, true); got != 14*d {
		t.Errorf("paranoid A: got %v, want 14d", got)
	}
}

func TestFor_SensitiveClassOverride(t *testing.T) {
	d := 24 * time.Hour

	// A+ login: capped at 7d even though grade allows 38d.
	if got := For(APlus, Login, false); got != 7*d {
		t.Errorf("A+ login: got %v, want 7d cap", got)
	}
	// A+ download: capped at 6h.
	if got := For(APlus, Download, false); got != 6*time.Hour {
		t.Errorf("A+ download: got %v, want 6h", got)
	}
	// B + login: B's TTL is 24h, login cap is 7d; min applies → 24h.
	if got := For(B, Login, false); got != 24*time.Hour {
		t.Errorf("B login: got %v, want 24h (B's TTL wins)", got)
	}
}

func TestIsSensitive(t *testing.T) {
	sensitive := []PageClass{Login, Payment, OAuth, Admin, Download}
	for _, pc := range sensitive {
		if !IsSensitive(pc) {
			t.Errorf("%s should be sensitive", pc)
		}
	}
	if IsSensitive(Generic) {
		t.Errorf("generic should not be sensitive")
	}
}
