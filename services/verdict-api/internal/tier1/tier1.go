// Package tier1 — fast synchronous checks that must complete in ≤250ms.
//
// All checks run in parallel via errgroup; their per-signal scores are summed.
// The result is either a confident verdict or "uncertain → escalate to Tier 2".
package tier1

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

type Signal struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

type Result struct {
	Score   float64  // 0..1; ≥0.85 → block, ≤0.2 → allow, else escalate
	Signals []Signal
}

// Run executes all Tier-1 checks against `domain` with a 250ms deadline.
func Run(ctx context.Context, domain string, brandKeywords []string) Result {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()

	r := Result{}
	var signals []Signal

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if s := homoglyphScore(domain, brandKeywords); s.Weight > 0 {
			signals = append(signals, s)
		}
		return nil
	})

	g.Go(func() error {
		if s := certScore(gctx, domain); s.Weight > 0 {
			signals = append(signals, s)
		}
		return nil
	})

	g.Go(func() error {
		if s := lexicalScore(domain); s.Weight > 0 {
			signals = append(signals, s)
		}
		return nil
	})

	g.Go(func() error {
		// DGA classifier — registrable-name level. Strip the leftmost
		// label as the SLD candidate (homoglyph's `original` does the same
		// upstream but we keep this self-contained).
		sld := domain
		if i := strings.IndexByte(domain, '.'); i >= 0 {
			sld = domain[:i]
		}
		if s, ok := DGASignal(sld); ok {
			signals = append(signals, s)
		}
		return nil
	})

	_ = g.Wait()

	var sum float64
	for _, s := range signals {
		sum += s.Weight
	}
	r.Signals = signals
	r.Score = clamp(sum / 1.5) // rough normalization for 3-signal max
	return r
}

// homoglyphScore — homoglyph / typosquat / combosquat detector.
//
// Keeps both the original SLD and a small set of "alternate-reading"
// variants. If the ORIGINAL matches a brand keyword exactly, we treat it as
// the legitimate brand and skip. If any VARIANT matches the keyword exactly,
// that's a pure homoglyph substitution — the strongest single signal.
// Otherwise we look for Levenshtein <= 2 (typos) or substring containment
// (combosquats like "paypal-secure-login").
func homoglyphScore(domain string, keywords []string) Signal {
	original := strings.SplitN(domain, ".", 2)[0]
	original = strings.ToLower(original)
	vars := normalizationVariants(original)

	for _, kw := range keywords {
		if original == kw {
			continue // legitimate brand domain itself — not impersonation
		}
		// Pure homoglyph: a variant equals the brand keyword exactly.
		for _, v := range vars {
			if v == kw {
				return Signal{
					Name:   "homoglyph_match",
					Weight: 0.85,
					Detail: "'" + original + "' → '" + v + "' matches brand keyword '" + kw + "'",
				}
			}
		}
		// Near-match: typo within 1–2 edits.
		for _, v := range vars {
			if d := levenshtein(v, kw); d > 0 && d <= 2 {
				return Signal{
					Name:   "homoglyph_match",
					Weight: 0.7,
					Detail: "edit distance " + itoa(d) + " from brand keyword '" + kw + "' (via " + v + ")",
				}
			}
		}
		// Combosquat: brand appears as a substring with extra tokens.
		for _, v := range vars {
			if strings.Contains(v, kw) && v != kw {
				return Signal{
					Name:   "combosquat",
					Weight: 0.5,
					Detail: "contains brand keyword '" + kw + "' with extra tokens",
				}
			}
		}
	}
	return Signal{}
}

// normalizationVariants — returns the original SLD plus a few alternate
// readings. We include:
//
//   - The original (so exact matches still register as the real brand).
//   - normalizeConfusables(original)         (1→l, 0→o, Cyrillic а→a, etc.)
//   - The same with '1' interpreted as 'i'   (catches w1thin → within)
//   - The same with 'rn' → 'm'               (catches rnicrosoft → microsoft)
//
// Capped at 8 variants regardless of input length.
func normalizationVariants(s string) []string {
	seen := map[string]struct{}{s: {}}
	out := []string{s}
	add := func(v string) {
		if _, dup := seen[v]; dup || len(out) >= 8 {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	add(normalizeConfusables(s))
	add(normalizeConfusables(strings.ReplaceAll(s, "1", "i")))
	add(normalizeConfusables(strings.ReplaceAll(s, "rn", "m")))
	add(normalizeConfusables(strings.ReplaceAll(strings.ReplaceAll(s, "1", "i"), "rn", "m")))
	return out
}

func certScore(ctx context.Context, domain string) Signal {
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	c, err := tls.DialWithDialer(&d, "tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return Signal{}
	}
	defer c.Close()
	chain := c.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return Signal{}
	}
	leaf := chain[0]
	age := time.Since(leaf.NotBefore)
	switch {
	case age < 24*time.Hour:
		return Signal{Name: "cert_age", Weight: 0.4, Detail: "cert <24h old"}
	case age < 7*24*time.Hour:
		return Signal{Name: "cert_age", Weight: 0.2, Detail: "cert <7d old"}
	}
	return Signal{}
}

func lexicalScore(domain string) Signal {
	d := strings.ToLower(domain)
	suspiciousKW := []string{"login", "secure", "verify", "account", "update", "wallet", "mfa", "bank-"}
	hits := 0
	for _, k := range suspiciousKW {
		if strings.Contains(d, k) {
			hits++
		}
	}
	if hits > 0 {
		return Signal{Name: "suspicious_lexical", Weight: 0.15 * float64(hits), Detail: "phishy keywords"}
	}
	if strings.Count(d, "-") >= 3 {
		return Signal{Name: "many_hyphens", Weight: 0.2, Detail: "≥3 hyphens"}
	}
	return Signal{}
}

// --- helpers ---

var confusables = map[rune]rune{
	'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
	// Cyrillic lookalikes (subset)
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
}

func normalizeConfusables(s string) string {
	var b strings.Builder
	for _, r := range s {
		if v, ok := confusables[r]; ok {
			b.WriteRune(v)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func clamp(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
