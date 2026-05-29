package main

import (
	"fmt"
	"github.com/xgenguardian/services/verdict-api/internal/tier1"
)

func main() {
	for _, s := range []string{
		"jevhcksi", "egvbrkdf", "google", "amazon", "paypal",
		"github", "qzwxecrvtb", "facebook", "claudiyoketka",
		"ravishingtattle", "claudemac", "youtube", "stackoverflow",
	} {
		d := tier1.DGAScore(s)
		_, ok1 := tier1.DGASignal(s)
		r, ok2 := tier1.RandomHostSignal(s)
		fmt.Printf("  %-18s  dga=%.3f%s  random=%v\n",
			s, d, mark(ok1), markSig(r, ok2))
	}
}
func mark(b bool) string { if b { return " HIT" }; return "    " }
func markSig(s tier1.Signal, ok bool) string {
	if !ok { return "no" }
	return fmt.Sprintf("YES (%s w=%.2f)", s.Detail, s.Weight)
}
