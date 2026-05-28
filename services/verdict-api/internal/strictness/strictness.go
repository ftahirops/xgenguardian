// Package strictness applies the per-user / per-tenant verdict mapping.
//
// Executive Mode (a.k.a. paranoid mode, docs/UNIFIED-PLAN.md §4.4) is a
// grade→verdict remap, not a new detector. The fusion layer (internal/fusion)
// computes a raw verdict and confidence; this package elevates the floor for
// users who have opted in.
//
// The mode is deliberately small: 4 inputs, 1 output, no side effects. The
// loader in loader.go fetches the policy from Postgres and caches it; this
// file holds only the pure mapping.
package strictness

import "time"

// Verdict — wire-format strings shared with extension and resolver.
type Verdict string

const (
	Allow     Verdict = "ALLOW"
	Warn      Verdict = "WARN"
	Block     Verdict = "BLOCK"
	Isolate   Verdict = "ISOLATE"
	Analyzing Verdict = "ANALYZING"
)

// Grade — A+|A|B|C|D|F|F+ from the trust registry (urls.grade).
// Empty string means "unknown / first-seen / no row yet".
type Grade string

const (
	GradeAPlus Grade = "A+"
	GradeA     Grade = "A"
	GradeB     Grade = "B"
	GradeC     Grade = "C"
	GradeD     Grade = "D"
	GradeF     Grade = "F"
	GradeFPlus Grade = "F+"
)

// WarmupWindow — how long after first enabling paranoid mode we keep
// treating B as A so the personal cache can populate. Hard rule from §4.4.
const WarmupWindow = 24 * time.Hour

// Policy is the per-request strictness context.
type Policy struct {
	// Paranoid is true if the effective flag (user-override-or-tenant) is on.
	Paranoid bool
	// EnabledAt is when the user first turned paranoid on. Zero value means
	// "not in warmup" — either disabled, or the warmup window has already
	// elapsed. The loader is responsible for zeroing this once
	// EnabledAt+WarmupWindow < now.
	EnabledAt time.Time
	// Now is injected for testability. Pass time.Now() in production.
	Now time.Time
}

// Inputs carries everything Apply needs to decide. Kept small on purpose.
type Inputs struct {
	// RawVerdict is what fusion.Score returned.
	RawVerdict Verdict
	// Grade is the stored urls.grade for this URL ("" if unknown).
	Grade Grade
	// PageClass is the urls.page_class for this URL. Sensitive classes
	// (login/payment/oauth/admin/download/consent) NEVER get a strictness
	// downgrade — they keep whatever fusion or normal-mode policy chose.
	PageClass string
	// FromOverride is true if an active, unexpired override produced this
	// verdict. Overrides bypass strictness — by definition the user asked
	// for an exception.
	FromOverride bool
}

// Result is the final verdict plus a flag the caller uses to attach the
// BLOCKED_BY_STRICTNESS_POLICY reason code (so analytics can separate
// friction from real detection).
type Result struct {
	Verdict           Verdict
	StrictnessApplied bool
}

// Apply maps (raw verdict + grade + policy) to the final verdict.
//
// Mapping table (docs/UNIFIED-PLAN.md §4.4):
//
//	Grade   Normal           Paranoid
//	A+ / A  ALLOW            ALLOW
//	B       ALLOW            ISOLATE  (or ALLOW during warmup)
//	C       WARN             ISOLATE
//	D       ISOLATE          ISOLATE
//	F / F+  BLOCK            BLOCK
//	unknown WARN or ISOLATE  ISOLATE
//
// Hard rules:
//   - Sensitive page classes are never relaxed and never elevated by
//     strictness — fusion+TTL caps handle them.
//   - BLOCK from the raw verdict is never downgraded. Detection wins over
//     strictness.
//   - Override-produced verdicts pass through untouched.
//   - Warmup: during the first WarmupWindow after Policy.EnabledAt, grade B
//     is still ALLOW. Other grades follow the paranoid mapping.
func Apply(in Inputs, p Policy) Result {
	if in.FromOverride {
		return Result{Verdict: in.RawVerdict, StrictnessApplied: false}
	}

	// Detection-driven BLOCK always wins.
	if in.RawVerdict == Block {
		return Result{Verdict: Block, StrictnessApplied: false}
	}

	if !p.Paranoid {
		return Result{Verdict: in.RawVerdict, StrictnessApplied: false}
	}

	inWarmup := !p.EnabledAt.IsZero() && p.Now.Sub(p.EnabledAt) < WarmupWindow

	// Sensitive classes: don't apply strictness. Fusion / TTL caps handle.
	switch in.PageClass {
	case "login", "payment", "oauth", "admin", "download", "consent":
		return Result{Verdict: in.RawVerdict, StrictnessApplied: false}
	}

	switch in.Grade {
	case GradeAPlus, GradeA:
		// Top grades pass through whatever fusion said.
		return Result{Verdict: in.RawVerdict, StrictnessApplied: false}

	case GradeB:
		if inWarmup {
			return Result{Verdict: in.RawVerdict, StrictnessApplied: false}
		}
		return elevate(in.RawVerdict, Isolate)

	case GradeC, GradeD:
		return elevate(in.RawVerdict, Isolate)

	case GradeF, GradeFPlus:
		// Already BLOCK by fusion in nearly all cases; belt-and-suspenders.
		return Result{Verdict: Block, StrictnessApplied: in.RawVerdict != Block}

	case "":
		// Unknown / first-seen. Paranoid forces ISOLATE for unknown content
		// — this is the headline behavior of the mode.
		return elevate(in.RawVerdict, Isolate)
	}

	// Fallthrough — unrecognized grade string. Treat as unknown.
	return elevate(in.RawVerdict, Isolate)
}

// elevate returns the stricter of raw and floor, preserving the existing
// verdict if it is already at-or-above the floor.
//
// Strictness ladder: ALLOW < ANALYZING < WARN < ISOLATE < BLOCK.
func elevate(raw, floor Verdict) Result {
	if strictnessRank(raw) >= strictnessRank(floor) {
		return Result{Verdict: raw, StrictnessApplied: false}
	}
	return Result{Verdict: floor, StrictnessApplied: true}
}

func strictnessRank(v Verdict) int {
	switch v {
	case Allow:
		return 0
	case Analyzing:
		return 1
	case Warn:
		return 2
	case Isolate:
		return 3
	case Block:
		return 4
	}
	return 0
}
